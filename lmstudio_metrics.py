"""Métricas HTTP sin contenido. Emisión JSON a stderr, sin archivos propios."""
import json
import math
import sys
import time
import urllib.error
import http.client
import errno

FASES = ('preparacion', 'conexion_y_cabeceras', 'conexion_tcp', 'envio_peticion', 'espera_cabeceras', 'lectura_cuerpo', 'cierre', 'validacion')
FINALES = {'stop', 'length', 'tool_calls', 'function_call', 'content_filter'}
ERRORES_SISTEMA = {'TimeoutError', 'ConnectionRefusedError', 'PermissionError', 'OSError'}


MOTIVOS_VALIDACION = frozenset((
    'respuesta_no_objeto', 'choices_invalidas', 'assistant_invalido',
    'contenido_no_textual', 'llamadas_invalidas', 'llamada_invalida',
    'llamada_malformada', 'sin_texto_ni_herramientas', 'json_invalido',
    'http_excesivo', 'explicacion_vacia', 'herramientas_en_explicacion',
    'explicacion_no_final', 'afirmacion_operativa_o_recomendacion_administrativa',
))


def motivo_validacion(error):
    codigo = getattr(error, 'codigo', None)
    return codigo if isinstance(codigo, str) and codigo in MOTIVOS_VALIDACION else None


def forma_segura(respuesta):
    """Solo tipos, contadores y presencia de campos conocidos; nunca valores."""
    if not isinstance(respuesta, dict):
        return None
    choices = respuesta.get('choices')
    choice = choices[0] if isinstance(choices, list) and choices and isinstance(choices[0], dict) else {}
    mensaje = choice.get('message')
    mensaje = mensaje if isinstance(mensaje, dict) else {}
    contenido = mensaje.get('content')
    tipo = ('ausente' if 'content' not in mensaje else 'null' if contenido is None else
            'texto' if isinstance(contenido, str) else 'lista' if isinstance(contenido, list) else
            'objeto' if isinstance(contenido, dict) else 'otro')
    return dict(content_tipo=tipo,
                content_vacio=(not contenido) if isinstance(contenido, str) else None,
                content_solo_espacios=(bool(contenido) and not contenido.strip()) if isinstance(contenido, str) else None,
                reasoning_presente=any(k in mensaje for k in ('reasoning', 'reasoning_content', 'analysis')),
                tool_calls_presente='tool_calls' in mensaje,
                function_call_presente='function_call' in mensaje)


def sanear_forma(forma):
    if not isinstance(forma, dict):
        return None
    tipo = forma.get('content_tipo')
    return dict(content_tipo=tipo if isinstance(tipo, str) and tipo in ('ausente', 'null', 'texto', 'lista', 'objeto', 'otro') else None,
                **{k: forma.get(k) if type(forma.get(k)) is bool else None for k in (
                    'content_vacio', 'content_solo_espacios', 'reasoning_presente',
                    'tool_calls_presente', 'function_call_presente')})


def tipo_error_sistema(error):
    """Solo la excepción de sistema explícita; nunca inferir desde su texto.

    URLError suele envolver el OSError de urllib. HTTPError.reason es una
    razón HTTP, no una causa de transporte, y no se inspecciona.
    """
    if isinstance(error, urllib.error.HTTPError):
        return None
    if isinstance(error, urllib.error.URLError):
        error = error.reason
    if not isinstance(error, OSError):
        return None
    if isinstance(error, TimeoutError) or error.errno == errno.ETIMEDOUT:
        return 'TimeoutError'
    if isinstance(error, ConnectionRefusedError) or error.errno == errno.ECONNREFUSED:
        return 'ConnectionRefusedError'
    if isinstance(error, PermissionError) or error.errno in (errno.EACCES, errno.EPERM):
        return 'PermissionError'
    return 'OSError'


def tipo_error(error):
    if error is None:
        return None
    if isinstance(error, urllib.error.HTTPError):
        return 'HTTPError'
    if isinstance(error, TimeoutError):
        return 'TimeoutError'
    if isinstance(error, urllib.error.URLError):
        return 'URLError'
    if isinstance(error, http.client.IncompleteRead):
        return 'IncompleteRead'
    if isinstance(error, http.client.HTTPException):
        return 'HTTPException'
    if isinstance(error, OSError):
        return 'OSError'
    if isinstance(error, ValueError):
        return 'RespuestaInvalida' if type(error).__name__ == 'RespuestaInvalida' else 'ValueError'
    if isinstance(error, (KeyboardInterrupt, SystemExit)):
        return 'Interrupcion'
    return 'ErrorInterno'


def _contador(valor):
    return valor if type(valor) is int and 0 <= valor <= 2**63 - 1 else None


def uso_seguro(uso):
    if not isinstance(uso, dict):
        return None
    datos = {}
    for clave in ('prompt_tokens', 'completion_tokens', 'total_tokens'):
        valor = _contador(uso.get(clave))
        if valor is not None:
            datos[clave] = valor
    for grupo, campo in (('prompt_tokens_details', 'cached_tokens'),
                         ('completion_tokens_details', 'reasoning_tokens')):
        detalle = uso.get(grupo)
        if isinstance(detalle, dict):
            valor = _contador(detalle.get(campo))
            if valor is not None:
                datos[grupo] = {campo: valor}
    return datos or None


class MedicionHTTP:
    """Fases locales; las cabeceras no distinguen cola y generación del servidor."""
    def __init__(self):
        self.inicio = self.inicio_fase = time.monotonic()
        self.actual = 'preparacion'
        self.datos = {'duraciones_s': {fase: None for fase in FASES},
                      'bytes_peticion': 0, 'bytes_cuerpo': 0, 'estado_http': None,
                      'finish_reason': None, 'uso_tokens': None, 'forma_respuesta': None}

    def fase(self, nombre):
        ahora = time.monotonic()
        self.datos['duraciones_s'][self.actual] = max(0, ahora - self.inicio_fase)
        self.actual, self.inicio_fase = nombre, ahora

    def estado_http(self, codigo):
        if type(codigo) is int and 100 <= codigo <= 599:
            self.datos['estado_http'] = codigo

    def respuesta(self, respuesta):
        # Extraer solo campos permitidos, incluso si el mensaje resulta inválido.
        self.datos['forma_respuesta'] = forma_segura(respuesta)
        if not isinstance(respuesta, dict):
            return
        choices = respuesta.get('choices')
        choice = choices[0] if isinstance(choices, list) and choices and isinstance(choices[0], dict) else {}
        final = choice.get('finish_reason')
        self.datos['finish_reason'] = final if isinstance(final, str) and final in FINALES else None
        self.datos['uso_tokens'] = uso_seguro(respuesta.get('usage'))

    def finalizar(self, error=None):
        ahora = time.monotonic()
        self.datos['duraciones_s'][self.actual] = max(0, ahora - self.inicio_fase)
        self.datos['duraciones_s'] = {k: round(v, 6) if v is not None else None
                                      for k, v in self.datos['duraciones_s'].items()}
        self.datos.update(total_s=round(max(0, ahora - self.inicio), 6),
                          tipo_error=tipo_error(error), fase_error=self.actual if error else None,
                          tipo_error_sistema=tipo_error_sistema(error), motivo_validacion=motivo_validacion(error))
        if isinstance(error, urllib.error.HTTPError):
            self.estado_http(error.code)
        if isinstance(error, http.client.IncompleteRead) and isinstance(error.partial, (bytes, bytearray)):
            self.datos['bytes_cuerpo'] += len(error.partial)
        return self.datos


def _duracion(valor):
    if type(valor) in (int, float) and math.isfinite(valor) and valor >= 0:
        return valor
    return None


def registrar_metadatos(datos):
    # Segunda lista blanca en la salida: tampoco un campo añadido accidentalmente
    # por el llamador puede volcar prompts, cabeceras, mensajes o excepciones.
    duraciones = datos.get('duraciones_s', {})
    final = datos.get('finish_reason')
    fase = datos.get('fase_error')
    error = datos.get('tipo_error')
    sistema = datos.get('tipo_error_sistema')
    codigo = datos.get('estado_http')
    tipos = {'HTTPError', 'TimeoutError', 'URLError', 'IncompleteRead', 'HTTPException',
             'OSError', 'RespuestaInvalida', 'ValueError', 'Interrupcion', 'ErrorInterno'}
    motivo = datos.get('motivo_validacion')
    seguro = {
        'duraciones_s': {k: _duracion(duraciones.get(k)) for k in FASES},
        'total_s': _duracion(datos.get('total_s')),
        'bytes_peticion': _contador(datos.get('bytes_peticion')),
        'bytes_cuerpo': _contador(datos.get('bytes_cuerpo')),
        'estado_http': codigo if type(codigo) is int and 100 <= codigo <= 599 else None,
        'finish_reason': final if isinstance(final, str) and final in FINALES else None,
        'uso_tokens': uso_seguro(datos.get('uso_tokens')),
        'motivo_validacion': motivo if isinstance(motivo, str) and motivo in MOTIVOS_VALIDACION else None,
        'forma_respuesta': sanear_forma(datos.get('forma_respuesta')),
        'fase_error': fase if isinstance(fase, str) and fase in FASES else None,
        'tipo_error': error if isinstance(error, str) and error in tipos else None,
        'tipo_error_sistema': sistema if isinstance(sistema, str) and sistema in ERRORES_SISTEMA else None,
    }
    print('LMSTUDIO_METRICAS ' + json.dumps(seguro, ensure_ascii=True, allow_nan=False), file=sys.stderr)
