"""Métricas HTTP sin contenido. Emisión JSON a stderr, sin archivos propios."""
import json
import math
import sys
import time
import urllib.error
import http.client

FASES = ('preparacion', 'conexion_y_cabeceras', 'lectura_cuerpo', 'cierre', 'validacion')
FINALES = {'stop', 'length', 'tool_calls', 'function_call', 'content_filter'}


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
    """No puede separar DNS/TCP/envío/cola/generación antes de las cabeceras."""
    def __init__(self):
        self.inicio = self.inicio_fase = time.monotonic()
        self.actual = 'preparacion'
        self.datos = {'duraciones_s': {fase: None for fase in FASES},
                      'bytes_peticion': 0, 'bytes_cuerpo': 0, 'estado_http': None,
                      'finish_reason': None, 'uso_tokens': None}

    def fase(self, nombre):
        ahora = time.monotonic()
        self.datos['duraciones_s'][self.actual] = max(0, ahora - self.inicio_fase)
        self.actual, self.inicio_fase = nombre, ahora

    def estado_http(self, codigo):
        if type(codigo) is int and 100 <= codigo <= 599:
            self.datos['estado_http'] = codigo

    def respuesta(self, respuesta):
        # Extraer solo campos permitidos, incluso si el mensaje resulta inválido.
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
                          tipo_error=tipo_error(error), fase_error=self.actual if error else None)
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
    codigo = datos.get('estado_http')
    tipos = {'HTTPError', 'TimeoutError', 'URLError', 'IncompleteRead', 'HTTPException',
             'OSError', 'RespuestaInvalida', 'ValueError', 'Interrupcion', 'ErrorInterno'}
    seguro = {
        'duraciones_s': {k: _duracion(duraciones.get(k)) for k in FASES},
        'total_s': _duracion(datos.get('total_s')),
        'bytes_peticion': _contador(datos.get('bytes_peticion')),
        'bytes_cuerpo': _contador(datos.get('bytes_cuerpo')),
        'estado_http': codigo if type(codigo) is int and 100 <= codigo <= 599 else None,
        'finish_reason': final if isinstance(final, str) and final in FINALES else None,
        'uso_tokens': uso_seguro(datos.get('uso_tokens')),
        'fase_error': fase if isinstance(fase, str) and fase in FASES else None,
        'tipo_error': error if isinstance(error, str) and error in tipos else None,
    }
    print('LMSTUDIO_METRICAS ' + json.dumps(seguro, ensure_ascii=True, allow_nan=False), file=sys.stderr)
