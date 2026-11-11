"""Diagnóstico real optativo: destino fijo, casos sintéticos y solo metadatos.

No se descubre como test, no modifica configuración, no ejecuta herramientas ni
registra prompts, finales o razonamiento. Máximo cinco peticiones, sin reintentos.
"""
import argparse
import http.client
import json
from pathlib import Path
import sys
import time
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import AsistenteLocal as app
from lmstudio_http import abrir_http_local
from lmstudio_metrics import MedicionHTTP

CASOS = dict(A='A_system_user_system.json', B='B_system_user.json',
             C='C_sin_tool_choice.json', D='D_reasoning_low.json',
             E='E_max_completion_tokens.json')


def probar(payload, deadline, *, abrir=None):
    """El JSON de respuesta solo vive en memoria; retorna métricas cerradas."""
    abrir = abrir or abrir_http_local
    m = MedicionHTTP()
    error = None
    caracteres = None
    try:
        req = urllib.request.Request(app.API_URL, data=json.dumps(payload).encode(),
                                     headers={'Content-Type': 'application/json'}, method='POST')
        limite = min(deadline, time.monotonic() + app.MAX_MODEL_SECONDS)
        m.datos['bytes_peticion'] = len(req.data)
        m.fase('conexion_y_cabeceras')
        with abrir(req, timeout=app.restante(limite), medicion=m, deadline=limite) as respuesta:
            m.estado_http(respuesta.status)
            m.fase('lectura_cuerpo')
            datos = bytearray()
            while True:
                app.restante(limite)
                bloque = respuesta.read1(min(65536, app.MAX_HTTP_BYTES + 1 - len(datos)))
                app.restante(limite)
                if not bloque:
                    break
                datos.extend(bloque)
                m.datos['bytes_cuerpo'] = len(datos)
                if len(datos) > app.MAX_HTTP_BYTES:
                    raise app.RespuestaInvalida(codigo='http_excesivo')
            m.fase('cierre')
        m.fase('validacion')
        try:
            documento = json.loads(datos)
        except (ValueError, UnicodeError, RecursionError):
            raise app.RespuestaInvalida(codigo='json_invalido') from None
        m.respuesta(documento)
        if isinstance(documento, dict):
            choices = documento.get('choices')
            if isinstance(choices, list) and choices and isinstance(choices[0], dict):
                mensaje = choices[0].get('message')
                if isinstance(mensaje, dict) and isinstance(mensaje.get('content'), str):
                    caracteres = len(mensaje['content'])
        app.validar_explicacion(documento)
        app.restante(limite)
    except (OSError, ValueError, TypeError, http.client.HTTPException) as exc:
        error = exc
    resultado = m.finalizar(error)
    resultado.update(caracteres_final=caracteres, explicacion_admisible=error is None)
    return resultado


def privacidad_configurada():
    """Sondeo de archivo local, no cambia opciones ni garantiza recarga del servidor."""
    try:
        config = json.loads((Path.home()/'.lmstudio/.internal/http-server-config.json').read_text())
        return isinstance(config, dict) and config.get('logSensitiveData') is False
    except (OSError, ValueError):
        return False


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--real', action='store_true', help='confirma la solicitud explícita de inferencia local real')
    parser.add_argument('--casos', nargs='+', choices=tuple(CASOS), default=['A', 'B'])
    parser.add_argument('--seed', type=int)
    opciones = parser.parse_args(argv)
    if not opciones.real or len(opciones.casos) > 5:
        parser.error('se requiere --real y como máximo cinco casos, sin reintentos')
    if opciones.seed is not None and not 0 <= opciones.seed <= 2**31-1:
        parser.error('seed fuera del intervalo admitido')
    if not privacidad_configurada():
        parser.error('privacidad_servidor_no_confirmada: no se envian peticiones; revisar configuracion con autorizacion')
    fin = time.monotonic() + app.MAX_SECONDS
    for caso in opciones.casos:
        payload = json.loads((Path(__file__).parent/'fixtures'/'lmstudio_explicacion'/CASOS[caso]).read_text())
        if opciones.seed is not None:
            payload['seed'] = opciones.seed
        resultado = probar(payload, fin)
        print(json.dumps(dict(caso=caso, seed=opciones.seed, metadatos=resultado), ensure_ascii=True), flush=True)
        if time.monotonic() >= fin:
            break


if __name__ == '__main__':
    main()
