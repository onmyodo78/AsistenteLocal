"""Adquisición independiente del cliente conversacional y de HTTP.

Coordinadores extraídos de AsistenteLocal; los módulos de dominio siguen siendo
la fuente de validación. No imprime informes ni requiere LM Studio.
"""
import os
import selectors
import subprocess
import time
from auditoria_seguridad import (
    CONSULTAS as CONSULTAS_AUDITORIA, normalizar as normalizar_auditoria,
    consultar_inventario, comando_aislado, AVISO_LOG_DNF,
    registrar_metricas as metricas_auditoria, _finalizar_proceso,
)
from auditoria_debian import consultar_auditoria as auditoria_debian
from backend_seguridad import seleccionar_backend_seguridad, resultado_no_disponible
from correlacion_seguridad import consultar as correlacion_fedora

MAX_COMMAND_BYTES = 65536
MAX_SECONDS = 120

def restante(deadline):
    segundos = deadline - time.monotonic()
    if segundos <= 0:
        raise TimeoutError("Se agotó el tiempo total de la petición.")
    return segundos


def ejecutar_comando(comando, timeout):
    """Captura y recogida comparten plazo; se reserva hasta 1 s para finalizar.

    Agotar la espera no demuestra desaparición. No se garantiza recogida ulterior
    de un proceso resistente; kill/recogida/cierre fallidos producen OSError.
    """
    salida = {"stdout": bytearray(), "stderr": bytearray()}
    presupuesto = max(0, timeout)
    deadline = time.monotonic() + presupuesto
    fin_captura = deadline - min(1.0, presupuesto / 4)
    truncado = False
    proceso = subprocess.Popen(comando, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               stdin=subprocess.DEVNULL)
    recogido = False
    codigo = None
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(proceso.stdout, selectors.EVENT_READ, "stdout")
            selector.register(proceso.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map():
                eventos = selector.select(restante(fin_captura))
                if not eventos:
                    raise TimeoutError("La consulta agotó su tiempo límite.")
                for key, _ in eventos:
                    bloque = os.read(key.fd, 4096)
                    if not bloque:
                        selector.unregister(key.fileobj)
                        continue
                    espacio = MAX_COMMAND_BYTES - sum(map(len, salida.values()))
                    salida[key.data].extend(bloque[:espacio])
                    if len(bloque) > espacio:
                        truncado = True
                        break
                if truncado:
                    break
        if not truncado:
            codigo = proceso.wait(timeout=max(0, fin_captura - time.monotonic()))
            recogido = True
    finally:
        codigo, fallo = _finalizar_proceso(proceso, deadline, recogido, codigo)
        if fallo:
            raise OSError(fallo + ': terminación o limpieza no confirmada')
    return (codigo,
            salida["stdout"].decode("utf-8", errors="replace"),
            salida["stderr"].decode("utf-8", errors="replace"), truncado)


def consultar_auditoria_seguridad(deadline):
    fuentes = {}
    for nombre, comando in CONSULTAS_AUDITORIA:
        restante(deadline)
        inicio = time.monotonic()
        fuente = {'estado': 'no_consultada', 'codigo': None, 'stdout': '',
                  'stdout_bytes': 0, 'stderr_bytes': 0}
        try:
            if nombre == 'rpm':
                fuente = consultar_inventario(min(15, restante(deadline)))
            else:
                if nombre in ('pendientes', 'instalados'):
                    comando = comando_aislado(nombre)
                codigo, salida, errores, truncado = ejecutar_comando(
                    list(comando), min(15, restante(deadline)))
                fuente.update(codigo=codigo, stdout=salida,
                              stdout_bytes=len(salida.encode('utf-8')),
                              stderr_bytes=len(errores.encode('utf-8')))
                # Solo este diagnóstico exacto se admite: logdir inaccesible
                # dentro del aislamiento. Ningún otro stderr se ignora.
                if nombre in ('pendientes', 'instalados') and errores == AVISO_LOG_DNF:
                    errores = ''
                fuente['estado'] = (
                    'truncada' if truncado else
                    'aislamiento_no_disponible' if codigo == 78 else
                    'ejecutable_ausente' if codigo == 69 else
                    'error_comando' if codigo else
                    'avisos_no_interpretados' if errores else 'correcta')
            restante(deadline)
        except (TimeoutError, subprocess.TimeoutExpired):
            fuente['estado'] = 'tiempo_agotado'
        except FileNotFoundError:
            fuente['estado'] = 'ejecutable_ausente'
        except PermissionError:
            fuente['estado'] = 'permiso_denegado'
        except OSError:
            fuente['estado'] = 'error_sistema'
        fuente['duracion_s'] = round(time.monotonic()-inicio, 6)
        fuentes[nombre] = fuente
    restante(deadline)
    datos = normalizar_auditoria(fuentes)
    for nombre, fuente in datos['fuentes'].items():
        metricas_auditoria(nombre, fuente)
    return datos


def consultar(nombre, deadline=None):
    if nombre not in ('auditoria_seguridad', 'correlacion_seguridad'):
        raise ValueError('operacion_no_autorizada')
    deadline = deadline if deadline is not None else time.monotonic() + MAX_SECONDS
    seleccion = seleccionar_backend_seguridad()
    if seleccion['backend'] is None or (seleccion['backend'] == 'debian' and nombre == 'correlacion_seguridad'):
        import json
        return json.loads(resultado_no_disponible(nombre, seleccion))
    if seleccion['backend'] == 'debian':
        return auditoria_debian(restante(deadline))
    if nombre == 'auditoria_seguridad':
        return consultar_auditoria_seguridad(deadline)
    return correlacion_fedora(consultar_auditoria_seguridad, ejecutar_comando, False, deadline)
