"""Transporte acotado de operaciones fijas, en hijo sin red ni escrituras."""
import os
from pathlib import Path
import selectors
import subprocess
import sys
import time
import tempfile
from auditoria_debian import _finalizar_proceso

MODOS = ('apt-diagnostico','apt-dpkg-audit','apt-version', 'apt-simular', 'dnf-version', 'dnf5-version',
         'dnf-consultar', 'dnf-simular', 'dnf5-consultar', 'dnf5-simular', 'dnf5-preparar', 'rpm-inventario')
MAX_BYTES = 4 * 1024 * 1024
MAX_SEGUNDOS = 30


def ejecutar(modo, deadline):
    if modo not in MODOS:
        raise ValueError('operacion_no_autorizada')
    if os.geteuid() == 0:
        return dict(codigo=None, stdout='', estado='error', error='ejecucion_root_rechazada')
    try:
        with tempfile.TemporaryDirectory(prefix='asistentelocal-plan-', dir='/tmp') as temporal:
            return _ejecutar(modo, deadline, temporal)
    except OSError:
        return dict(codigo=None, stdout='', estado='error', error='temporal_no_disponible')


def _ejecutar(modo, deadline, temporal):
    if modo not in MODOS:
        raise ValueError('operacion_no_autorizada')
    if os.geteuid() == 0:
        return dict(codigo=None, stdout='', estado='error', error='ejecucion_root_rechazada')
    fin = min(deadline, time.monotonic() + MAX_SEGUNDOS)
    captura = fin - min(1., max(0., fin - time.monotonic()) / 4)
    salida = {'stdout': bytearray(), 'stderr': bytearray()}
    proceso = None
    codigo = None
    recogido = False
    error = None
    try:
        if captura <= time.monotonic():
            raise TimeoutError()
        entorno = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'LANG': 'C',
                   'HOME': os.path.expanduser('~'), 'PYTHONDONTWRITEBYTECODE': '1',
                   'TMPDIR': temporal, 'ASISTENTE_TEMPORAL': temporal}
        proceso = subprocess.Popen([sys.executable, '-I', '-B',
            str(Path(__file__).with_name('mantenimiento_worker.py').resolve()), modo],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=entorno)
        with selectors.DefaultSelector() as selector:
            for n in salida:
                selector.register(getattr(proceso, n), selectors.EVENT_READ, n)
            while selector.get_map():
                espera = captura - time.monotonic()
                if espera <= 0:
                    raise TimeoutError()
                eventos = selector.select(espera)
                if not eventos:
                    raise TimeoutError()
                for clave, _ in eventos:
                    disponible = MAX_BYTES - sum(map(len, salida.values()))
                    bloque = os.read(clave.fd, min(4096, disponible + 1))
                    if len(bloque) > disponible:
                        raise ValueError('limite_salida')
                    if bloque:
                        salida[clave.data].extend(bloque)
                    else:
                        selector.unregister(clave.fileobj)
            codigo = proceso.wait(timeout=max(0, captura-time.monotonic()))
            recogido = True
    except (TimeoutError, subprocess.TimeoutExpired):
        error = 'tiempo_agotado'
    except ValueError:
        error = 'limite_salida'
    except OSError:
        error = 'error_sistema'
    finally:
        if proceso is not None:
            codigo, limpieza = _finalizar_proceso(proceso, fin, recogido, codigo)
            error = limpieza or error
    error = error or {78: 'aislamiento_no_disponible', 69: 'dependencia_ausente',
                      70: 'binding_no_disponible', 72: 'consulta_nativa_fallida'}.get(codigo)
    if error is None and codigo != 0:
        error = 'error_gestor'
    if salida['stderr'] and error is None:
        error = 'avisos_no_verificados'
    return dict(codigo=codigo, stdout=salida['stdout'].decode('utf-8', errors='replace'),
                estado='completo' if error is None else 'error', error=error)
