"""Selección de seguridad sin adquisición ni cambios en los backends Fedora."""
import json
from distribucion_linux import detectar_distribucion

HERRAMIENTAS_SEGURIDAD = frozenset(('auditoria_seguridad', 'correlacion_seguridad'))


def seleccionar_backend_seguridad():
    distribucion = detectar_distribucion()
    backend, estado = None, 'no_soportado'
    if distribucion['estado'] == 'soportado':
        if distribucion['id'] == 'fedora':
            backend, estado = 'fedora', 'disponible'
        elif distribucion['id'] == 'debian' and distribucion['version_id'] == '13':
            backend, estado = 'debian', 'parcial'
    return dict(backend=backend, estado=estado, distribucion=distribucion)


def estado_herramienta(nombre, seleccion):
    if seleccion['backend'] == 'debian':
        return 'disponible' if nombre == 'auditoria_seguridad' else 'no_implementado'
    return seleccion['estado']


def resultado_no_disponible(nombre, seleccion):
    """Sin recuentos cero ni colecciones vacías que sugieran adquisición."""
    return json.dumps(dict(version=1, herramienta=nombre,
        backend=seleccion['backend'], distribucion=seleccion['distribucion'],
        estado=estado_herramienta(nombre, seleccion), estado_adquisicion='no_realizada',
        motivo=('Funcionalidad de seguridad Debian 13 todavía no implementada.'
                if seleccion['backend'] == 'debian' else
                'Distribución no soportada o identificación inválida.'),
        limitaciones=['No se ha realizado ninguna auditoría ni correlación.',
                      'No permite determinar vulnerabilidades ni actualizaciones pendientes.']),
        ensure_ascii=True, separators=(',', ':'))
