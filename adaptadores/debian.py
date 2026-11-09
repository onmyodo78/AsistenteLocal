"""APT local: candidatas Policy separadas del resolvedor apt-get --simulate."""
import os
import re
import time
from auditoria_debian import consultar_auditoria
from contratos_mantenimiento import paquete, componente
from mantenimiento_transporte import ejecutar

from apt_simulacion import INST, REMV, CONF, RESUMEN, identidad, parsear_simulacion


class Debian:
    distribucion = 'debian13'
    gestor = 'apt'

    def capacidades(self, deadline):
        disponible = os.path.isfile('/usr/bin/apt-get') and os.access('/usr/bin/apt-get', os.X_OK)
        probe = ejecutar('apt-version', deadline) if disponible else {}
        compatible = probe.get('estado') == 'completo' and bool(re.match(r'apt [23]\.\d', probe.get('stdout', '')))
        return dict(consulta=disponible, simulacion=compatible, ejecucion=False,
                    solo_cache=True, sin_red=True)

    def consultar(self, deadline, datos=None):
        datos = consultar_auditoria(max(0, deadline-time.monotonic())) if datos is None else datos
        apt = datos['actualizaciones']
        candidatos = [paquete(r['nombre_binario'], r['arquitectura'], r['instalada'], r['candidata'])
                      for r in apt['candidatos'] if r['superior']]
        estado = apt['estado_adquisicion']
        if datos['estado_inventario'] != 'completo' and estado == 'completo':
            estado = 'parcial'
        c = componente(estado, candidatos, [apt['motivo']] if apt.get('motivo') else [])
        return c, datos

    def simular(self, deadline, datos):
        salida = ejecutar('apt-simular', deadline)
        if salida['estado'] != 'completo':
            return dict(estado='error', actualizaciones=[], instalaciones=[], eliminaciones=[],
                        retenciones=[], retenciones_estado='no_comprobada', no_actualizados_total=None, errores=[salida['error']])
        if datos.get('estado_inventario') != 'completo':
            return dict(estado='no_verificable', actualizaciones=[], instalaciones=[], eliminaciones=[],
                        retenciones=[], retenciones_estado='no_comprobada', no_actualizados_total=None, errores=['inventario_incompleto'])
        try:
            grupos = parsear_simulacion(salida['stdout'], datos['inventario_dpkg'])
            return dict(estado='completo', **grupos, retenciones_estado='completo', errores=[])
        except ValueError as e:
            return dict(estado='no_verificable', actualizaciones=[], instalaciones=[], eliminaciones=[],
                        retenciones=[], retenciones_estado='no_comprobada', no_actualizados_total=None, errores=[str(e)])
