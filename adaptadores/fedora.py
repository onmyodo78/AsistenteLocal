"""Fedora: consultas nativas locales; resolvedor DNF4 opcional y DNF5 conservador."""
import importlib.util
import json
import os
import re
import time
from contratos_mantenimiento import paquete, componente
from mantenimiento_transporte import ejecutar


def evr(version):
    if type(version) is not str:
        raise ValueError('version_rpm_invalida')
    return version if ':' in version else '0:' + version


def parsear_filas(texto):
    filas = []
    for linea in texto.splitlines():
        campos = linea.split('\t')
        if len(campos) != 3:
            raise ValueError('salida_paquetes_no_interpretada')
        n, a, v = campos
        if n == 'gpg-pubkey' and a == '(none)':
            continue
        filas.append(paquete(n, a, evr(v), None))
    return filas


def parsear_transaccion(texto, inventario):
    datos = json.loads(texto)
    if type(datos) is not dict or set(datos) != {'version', 'resolvedor', 'acciones'} or type(datos['version']) is not int or datos['version'] != 1 or datos['resolvedor'] != 'dnf4' or type(datos['acciones']) is not list:
        raise ValueError('transaccion_dnf_no_interpretada')
    grupos = dict(actualizaciones=[], instalaciones=[], eliminaciones=[], retenciones=[])
    reemplazados = []
    for item in datos['acciones']:
        if type(item) is not dict or set(item) != {'accion','nombre','arquitectura','version'}:
            raise ValueError('accion_dnf_invalida')
        n, a, v = item['nombre'], item['arquitectura'], evr(item['version'])
        paquete(n, a, v, None)
        viejos = [p for p in inventario if (p['nombre'], p['arquitectura']) == (n, a)]
        accion = item['accion']
        if accion == 'actualizar':
            if len(viejos) != 1:
                raise ValueError('version_anterior_ambigua')
            grupos['actualizaciones'].append(paquete(n, a, viejos[0]['anterior'], v))
        elif accion == 'instalar':
            grupos['instalaciones'].append(paquete(n, a, None, v))
        elif accion in ('eliminar', 'reemplazado'):
            if not any(p['anterior'] == v for p in viejos):
                raise ValueError('inventario_no_coincidente')
            if accion == 'eliminar':
                grupos['eliminaciones'].append(paquete(n, a, v, None))
            else:
                reemplazados.append(paquete(n, a, v, None))
        else:
            raise ValueError('accion_dnf_no_soportada')
    for r in reemplazados:
        if not any((p['nombre'],p['arquitectura'],p['anterior']) == (r['nombre'],r['arquitectura'],r['anterior']) for p in grupos['actualizaciones']):
            raise ValueError('reemplazo_sin_actualizacion')
    return grupos


class Fedora:
    distribucion = 'fedora'

    def __init__(self):
        self.gestor = 'dnf5' if (os.path.exists('/usr/bin/dnf5') or
            os.path.realpath('/usr/bin/dnf').endswith('/dnf5')) else 'dnf'

    def capacidades(self, deadline):
        disponible = os.path.isfile('/usr/bin/' + self.gestor) and os.access('/usr/bin/' + self.gestor, os.X_OK)
        probe = ejecutar(self.gestor + '-version', deadline) if disponible else {}
        version = probe.get('stdout', '')
        dnf4 = self.gestor == 'dnf' and probe.get('estado') == 'completo' and bool(re.match(r'4\.\d', version))
        binding = importlib.util.find_spec('dnf') is not None
        return dict(consulta=disponible, simulacion=dnf4 and binding, ejecucion=False,
                    solo_cache=True, sin_red=True)

    def consultar(self, deadline, datos=None):
        if datos is None:
            inventario = ejecutar('rpm-inventario', deadline)
        else:
            filas = datos.get('inventario_rpm') or []
            texto = '\n'.join(f"{r['nombre']}\t{r['arquitectura']}\t{r['epoch']}:{r['version']}-{r['release']}" for r in filas if r['arquitectura'] is not None)
            inventario = dict(estado='completo' if datos.get('inventario_completo') else 'error', stdout=texto, error='inventario_previo_incompleto')
        consulta = ejecutar(self.gestor + '-consultar', deadline)
        errores = [r['error'] for r in (inventario,consulta) if r['estado'] != 'completo']
        try:
            instalados = parsear_filas(inventario['stdout']) if inventario['estado'] == 'completo' else []
            candidatos = []
            if consulta['estado'] == 'completo':
                for r in parsear_filas(consulta['stdout']):
                    previos = [p for p in instalados if (p['nombre'],p['arquitectura']) == (r['nombre'],r['arquitectura'])]
                    anterior = previos[0]['anterior'] if len(previos) == 1 else None
                    candidatos.append(paquete(r['nombre'],r['arquitectura'],anterior,r['anterior']))
            if not instalados:
                errores.append('inventario_vacio_o_incompleto')
            return componente('parcial' if errores and candidatos else 'error' if errores else 'completo', candidatos, errores), instalados
        except ValueError:
            return componente('no_verificable', errores=['formato_fedora_no_interpretado']), []

    def simular(self, deadline, inventario):
        if self.gestor == 'dnf5':
            s = dict(estado='no_verificable', actualizaciones=[], instalaciones=[], eliminaciones=[], retenciones=[], retenciones_estado='no_comprobada', no_actualizados_total=None,
                errores=['dnf5_transaccion_estructurada_no_disponible'])
            d=self.preparar(deadline,inventario)
            if d['acciones_estado']!='completo':
                s['errores']=d['errores']
                return s
            # Proyección informativa v1. Las relaciones NEVRA completas se
            # conservan en preparar-dnf5; no convertirlas en autoridad APT.
            for a in d['acciones']:
                p=a['paquete'];v=p['evr'];n=p['nombre'];ar=p['arquitectura']
                if a['accion']=='UPGRADE':
                    prev=[r for r in a['reemplaza'] if (r['nombre'],r['arquitectura'])==(n,ar)]
                    if len(prev)==1:
                        s['actualizaciones'].append(paquete(n,ar,prev[0]['evr'],v))
                elif a['accion']=='INSTALL':s['instalaciones'].append(paquete(n,ar,None,v))
                elif a['accion']=='REMOVE' or (a['accion']=='REPLACED' and not any(
                        b['accion']=='UPGRADE' and b['paquete']['nombre']==n and b['paquete']['arquitectura']==ar
                        and p in b['reemplaza'] for b in d['acciones'])):
                    s['eliminaciones'].append(paquete(n,ar,v,None))
            s['errores']=list(d['pendientes'])
            return s
        resultado = ejecutar(self.gestor + '-simular', deadline)
        if resultado['estado'] != 'completo':
            return dict(estado='error', actualizaciones=[], instalaciones=[], eliminaciones=[], retenciones=[], retenciones_estado='no_comprobada', no_actualizados_total=None, errores=[resultado['error']])
        try:
            if not inventario:
                raise ValueError('inventario_incompleto')
            return dict(estado='completo', **parsear_transaccion(resultado['stdout'], inventario),
                        retenciones_estado='no_comprobada', no_actualizados_total=None, errores=[])
        except (ValueError, TypeError, KeyError):
            return dict(estado='no_verificable', actualizaciones=[], instalaciones=[], eliminaciones=[], retenciones=[],
                        retenciones_estado='no_comprobada', no_actualizados_total=None,
                        errores=['transaccion_dnf_no_interpretada'])

    def preparar(self, deadline, inventario=None):
        from dnf5_preparacion import resultado, leer, ERRORES
        if time.monotonic()>=deadline:return resultado('tiempo_agotado')
        if self.gestor!='dnf5':return resultado('dnf5_no_disponible')
        if importlib.util.find_spec('libdnf5') is None:
            return resultado('binding_no_disponible')
        r=ejecutar('dnf5-preparar',deadline)
        if time.monotonic()>=deadline:return resultado('tiempo_agotado')
        if r['estado']!='completo':
            return resultado(r['error'] if r['error'] in ERRORES else 'resolucion_dnf5_fallida')
        try:
            d=leer(r['stdout'])
            if inventario is not None and d['acciones_estado']=='completo':
                from contratos_mantenimiento import serializar
                anterior=sorted((dict(nombre=p['nombre'],arquitectura=p['arquitectura'],evr=p['anterior']) for p in inventario),key=serializar)
                if anterior!=d['inventario']:return resultado('inventario_no_coincidente')
            return d
        except (ValueError,TypeError,KeyError):
            return resultado('evidencia_dnf5_invalida')
