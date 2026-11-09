"""Motor independiente: consultar y simular, nunca autorizar ni modificar paquetes."""
import time
from distribucion_linux import detectar_distribucion
from contratos_mantenimiento import base, finalizar, componente
from adaptadores.debian import Debian
from adaptadores.fedora import Fedora

MAX_SECONDS = 120


def seleccionar(distribucion):
    if distribucion['estado'] != 'soportado':
        return None
    if distribucion['id'] == 'debian' and distribucion['version_id'] == '13':
        return Debian()
    if distribucion['id'] == 'fedora':
        return Fedora()
    return None


def consultar(operacion='plan', *, distribucion=None, adaptador=None, deadline=None, datos_previos=None, observador=None):
    if operacion not in ('capacidades', 'actualizaciones', 'plan'):
        raise ValueError('operacion_no_autorizada')
    distro = detectar_distribucion() if distribucion is None else distribucion
    adaptador = seleccionar(distro) if adaptador is None else adaptador
    d = base(adaptador.distribucion if adaptador else None,
             adaptador.gestor if adaptador else None, operacion)
    if adaptador is None:
        d['candidatas']['errores'] = ['distribucion_no_soportada']
        return finalizar(d)
    deadline = min(deadline, time.monotonic() + MAX_SECONDS) if deadline is not None else time.monotonic() + MAX_SECONDS
    if deadline <= time.monotonic():
        raise TimeoutError("plazo_agotado")
    def comprobar_plazo():
        if time.monotonic() >= deadline:raise TimeoutError('plazo_agotado')
    def registrar(nombre,inicio,estado):
        if observador is not None:
            observador(dict(operacion=nombre,estado=estado,duracion_ms=max(0,int((time.monotonic()-inicio)*1000))))
    inicio=time.monotonic()
    try:
        comprobar_plazo()
        d['capacidades'] = adaptador.capacidades(deadline)
        registrar('capacidades_'+adaptador.gestor,inicio,'completo')
    except (OSError, ValueError, KeyError, TypeError):
        d['candidatas']['errores'] = ['capacidades_no_verificadas']
        return finalizar(d)
    if operacion == 'capacidades':
        d['estado'] = 'completo' if d['capacidades']['consulta'] else 'no_disponible'
        return finalizar(d)
    if not d['capacidades']['consulta']:
        d['candidatas']['estado'] = 'no_disponible'
        d['candidatas']['errores'] = ['gestor_no_disponible']
        return finalizar(d)
    inicio=time.monotonic()
    try:
        comprobar_plazo()
        if datos_previos is not None and isinstance(adaptador, (Debian,Fedora)):
            d['candidatas'], datos = adaptador.consultar(deadline, datos=datos_previos)
        else:
            d['candidatas'], datos = adaptador.consultar(deadline)
        registrar('candidatas_'+adaptador.gestor,inicio,d['candidatas']['estado'])
    except (OSError, ValueError, KeyError, TypeError):
        d['candidatas'] = componente('error', errores=['consulta_fallida'])
        datos = {}
    if operacion == 'actualizaciones':
        d['estado'] = d['candidatas']['estado']
        return finalizar(d)
    if not d['capacidades']['simulacion'] and adaptador.gestor != 'dnf5':
        d['simulacion'].update(estado='no_disponible', errores=['simulacion_no_soportada'])
    else:
        inicio=time.monotonic()
        try:
            comprobar_plazo()
            d['simulacion'] = adaptador.simular(deadline, datos)
            registrar('simulacion_'+adaptador.gestor,inicio,d['simulacion']['estado'])
        except (OSError, ValueError, KeyError, TypeError):
            d['simulacion'].update(estado='error', errores=['simulacion_fallida'])
    if d['simulacion']['estado'] == d['candidatas']['estado'] == 'completo':
        previstas = {(r['nombre'],r['arquitectura'],r['propuesta']) for r in
                     d['simulacion']['actualizaciones'] + d['simulacion']['instalaciones']}
        d['comparacion'] = dict(estado='completa', no_previstas=[r for r in d['candidatas']['paquetes']
            if (r['nombre'],r['arquitectura'],r['propuesta']) not in previstas])
        d['estado'] = 'completo'
    else:
        d['estado'] = 'parcial' if (d['candidatas']['estado'] == 'completo' or d['simulacion']['estado'] == 'completo'
                                   or d['candidatas']['paquetes']) else 'error'
    if adaptador.gestor in ('dnf','dnf5'):
        d['limitaciones'].append('Retenciones y exclusiones Fedora no enumeradas; lista vacía no acredita ausencia.')
    return finalizar(d)
