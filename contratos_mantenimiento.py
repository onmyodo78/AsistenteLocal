"""Contrato versionado del plan local; ninguna operación autoriza ejecución."""
import hashlib
import json
import re

VERSION = 1
MAX_FILAS = 25000
ESTADOS = ('completo', 'parcial', 'error', 'no_disponible', 'no_verificable', 'no_realizada')
LIMITACIONES = [
    'Solo metadatos locales: frescura, cobertura y autenticidad no revalidadas.',
    'Lectura no transaccional; el sistema puede cambiar durante la simulación.',
    'Simulación sin privilegios: configuración inaccesible puede alterar el resultado.',
    'Un plan simulado no autoriza ni garantiza una actualización real.',
    'Seguridad CVE, descargas, espacio libre y reinicios no comprobados.',
]


def serializar(dato):
    return json.dumps(dato, ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False)


def paquete(nombre, arquitectura, anterior, propuesta):
    r = dict(nombre=nombre, arquitectura=arquitectura, anterior=anterior, propuesta=propuesta)
    patrones = {'nombre': r'[A-Za-z0-9][A-Za-z0-9_+.-]{0,255}\Z',
                'arquitectura': r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z'}
    for k, v in r.items():
        if v is None and k != 'nombre':
            continue
        if type(v) is not str or not re.fullmatch(patrones.get(k, r'[A-Za-z0-9][A-Za-z0-9.+:~^%_-]{0,511}\Z'), v):
            raise ValueError('identidad_paquete_invalida')
    return r


def componente(estado='no_realizada', paquetes=None, errores=None):
    return dict(estado=estado, paquetes=paquetes or [], errores=errores or [])


def base(distribucion, gestor, operacion):
    return dict(version=VERSION, tipo='plan_mantenimiento', distribucion=distribucion,
        gestor=gestor, operacion=operacion, estado='no_disponible', capacidades={},
        candidatas=componente(), simulacion=dict(estado='no_realizada', actualizaciones=[],
        instalaciones=[], eliminaciones=[], retenciones=[], retenciones_estado='no_comprobada',
        no_actualizados_total=None, errores=[]),
        comparacion=dict(estado='no_comprobada', no_previstas=[]),
        limitaciones=list(LIMITACIONES), ejecucion_habilitada=False, huella=None)


def validar(d):
    if type(d) is not dict or set(d) != set(base(None, None, 'plan')):
        raise ValueError('campos_plan_invalidos')
    if type(d['version']) is not int or d['version'] != VERSION or d['tipo'] != 'plan_mantenimiento':
        raise ValueError('version_plan_invalida')
    if d['distribucion'] not in ('debian13', 'fedora', None) or d['gestor'] not in ('apt', 'dnf', 'dnf5', None):
        raise ValueError('backend_invalido')
    if d['operacion'] not in ('capacidades', 'actualizaciones', 'plan') or d['estado'] not in ESTADOS:
        raise ValueError('estado_plan_invalido')
    if d['ejecucion_habilitada'] is not False:
        raise ValueError('ejecucion_no_implementada')
    if (type(d['capacidades']) is not dict
            or (d['capacidades'] and set(d['capacidades']) != {'consulta','simulacion','ejecucion','solo_cache','sin_red'})
            or any(type(v) is not bool for v in d['capacidades'].values())
            or d['capacidades'].get('ejecucion', False)):
        raise ValueError('capacidades_invalidas')
    if set(d['candidatas']) != {'estado', 'paquetes', 'errores'} or set(d['simulacion']) != {
            'estado', 'actualizaciones', 'instalaciones', 'eliminaciones', 'retenciones',
            'retenciones_estado', 'no_actualizados_total', 'errores'}:
        raise ValueError('componentes_invalidos')
    for c in (d['candidatas'], d['simulacion']):
        if c['estado'] not in ESTADOS:
            raise ValueError('estado_componente_invalido')
        for k, filas in c.items():
            if k in ('estado', 'errores', 'retenciones_estado', 'no_actualizados_total'):
                continue
            if type(filas) is not list or len(filas) > MAX_FILAS:
                raise ValueError('limite_filas')
            vistos = set()
            for r in filas:
                if type(r) is not dict or set(r) != {'nombre','arquitectura','anterior','propuesta'}:
                    raise ValueError('fila_invalida')
                paquete(**r)
                clave = serializar(r)
                if clave in vistos:
                    raise ValueError('fila_duplicada')
                vistos.add(clave)
        if type(c['errores']) is not list or any(type(x) is not str or not re.fullmatch(r'[a-z0-9_]{1,100}', x) for x in c['errores']):
            raise ValueError('error_no_saneado')
    if d['simulacion']['estado'] == 'completo':
        for grupo in ('actualizaciones', 'instalaciones', 'eliminaciones'):
            for r in d['simulacion'][grupo]:
                if r['arquitectura'] is None or (grupo != 'instalaciones' and r['anterior'] is None) or (grupo != 'eliminaciones' and r['propuesta'] is None):
                    raise ValueError('simulacion_incompleta')
    if d['simulacion']['retenciones_estado'] not in ('completo', 'no_comprobada'):
        raise ValueError('retenciones_invalidas')
    total = d['simulacion']['no_actualizados_total']
    if total is not None and (type(total) is not int or not 0 <= total <= MAX_FILAS):
        raise ValueError('total_no_actualizados_invalido')
    if set(d['comparacion']) != {'estado', 'no_previstas'} or d['comparacion']['estado'] not in ('completa','no_comprobada'):
        raise ValueError('comparacion_invalida')
    filas = d['comparacion']['no_previstas']
    if type(filas) is not list or len(filas) > MAX_FILAS:
        raise ValueError('comparacion_invalida')
    for r in filas:
        if type(r) is not dict or set(r) != {'nombre','arquitectura','anterior','propuesta'}:
            raise ValueError('comparacion_invalida')
        paquete(**r)
    if type(d['limitaciones']) is not list or any(type(x) is not str or len(x) > 1000 or any(ord(c) < 32 for c in x) for x in d['limitaciones']):
        raise ValueError('limitaciones_invalidas')
    if d['estado'] == 'completo' and d['operacion'] == 'plan' and not (d['candidatas']['estado'] == d['simulacion']['estado'] == 'completo'):
        raise ValueError('plan_incompleto')
    if d['huella'] is not None:
        copia = dict(d, huella=None)
        if d['huella'] != hashlib.sha256(serializar(copia).encode()).hexdigest():
            raise ValueError('huella_invalida')
    serializar(d)
    return d


def finalizar(d):
    # Orden estable y huella del contenido: no representa autorización.
    for c in (d['candidatas'], d['simulacion']):
        for k, v in c.items():
            if isinstance(v, list):
                c[k] = sorted(v, key=serializar)
    d['comparacion']['no_previstas'] = sorted(d['comparacion']['no_previstas'], key=serializar)
    d['huella'] = None
    validar(d)
    d['huella'] = hashlib.sha256(serializar(d).encode()).hexdigest()
    return d
