"""Contrato informe_exportacion_v1; solo datos en memoria, sin generadores ni E/S.

Recibe registros saneados de historial_contratos, no resultados originales ni
texto de comandos. Las fechas verificadas son una declaración del llamador:
este módulo comprueba su formato y coherencia, no certifica un reloj externo.
"""
from datetime import datetime
import json
from types import MappingProxyType

import historial_contratos as historial

VERSION_FORMATO = VERSION_PRIVACIDAD = VERSION_CATALOGO = 1
MAX_RESULTADOS = 100
MAX_INFORME_BYTES = 1024 * 1024
MAX_NODOS = 50000
MAX_PROFUNDIDAD = 12

# id -> (tipo, unidad, significado cerrado). No contiene etiquetas del sistema.
_CATALOGO = MappingProxyType({
    'ram_total_bytes': ('entero', 'byte', 'RAM total visible al proceso.'),
    'ram_disponible_estimada_bytes': ('entero', 'byte', 'Estimación de RAM disponible.'),
    'ram_utilizada_estimada_bytes': ('entero', 'byte', 'RAM total menos disponible estimada.'),
    'ram_libre_bytes': ('entero', 'byte', 'RAM libre observada.'),
    'swap_total_bytes': ('entero', 'byte', 'Capacidad de swap visible.'),
    'swap_libre_bytes': ('entero', 'byte', 'Swap libre observada.'),
    'swap_ocupada_bytes': ('entero', 'byte', 'Swap ocupada; no mide actividad de intercambio.'),
    'servicios_fallidos': ('entero', 'unidad_service', 'Unidades service fallidas enumeradas.'),
    'registros_sockets': ('entero', 'registro_socket', 'Registros de sockets del alcance de la herramienta; no servicios únicos.'),
    'interfaces_enumeradas_ip': ('entero', 'interfaz', 'Interfaces enumeradas por ip; no implica conectividad.'),
    'paquetes_rpm': ('entero', 'paquete', 'Total de registros RPM si el inventario es completo.'),
    'paquetes_rpm_recogidos': ('entero', 'paquete', 'Registros RPM recogidos; pueden ser un prefijo parcial.'),
    'avisos_pendientes': ('entero', 'aviso', 'Avisos DNF pendientes agrupados; no número de vulnerabilidades.'),
    'avisos_instalados': ('entero', 'aviso', 'Avisos DNF observados como instalados; no historial transaccional.'),
    'reinicio_pendiente_kernel': ('booleano', 'indicador', 'Indicador limitado de kernel Fedora más reciente instalado y no activo.'),
    'dpkg_instalados': ('entero', 'paquete', 'Paquetes correctamente instalados recogidos por dpkg.'),
    'dpkg_incompletos': ('entero', 'paquete', 'Registros dpkg en estados incompletos.'),
    'dpkg_residuales': ('entero', 'paquete', 'Registros dpkg con configuración residual.'),
    'dpkg_no_instalados': ('entero', 'paquete', 'Registros dpkg clasificados como no instalados.'),
    'dpkg_total_instalados': ('entero', 'paquete', 'Total instalado confirmado solo con inventario dpkg completo.'),
    'apt_total_posibles': ('entero', 'paquete', 'Posibles actualizaciones locales; no garantiza instalabilidad ni confirma CVE.'),
})
OMISIONES = ('identidades_excluidas', 'salidas_originales_excluidas', 'texto_libre_excluido')
LIMITACIONES = ('ejecucion_no_acredita_seguridad', 'sin_nuevas_adquisiciones',
    'solo_metricas_admitidas', 'fuentes_no_reverificadas',
    'alcance_limitado_al_contrato_origen')
ESPECIFICAS = {
    'memoria': ('instantanea_no_mide_actividad_swap',),
    'servicios_fallidos': ('recuento_no_identifica_resolucion_de_servicios',),
    'puertos': ('sockets_no_acreditan_exposicion_externa', 'udp_no_equivale_a_escucha_tcp'),
    'conexiones': ('sockets_no_acreditan_conectividad',),
    'interfaces_red': ('enumeracion_no_acredita_conectividad',),
    'auditoria_seguridad': ('cobertura_seguridad_no_verificada',),
}


class ErrorInforme(ValueError):
    pass


def _error():
    raise ErrorInforme('informe_exportacion_invalido')


def _fecha(valor):
    if type(valor) is not str or len(valor) != 20:
        _error()
    try:
        d = datetime.strptime(valor, '%Y-%m-%dT%H:%M:%SZ')
    except ValueError:
        _error()
    if d.strftime('%Y-%m-%dT%H:%M:%SZ') != valor:
        _error()
    return valor


def _canonico(d):
    # Uso interno de JSON únicamente para copias, igualdad y límites.
    # No es un generador ni produce archivos o una exportación pública JSON.
    return json.dumps(d, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(',', ':'))


def _limitar(d):
    historial._limitar(d)
    nodos = 0
    def contar(v, nivel):
        nonlocal nodos
        nodos += 1
        if nodos > MAX_NODOS or nivel > MAX_PROFUNDIDAD:
            _error()
        if type(v) is dict:
            for x in v.values():
                contar(x, nivel+1)
        elif type(v) is list:
            for x in v:
                contar(x, nivel+1)
    contar(d, 0)
    if len(_canonico(d).encode('utf-8')) > MAX_INFORME_BYTES:
        _error()


def catalogo_metricas():
    """Copia independiente del catálogo cerrado ordenado por identificador."""
    return [dict(identificador=k, tipo=t, unidad=u, significado=s)
            for k,(t,u,s) in sorted(_CATALOGO.items())]


def _ids(r):
    ids = set(historial.METRICAS[r['herramienta']])
    if r['herramienta'] == 'auditoria_seguridad':
        if r['distribucion'] == 'fedora':
            ids = {k for k in ids if not k.startswith(('dpkg_', 'apt_'))}
        else:
            ids = {k for k in ids if k.startswith(('dpkg_', 'apt_'))}
    if not set(r['metricas']) <= ids:
        _error()
    return sorted(ids)


def _resultado(r, observacion):
    ids = _ids(r)
    metricas = []
    for ident in ids:
        tipo, unidad, significado = _CATALOGO[ident]
        presente = ident in r['metricas']
        valor = r['metricas'].get(ident)
        metricas.append(dict(identificador=ident, tipo=tipo, unidad=unidad,
            significado=significado, estado_valor='no_recogida' if not presente else
            'desconocido' if valor is None else 'conocido', valor=valor))
    metadatos = {k:v for k,v in r.items() if k not in ('metricas', 'componentes')}
    estructurado = r['procedencia'] != 'estado_declarado_v1'
    omisiones = list(OMISIONES)
    if not estructurado:
        omisiones.append('sin_metricas_estructuradas_para_resultado')
    if observacion is None:
        omisiones.append('fecha_observacion_no_disponible')
    limites = list(LIMITACIONES) + list(ESPECIFICAS.get(r['herramienta'], ()))
    if r['herramienta'] == 'auditoria_seguridad' and r['distribucion'] == 'debian13':
        limites += ['dpkg_no_es_auditoria_cve', 'apt_no_garantiza_instalabilidad']
    return dict(origen=metadatos, fecha_observacion_utc=observacion,
        representacion='estructurada' if estructurado else 'solo_estado_declarado',
        soporte_metricas='adaptador_disponible' if r['herramienta'] in
        (*historial.PROCEDENCIAS, 'auditoria_seguridad') else 'sin_adaptador_estructurado',
        componentes=[dict(identificador=k, **v) for k,v in sorted(r['componentes'].items())],
        metricas=metricas, omisiones=sorted(omisiones), limitaciones=sorted(limites))


def preparar_informe(registros, *, fecha_preparacion_utc, observaciones=None):
    """Cada observación: None o {'fecha_utc': UTC, 'verificada': True}.

    No consulta el reloj. La fecha y su verificación las aporta el llamador.
    Cambiar el orden de entrada no cambia el informe; conserva repeticiones.
    """
    try:
        _fecha(fecha_preparacion_utc)
        if type(registros) is not list or not 1 <= len(registros) <= MAX_RESULTADOS:
            _error()
        if observaciones is None:
            observaciones = [None]*len(registros)
        if type(observaciones) is not list or len(observaciones) != len(registros):
            _error()
        resultados = []
        for r, obs in zip(registros, observaciones):
            r = historial.validar(r)
            fecha = None
            if obs is not None:
                if type(obs) is not dict or set(obs) != {'fecha_utc', 'verificada'} or obs['verificada'] is not True:
                    _error()
                fecha = _fecha(obs['fecha_utc'])
                if fecha > fecha_preparacion_utc:
                    _error()
            resultados.append(_resultado(r, fecha))
        resultados.sort(key=lambda r: (r['origen']['herramienta'], r['origen']['distribucion'],
            r['origen']['procedencia'], _canonico(r)))
        for orden, r in enumerate(resultados):
            r['orden'] = orden
        informe = dict(formato='informe_exportacion_v1', version_formato=VERSION_FORMATO,
            version_privacidad=VERSION_PRIVACIDAD, version_catalogo=VERSION_CATALOGO,
            fecha_preparacion_utc=fecha_preparacion_utc, resultados=resultados)
        _limitar(informe)
        return informe
    except (ValueError, TypeError, KeyError, RecursionError):
        raise ErrorInforme('informe_exportacion_invalido') from None


def validar_informe(informe):
    """Reconstruye desde el contrato histórico y compara toda la estructura cerrada."""
    try:
        _limitar(informe)
        if type(informe) is not dict or set(informe) != {'formato', 'version_formato',
            'version_privacidad', 'version_catalogo', 'fecha_preparacion_utc', 'resultados'}:
            _error()
        for campo in ('version_formato', 'version_privacidad', 'version_catalogo'):
            if type(informe[campo]) is not int or informe[campo] != 1:
                _error()
        if informe['formato'] != 'informe_exportacion_v1' or type(informe['resultados']) is not list:
            _error()
        registros, observaciones = [], []
        for r in informe['resultados']:
            if type(r) is not dict or set(r) != {'orden', 'origen', 'fecha_observacion_utc',
                'representacion', 'soporte_metricas', 'componentes', 'metricas', 'omisiones', 'limitaciones'}:
                _error()
            if type(r['origen']) is not dict or type(r['metricas']) is not list or type(r['componentes']) is not list:
                _error()
            registro = dict(r['origen'])
            metricas = {}
            for m in r['metricas']:
                if type(m) is not dict or set(m) != {'identificador', 'tipo', 'unidad', 'significado', 'estado_valor', 'valor'}:
                    _error()
                if m['identificador'] in metricas:
                    _error()
                if m['estado_valor'] != 'no_recogida':
                    metricas[m['identificador']] = m['valor']
            componentes = {}
            for c in r['componentes']:
                if type(c) is not dict or set(c) != {'identificador', 'ejecucion', 'calidad', 'cobertura'} or c['identificador'] in componentes:
                    _error()
                componentes[c['identificador']] = {k:v for k,v in c.items() if k != 'identificador'}
            registro.update(metricas=metricas, componentes=componentes)
            registros.append(registro)
            obs = r['fecha_observacion_utc']
            observaciones.append(None if obs is None else dict(fecha_utc=obs, verificada=True))
        esperado = preparar_informe(registros, fecha_preparacion_utc=informe['fecha_preparacion_utc'], observaciones=observaciones)
        if _canonico(informe) != _canonico(esperado):
            _error()
        return esperado
    except (ValueError, TypeError, KeyError, RecursionError):
        raise ErrorInforme('informe_exportacion_invalido') from None
