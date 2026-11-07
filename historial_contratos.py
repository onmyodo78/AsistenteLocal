"""Contratos históricos puros: sin adquisición, reloj, persistencia ni SQLite.

Solo entradas estructuradas de contratos conocidos. Los campos sensibles de
origen se descartan; nunca se incluyen en errores, hashes o representaciones.
No conectar este módulo automáticamente a la ejecución de herramientas.
"""
import json
import math
from resultado_verificado import ResultadoVerificado, CAMPOS

VERSION = VERSION_ADAPTADOR = VERSION_METRICAS = 1
MAX_NODOS = 500000
MAX_PROFUNDIDAD = 16
MAX_LISTA = 25000
MAX_TEXTO = 16384
MAX_ORIGEN_BYTES = 8 * 1024 * 1024
MAX_REGISTRO_BYTES = 8192
MAX_ENTERO = 2**63-1
HERRAMIENTAS = frozenset(('auditoria_seguridad', 'correlacion_seguridad', 'disco',
    'memoria', 'servicios_fallidos', 'puertos', 'conexiones', 'cortafuegos', 'vpn',
    'diagnostico_vpn', 'sistema', 'interfaces_red', 'trafico_red', 'listar_documentos'))
EJECUCION = frozenset(('correcto', 'parcial', 'error', 'no_verificado', 'no_ejecutado'))
CALIDAD = frozenset(('verificada', 'parcial', 'no_verificada', 'no_disponible'))
COBERTURA = frozenset(('completa_en_alcance', 'parcial', 'no_verificada', 'no_aplica'))
MAPA = {'completo': ('correcto', 'verificada'), 'parcial': ('parcial', 'parcial'),
        'error': ('error', 'no_disponible'), 'desconocido': ('no_verificado', 'no_verificada')}
MEMORIA = ('ram_total_bytes', 'ram_disponible_estimada_bytes', 'ram_utilizada_estimada_bytes',
           'ram_libre_bytes', 'swap_total_bytes', 'swap_libre_bytes', 'swap_ocupada_bytes')
METRICAS = {h: {} for h in HERRAMIENTAS}
METRICAS.update({
    'memoria': dict.fromkeys(MEMORIA, 'entero'),
    'servicios_fallidos': {'servicios_fallidos': 'entero'},
    'puertos': {'registros_sockets': 'entero'},
    'conexiones': {'registros_sockets': 'entero'},
    'interfaces_red': {'interfaces_enumeradas_ip': 'entero'},
    'auditoria_seguridad': dict.fromkeys(('paquetes_rpm', 'paquetes_rpm_recogidos',
        'avisos_pendientes', 'avisos_instalados', 'dpkg_instalados', 'dpkg_incompletos',
        'dpkg_residuales', 'dpkg_no_instalados', 'dpkg_total_instalados',
        'apt_total_posibles'), 'entero') | {'reinicio_pendiente_kernel': 'booleano'},
})
PROCEDENCIAS = {'memoria': 'memoria_verificada_v1', 'servicios_fallidos': 'servicios_verificados_v1',
    'puertos': 'puertos_verificados_v1', 'conexiones': 'conexiones_verificadas_v1',
    'interfaces_red': 'interfaces_verificadas_v1'}


def _error():
    raise ValueError('contrato_historico_invalido')


def _claves(d, permitidas, requeridas=None):
    if type(d) is not dict or not set(d) <= set(permitidas) or not set(
            permitidas if requeridas is None else requeridas) <= set(d):
        _error()


def _limitar(d):
    nodos = 0
    def recorrer(v, profundidad):
        nonlocal nodos
        nodos += 1
        if nodos > MAX_NODOS or profundidad > MAX_PROFUNDIDAD:
            _error()
        if type(v) is dict:
            if len(v) > MAX_LISTA:
                _error()
            for k, valor in v.items():
                if type(k) is not str or len(k) > 128:
                    _error()
                recorrer(valor, profundidad+1)
        elif type(v) is list:
            if len(v) > MAX_LISTA:
                _error()
            for valor in v:
                recorrer(valor, profundidad+1)
        elif type(v) is str:
            if len(v) > MAX_TEXTO:
                _error()
        elif type(v) is int:
            if abs(v) > MAX_ENTERO:
                _error()
        elif type(v) is float:
            if not math.isfinite(v):
                _error()
        elif v is not None and type(v) is not bool:
            _error()
    recorrer(d, 0)
    if len(json.dumps(d, ensure_ascii=True, allow_nan=False).encode()) > MAX_ORIGEN_BYTES:
        _error()


def _numero(v):
    if v is not None and (type(v) is not int or not 0 <= v <= MAX_ENTERO):
        _error()
    return v


def _estado(adquisicion):
    if adquisicion not in MAPA:
        _error()
    return MAPA[adquisicion]


def crear(herramienta, distribucion, procedencia, version_origen, ejecucion,
          calidad, cobertura, metricas, componentes=None):
    """Constructor cerrado; devuelve copia independiente, lista para filas futuras."""
    if herramienta not in HERRAMIENTAS or distribucion not in ('fedora', 'debian13'):
        _error()
    fuentes = set(PROCEDENCIAS.values()) | {'fedora_auditoria_v1', 'debian_dpkg_v1',
                'debian_auditoria_v2', 'estado_declarado_v1'}
    if procedencia not in fuentes or type(version_origen) is not int or version_origen not in (1, 2):
        _error()
    if ejecucion not in EJECUCION or calidad not in CALIDAD or cobertura not in COBERTURA:
        _error()
    if procedencia == 'estado_declarado_v1':
        if metricas or componentes or calidad not in ('no_verificada', 'no_disponible') or version_origen != 1:
            _error()
    elif herramienta == 'auditoria_seguridad':
        esperado = ('fedora_auditoria_v1' if distribucion == 'fedora' else
                    'debian_dpkg_v1' if version_origen == 1 else 'debian_auditoria_v2')
        if procedencia != esperado or (distribucion == 'fedora' and version_origen != 1):
            _error()
    elif procedencia != PROCEDENCIAS.get(herramienta) or version_origen != 1:
        _error()
    _claves(metricas, METRICAS[herramienta], ())
    for k, v in metricas.items():
        if METRICAS[herramienta][k] == 'booleano':
            if v is not None and type(v) is not bool:
                _error()
        else:
            _numero(v)
    componentes = {} if componentes is None else componentes
    _claves(componentes, ('dpkg', 'apt'), ())
    for c in componentes.values():
        _claves(c, ('ejecucion', 'calidad', 'cobertura'))
        if c['ejecucion'] not in EJECUCION or c['calidad'] not in CALIDAD or c['cobertura'] not in COBERTURA:
            _error()
    if componentes and (herramienta != 'auditoria_seguridad' or distribucion != 'debian13'):
        _error()
    d = dict(version=VERSION, version_adaptador=VERSION_ADAPTADOR,
             version_metricas=VERSION_METRICAS, version_privacidad=1,
             herramienta=herramienta, distribucion=distribucion,
             procedencia=procedencia, version_origen=version_origen,
             ejecucion=ejecucion, calidad=calidad, cobertura=cobertura,
             metricas=metricas, componentes=componentes)
    texto = json.dumps(d, ensure_ascii=True, allow_nan=False, separators=(',', ':'))
    if len(texto.encode()) > MAX_REGISTRO_BYTES:
        _error()
    return json.loads(texto)


def validar(registro):
    _limitar(registro)
    _claves(registro, ('version', 'version_adaptador', 'version_metricas', 'version_privacidad',
        'herramienta', 'distribucion', 'procedencia', 'version_origen', 'ejecucion',
        'calidad', 'cobertura', 'metricas', 'componentes'))
    for v in ('version', 'version_adaptador', 'version_metricas', 'version_privacidad'):
        if type(registro[v]) is not int or registro[v] != 1:
            _error()
    return crear(**{k: v for k, v in registro.items() if k not in
                 ('version', 'version_adaptador', 'version_metricas', 'version_privacidad')})


def estado_conocido(herramienta, distribucion, ejecucion):
    """No recibe ni interpreta textos. Estado conocido aportado por el llamador."""
    return crear(herramienta, distribucion, 'estado_declarado_v1', 1, ejecucion,
                 'no_disponible' if ejecucion == 'no_ejecutado' else 'no_verificada',
                 'no_aplica' if ejecucion == 'no_ejecutado' else 'no_verificada', {})


def _filas(lista, claves):
    if type(lista) is not list:
        _error()
    for fila in lista:
        _claves(fila, claves)


def _metadatos_comunes(d):
    for incidencia in d['incidencias']:
        _claves(incidencia, ('fase', 'codigo', 'detalle', 'campo', 'fuente'), ('fase', 'codigo', 'detalle'))
    permitidas = {'memoria': ('meminfo',), 'servicios': ('systemctl_sistema',),
        'conexiones': ('tcp4', 'tcp6', 'udp4', 'udp6'),
        'puertos': ('tcp4', 'tcp6', 'udp4', 'udp6'), 'interfaces_red': ('ip', 'nmcli')}
    _claves(d['fuentes'], permitidas[d['herramienta']], ())
    for fuente in d['fuentes'].values():
        _claves(fuente, ('estado', 'codigo', 'ruta', 'unidad_esperada', 'protocolo',
            'familia', 'stderr', 'detalle', 'duracion_s', 'stdout_bytes', 'stderr_bytes',
            'motivo', 'avisos'), ('estado',))
    alcance = d['alcance']
    if d['herramienta'] in ('memoria', 'interfaces_red'):
        _claves(alcance, ('actividad_intercambio', 'tipo_medicion', '_compatibilidad') if
            d['herramienta'] == 'memoria' else ('observaciones', 'limitaciones', '_compatibilidad'))
        _claves(alcance['_compatibilidad'], ('formato', 'campos'))
    elif d['herramienta'] == 'servicios':
        _claves(alcance, ('gestor', 'tipo', 'seleccion', 'unidad_conteo', 'UnitFileState',
            'logs', 'procesos', 'usuarios', 'consulta', 'limite_unidades', 'limite_visibles', 'privacidad'))
    else:
        _claves(alcance, ('protocolos', 'familias', 'unidad_conteo', 'consultas', 'espacio_red',
            'procesos', 'conectividad', 'dns', 'limite_registros_por_fuente',
            'limite_registros_visibles', 'extremos_internos', 'presentacion', 'origen', 'seleccion'),
            ('protocolos', 'familias', 'unidad_conteo'))


def adaptar_verificado(resultado, distribucion):
    if not isinstance(resultado, ResultadoVerificado):
        _error()
    d = resultado.a_dict()
    _limitar(d)
    _claves(d, CAMPOS)
    nombre = 'servicios_fallidos' if d['herramienta'] == 'servicios' else d['herramienta']
    if nombre not in PROCEDENCIAS or type(d['version']) is not int or d['version'] != 1:
        _error()
    ejecucion, calidad = _estado(d['estado_adquisicion'])
    _metadatos_comunes(d)
    datos = d['datos']
    if nombre == 'memoria':
        _claves(datos, ('unidad_normalizada', 'ram', 'swap', 'actividad_intercambio'))
        if datos['unidad_normalizada'] != 'bytes':
            _error()
        _claves(datos['ram'], ('total_bytes', 'disponible_estimada_bytes', 'utilizada_estimada_bytes', 'libre_bytes'))
        _claves(datos['swap'], ('total_bytes', 'libre_bytes', 'ocupada_bytes'))
        _claves(datos['actividad_intercambio'], ('estado', 'entrada_bytes_s', 'salida_bytes_s'))
        metricas = {f'{grupo}_{k}': _numero(v) for grupo in ('ram', 'swap') for k,v in datos[grupo].items()}
    elif nombre == 'servicios_fallidos':
        _claves(datos, ('unidades', 'total_unidades', 'recuentos'))
        _filas(datos['unidades'], ('nombre', 'LoadState', 'ActiveState', 'SubState'))
        metricas = {'servicios_fallidos': _numero(datos['total_unidades'])}
    elif nombre in ('puertos', 'conexiones'):
        claves = {'registros', 'recuentos_por_fuente', 'total_registros'}
        if nombre == 'puertos':
            claves.add('recuentos_origen_por_fuente')
        _claves(datos, claves)
        campos = ('id', 'fuente', 'protocolo', 'familia', 'estado', 'local')
        if nombre == 'conexiones':
            campos += ('cola_recepcion', 'cola_envio', 'remoto', 'procesos')
        _filas(datos['registros'], campos)
        for fila in datos['registros']:
            for extremo in ('local', 'remoto') if nombre == 'conexiones' else ('local',):
                _claves(fila[extremo], ('direccion', 'tipo_direccion', 'zona', 'puerto', 'tipo_puerto'))
            if nombre == 'conexiones':
                _claves(fila['procesos'], ('estado', 'valores'))
        for conteos in ('recuentos_por_fuente', 'recuentos_origen_por_fuente'):
            if conteos in datos:
                _claves(datos[conteos], ('tcp4', 'tcp6', 'udp4', 'udp6'))
                for valor in datos[conteos].values():
                    if valor is not None:
                        _claves(valor, ('total', 'por_estado', 'excluidos'), ('total', 'por_estado'))
                        _numero(valor['total'])
        metricas = {'registros_sockets': _numero(datos['total_registros'])}
    else:
        _claves(datos, ('interfaces', 'procedencia'))
        _filas(datos['interfaces'], ('nombre', 'administrativo', 'operativo', 'radio',
                                     'conectividad', 'networkmanager', 'contadores'))
        _claves(datos['procedencia'], ('administrativo', 'operativo', 'contadores', 'networkmanager'))
        for interfaz in datos['interfaces']:
            _claves(interfaz['contadores'], ('rx', 'tx'))
            for valores in interfaz['contadores'].values():
                _claves(valores, ('bytes', 'packets', 'errors', 'dropped'))
                for valor in valores.values():
                    _numero(valor)
            if interfaz['networkmanager'] is not None:
                _claves(interfaz['networkmanager'], ('tipo_observado', 'estado_observado', 'conexion_observada'))
        # No contar NetworkManager-only como interfaces enumeradas por ip.
        _claves(d['alcance'], ('observaciones', 'limitaciones', '_compatibilidad'))
        alcance = d['alcance']['observaciones']
        _claves(alcance, ('interfaces_enumeradas_ip', 'listado_ip', 'radio', 'conectividad'))
        metricas = {'interfaces_enumeradas_ip': _numero(alcance['interfaces_enumeradas_ip'])}
    if ejecucion in ('error', 'no_verificado'):
        metricas = {k: None for k in metricas}
    return crear(nombre, distribucion, PROCEDENCIAS[nombre], 1, ejecucion, calidad,
                 'completa_en_alcance' if ejecucion == 'correcto' else
                 'parcial' if ejecucion == 'parcial' else 'no_verificada', metricas)


FEDORA = ('version', 'herramienta', 'estado_adquisicion', 'fuentes', 'kernel_activo',
    'kernels_instalados', 'kernels_mas_recientes_no_activos', 'reinicio_pendiente_kernel',
    'inventario_rpm', 'inventario_completo', 'avisos_pendientes', 'avisos_instalados',
    'recuentos', 'limitaciones')
DEBIAN = ('version', 'backend', 'herramienta', 'alcance', 'estado_seguridad',
    'estado_adquisicion', 'inventario_completo', 'inventario_dpkg', 'fuente',
    'recuentos_recogidos', 'total_instalados', 'actualizaciones', 'cve',
    'avisos_seguridad', 'limitaciones')


def adaptar_auditoria(d, distribucion):
    """Recibe .datos local ya validado, nunca el resumen textual para el modelo."""
    _limitar(d)
    if distribucion == 'fedora':
        _claves(d, FEDORA)
        _claves(d['fuentes'], ('uname', 'rpm', 'kernels', 'pendientes', 'instalados'))
        for fuente in d['fuentes'].values():
            _claves(fuente, ('estado', 'codigo', 'motivo', 'duracion_s', 'stdout_bytes',
                'stderr_bytes', 'registros_recogidos'), ('estado', 'codigo'))
        for campo in ('inventario_rpm', 'kernels_instalados'):
            if d[campo] is not None:
                _filas(d[campo], ('nombre', 'epoch', 'version', 'release', 'arquitectura'))
        for campo in ('avisos_pendientes', 'avisos_instalados'):
            if d[campo] is not None:
                _filas(d[campo], ('id', 'paquetes'))
        if type(d['version']) is not int or d['version'] != 1:
            _error()
        _claves(d['recuentos'], ('paquetes_rpm', 'avisos_pendientes', 'avisos_instalados', 'paquetes_rpm_recogidos'))
        m = dict(d['recuentos'], reinicio_pendiente_kernel=d['reinicio_pendiente_kernel'])
        if type(d['inventario_completo']) is not bool:
            _error()
        if not d['inventario_completo']:
            m['paquetes_rpm'] = None
        procedencia = 'fedora_auditoria_v1'
        componentes = {}
    elif distribucion == 'debian13':
        v = d.get('version')
        if type(v) is not int or v not in (1, 2):
            _error()
        _claves(d, DEBIAN if v == 1 else (*DEBIAN, 'estado_inventario'))
        if d['backend'] != 'debian' or type(d['inventario_completo']) is not bool:
            _error()
        _filas(d['inventario_dpkg'], ('nombre_binario', 'arquitectura', 'version',
            'estado_instalacion', 'categoria', 'nombre_fuente', 'version_fuente'))
        _claves(d['fuente'], ('nombre', 'codigo', 'motivo', 'bytes', 'stderr_bytes', 'duracion_s'), ('nombre',))
        if d['fuente']['nombre'] != 'dpkg-query':
            _error()
        _numero(d['total_instalados'])
        _claves(d['recuentos_recogidos'], ('instalado', 'incompleto', 'residual', 'no_instalado'))
        m = {dict(instalado='dpkg_instalados', incompleto='dpkg_incompletos',
                  residual='dpkg_residuales', no_instalado='dpkg_no_instalados')[k]:
             _numero(valor) for k,valor in d['recuentos_recogidos'].items()}
        m['dpkg_total_instalados'] = _numero(d['total_instalados']) if d['inventario_completo'] else None
        estado = 'completo' if d['inventario_completo'] else ('parcial' if d['inventario_dpkg'] else 'error')
        if v == 2 and d['estado_inventario'] != estado:
            _error()
        e, q = _estado(estado)
        componentes = {'dpkg': dict(ejecucion=e, calidad=q, cobertura=
            'completa_en_alcance' if d['inventario_completo'] else 'parcial' if estado == 'parcial' else 'no_verificada')}
        if v == 1:
            if d['actualizaciones'] != 'no_implementado':
                _error()
            componentes['apt'] = dict(ejecucion='no_ejecutado', calidad='no_disponible', cobertura='no_aplica')
        else:
            apt = d['actualizaciones']
            _claves(apt, ('version', 'fuente', 'estado_adquisicion', 'motivo', 'codigo', 'duracion_s',
                'bytes', 'stderr_bytes', 'indices', 'candidatos', 'recuentos_recogidos',
                'total_posibles', 'instalabilidad', 'seguridad', 'limitaciones',
                'cobertura_aplicaciones'), ('version', 'fuente', 'estado_adquisicion',
                'motivo', 'codigo', 'duracion_s', 'bytes', 'stderr_bytes', 'indices',
                'candidatos', 'recuentos_recogidos', 'total_posibles', 'instalabilidad',
                'seguridad', 'limitaciones'))
            if apt.get('cobertura_aplicaciones', 'no_verificada') != 'no_verificada':
                _error()
            if type(apt['version']) is not int or apt['version'] != 1 or apt['fuente'] != 'apt_pkg.Policy':
                _error()
            _numero(apt['total_posibles'])
            _claves(apt['recuentos_recogidos'], ('registros', 'superiores', 'retenidos', 'posibles'))
            for valor in apt['recuentos_recogidos'].values():
                _numero(valor)
            if apt['indices'] is not None:
                _claves(apt['indices'], ('configurados', 'presentes', 'ausentes', 'edad_max_s',
                    'potencialmente_desactualizados', 'frescura', 'umbral_aviso_s',
                    'necesarios', 'opcionales', 'no_aplicables', 'declarados_vacios',
                    'indeterminados', 'seleccion_verificada', 'integridad_local'),
                    ('configurados', 'presentes', 'ausentes', 'edad_max_s',
                     'potencialmente_desactualizados', 'frescura', 'umbral_aviso_s'))
                if set(apt['indices']) & {'necesarios', 'opcionales', 'no_aplicables',
                        'declarados_vacios', 'indeterminados', 'seleccion_verificada', 'integridad_local'}:
                    from apt_debian import validar_seleccion
                    validar_seleccion(apt['indices'])
                    if (apt['estado_adquisicion'] == 'completo' and
                            apt['indices']['integridad_local'] != 'completa'):
                        _error()
            _filas(apt['candidatos'], ('nombre_binario', 'arquitectura', 'instalada', 'candidata',
                'prioridad', 'retenido', 'superior', 'posible_actualizacion', 'instalable_garantizada', 'origenes'))
            for fila in apt['candidatos']:
                _filas(fila['origenes'], ('origen', 'archivo', 'componente', 'sitio', 'confiable_segun_apt'))
            ae, aq = _estado(apt['estado_adquisicion'])
            componentes['apt'] = dict(ejecucion=ae, calidad=aq, cobertura='no_verificada')
            m['apt_total_posibles'] = _numero(apt['total_posibles']) if ae == 'correcto' else None
        procedencia = 'debian_dpkg_v1' if v == 1 else 'debian_auditoria_v2'
    else:
        _error()
    if d['herramienta'] != 'auditoria_seguridad':
        _error()
    e, q = _estado(d['estado_adquisicion'])
    return crear('auditoria_seguridad', distribucion, procedencia, d['version'],
                 e, q, 'no_verificada', m, componentes)
