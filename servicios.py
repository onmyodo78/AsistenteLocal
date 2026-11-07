"""Servicios fallidos del gestor del sistema: parser e informe sin adquisición.

Los nombres son visibles por decisión del usuario. Descripciones y errores
originales no forman parte del resultado normalizado.
"""
import re

from resultado_verificado import ResultadoVerificado

COMANDO = ('systemctl', '--system', '--no-pager', '--no-ask-password', '--plain',
           '--no-legend', '--full', 'list-units', '--type=service', '--state=failed')
MAX_UNIDADES = 500
MAX_VISIBLES = 20
ESTADOS_CARGA = frozenset(('stub', 'loaded', 'not-found', 'bad-setting', 'error',
                           'merged', 'masked'))
ESTADOS_FUENTE = frozenset(('correcta', 'truncada', 'tiempo_agotado',
                           'ejecutable_ausente', 'permiso_denegado', 'error_comando',
                           'error_sistema', 'avisos_no_interpretados'))
# No se decodifican escapes. Se excluyen rutas, controles y caracteres de terminal.
NOMBRE = re.compile(r'(?:[A-Za-z0-9:_.@-]|\\x[0-9a-fA-F]{2})+\.service', re.ASCII)
TOKEN_ESTADO = re.compile(r'[a-z][a-z0-9-]{0,63}', re.ASCII)


class FuenteInvalida(ValueError):
    def __init__(self, codigo='formato_invalido'):
        super().__init__('Fuente de servicios no interpretable con seguridad.')
        self.codigo = codigo


def parsear_servicios(texto, limite=MAX_UNIDADES):
    if not isinstance(texto, str) or type(limite) is not int or limite < 0:
        raise FuenteInvalida()
    # Las descripciones pueden ser Unicode; los controles se rechazan en todo el bloque.
    if any((ord(c) < 32 and c not in '\n\r\t') or 127 <= ord(c) <= 159
           or c in '\u2028\u2029\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069'
           for c in texto):
        raise FuenteInvalida()
    filas = [l for l in texto.splitlines() if l.strip()]
    if len(filas) > limite:
        raise FuenteInvalida('limite_unidades')
    unidades, nombres = [], set()
    for fila in filas:
        campos = fila.split(maxsplit=4)
        if len(campos) != 5:
            raise FuenteInvalida()
        nombre, carga, activo, sub, _ = campos  # La descripción se descarta inmediatamente.
        if (len(nombre) > 255 or not NOMBRE.fullmatch(nombre)
                or nombre == '.service' or nombre.startswith('@') or nombre.endswith('@.service')
                or nombre.count('@') > 1 or nombre in nombres
                or carga not in ESTADOS_CARGA or activo != 'failed'
                or not TOKEN_ESTADO.fullmatch(sub)):
            raise FuenteInvalida()
        nombres.add(nombre)
        unidades.append({'nombre': nombre, 'LoadState': carga,
                         'ActiveState': activo, 'SubState': sub})
    return sorted(unidades, key=lambda u: u['nombre'])


def normalizar_servicios(fuente):
    estado = fuente.get('estado')
    if estado not in ESTADOS_FUENTE:
        estado = 'error_sistema'
    unidades = None
    if estado == 'correcta':
        try:
            unidades = parsear_servicios(fuente.get('stdout', ''))
        except FuenteInvalida as error:
            estado = error.codigo
    recuentos = None
    if unidades is not None:
        recuentos = {campo: {} for campo in ('LoadState', 'ActiveState', 'SubState')}
        for u in unidades:
            for campo, conteo in recuentos.items():
                valor = u[campo]
                conteo[valor] = conteo.get(valor, 0) + 1
    return ResultadoVerificado({
        'version': 1, 'herramienta': 'servicios',
        'estado_adquisicion': 'completo' if unidades is not None else 'error',
        'estado_presentacion': 'pendiente',
        'fuentes': {'systemctl_sistema': {'estado': estado, 'codigo': fuente.get('codigo')}},
        'datos': {'unidades': unidades if unidades is not None else [],
                  'total_unidades': len(unidades) if unidades is not None else None,
                  'recuentos': recuentos},
        'incidencias': [] if unidades is not None else [
            {'fase': 'adquisicion', 'codigo': estado, 'fuente': 'systemctl_sistema',
             'detalle': 'Fuente descartada; el recuento es desconocido, no cero.'}],
        'alcance': {'gestor': 'sistema', 'tipo': 'service', 'seleccion': 'ActiveState=failed',
                    'unidad_conteo': 'unidades_enumeradas', 'UnitFileState': 'no_solicitado',
                    'logs': 'no_solicitados', 'procesos': 'no_solicitados',
                    'usuarios': 'no_consultados', 'consulta': 'unica_no_transaccional',
                    'limite_unidades': MAX_UNIDADES, 'limite_visibles': MAX_VISIBLES,
                    'privacidad': 'nombres_visibles_sin_descripciones_rutas_ni_errores_originales'},
    })


def informe_servicios(resultado, limite=18000):
    d = resultado.a_dict()
    if d['herramienta'] != 'servicios':
        raise ValueError('Se esperaba una instantánea de servicios.')
    estado = d['estado_adquisicion']
    datos = d['datos']
    total = datos['total_unidades']
    lineas = ['Informe determinista de servicios fallidos — generado por Python',
              f'Adquisición: {estado}.', 'Alcance: gestor systemd del sistema; solo unidades .service con ActiveState=failed.',
              f'Fuente systemctl_sistema: {d["fuentes"]["systemctl_sistema"]["estado"]}.',
              'Servicios fallidos observados: ' + (str(total) if total is not None else 'desconocido') + '.']
    if total is not None:
        for campo, conteo in datos['recuentos'].items():
            valores = ', '.join(f'{k}={v}' for k, v in sorted(conteo.items())) or 'sin unidades'
            lineas.append(f'{campo}: {valores}.')
        if total == 0:
            lineas.append('No se observaron servicios fallidos en el gestor del sistema consultado; no garantiza salud general ni ausencia de otros problemas.')
        else:
            lineas.append(f'Vista breve: {min(total, MAX_VISIBLES)} de {total} unidades.')
    for u in datos['unidades'][:MAX_VISIBLES]:
        lineas.append(f'{u["nombre"]}: LoadState={u["LoadState"]}; ActiveState={u["ActiveState"]}; SubState={u["SubState"]}.')
    if total is not None and total > MAX_VISIBLES:
        estado = 'parcial'
        lineas.append('Presentación parcial: hay más unidades; los recuentos incluyen todas las adquiridas.')
    lineas.extend([
        'ActiveState es estado de ejecución; LoadState es estado de carga. UnitFileState: no solicitado.',
        'inactive no equivale a failed; disabled no implica fallo. active no demuestra funcionamiento correcto.',
        'La ausencia en esta lista no demuestra que una unidad esté sana, ausente o descargada.',
        'No se deducen causas ni necesidad de habilitar servicios. No se consultan logs, procesos ni propiedades adicionales.',
        'Consulta única, no transaccional; los estados pueden cambiar. No se consulta el gestor de usuario.',
        'Privacidad: nombres reales visibles, incluidos escapes literales; pueden contener información sensible. No se conservan descripciones, rutas ni errores originales.',
    ])
    texto = '\n'.join(lineas)
    if len(texto) > limite:
        texto = 'Informe de servicios omitido por límite de tamaño; no permite concluir ausencia de fallos.'
        estado = 'omitido_por_limite'
    if len(texto) > limite:
        raise ValueError('No cabe el aviso de informe omitido.')
    return texto, resultado.con_presentacion(estado)
