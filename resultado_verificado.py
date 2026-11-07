"""Contrato interno y adaptadores sin adquisición, presentación ni cliente HTTP."""
import json

CAMPOS = ('version', 'herramienta', 'estado_adquisicion', 'estado_presentacion',
          'fuentes', 'datos', 'incidencias', 'alcance')
ADQUISICION = ('completo', 'parcial', 'error', 'desconocido')
PRESENTACION = ('pendiente', 'completo', 'parcial', 'error', 'omitido_por_limite')


def _json_sin_perdidas(valor):
    if isinstance(valor, dict):
        if any(not isinstance(k, str) for k in valor):
            raise TypeError('Las claves JSON deben ser texto.')
        for v in valor.values():
            _json_sin_perdidas(v)
    elif isinstance(valor, list):
        for v in valor:
            _json_sin_perdidas(v)
    elif valor is not None and type(valor) not in (str, bool, int, float):
        raise TypeError('Tipo no representable sin pérdidas en JSON.')


class ResultadoVerificado:
    """Una sola instantánea JSON; a_dict() devuelve siempre una copia profunda.

    No se guarda un diccionario mutable en paralelo. Solo se serializa al crear
    una instantánea o una nueva fase de presentación; a_json() reutiliza el texto.
    """
    __slots__ = ('_json',)

    def __init__(self, documento):
        if not isinstance(documento, dict) or set(documento) != set(CAMPOS):
            raise ValueError('Campos del contrato común inválidos.')
        if type(documento['version']) is not int or documento['version'] != 1:
            raise ValueError('Versión del contrato común no admitida.')
        if documento['herramienta'] not in ('interfaces_red', 'memoria', 'conexiones', 'puertos', 'servicios'):
            raise ValueError('Herramienta no admitida.')
        if documento['estado_adquisicion'] not in ADQUISICION or documento['estado_presentacion'] not in PRESENTACION:
            raise ValueError('Estado del contrato común inválido.')
        for campo in ('fuentes', 'datos', 'alcance'):
            if not isinstance(documento[campo], dict):
                raise TypeError('Se esperaba un objeto en ' + campo)
        if not isinstance(documento['incidencias'], list):
            raise TypeError('Se esperaba una lista de incidencias.')
        for incidencia in documento['incidencias']:
            if (not isinstance(incidencia, dict) or incidencia.get('fase') not in ('adquisicion', 'presentacion')
                    or not isinstance(incidencia.get('codigo'), str)
                    or not isinstance(incidencia.get('detalle'), str)):
                raise ValueError('Incidencia inválida.')
        _json_sin_perdidas(documento)
        object.__setattr__(self, '_json', json.dumps(documento, ensure_ascii=True,
                                                   separators=(',', ':'), allow_nan=False))

    def __setattr__(self, nombre, valor):
        raise AttributeError('La instantánea es inmutable.')

    def __delattr__(self, nombre):
        raise AttributeError('La instantánea es inmutable.')

    def a_dict(self):
        return json.loads(self._json)

    def a_json(self):
        return self._json

    @property
    def estado_presentacion(self):
        return self.a_dict()['estado_presentacion']

    def con_presentacion(self, estado):
        if estado == 'pendiente' or estado not in PRESENTACION:
            raise ValueError('Se esperaba un estado final de presentación.')
        documento = self.a_dict()
        cambio = documento['estado_presentacion'] != estado
        documento['estado_presentacion'] = estado
        if estado in ('parcial', 'omitido_por_limite', 'error'):
            detalles = {'parcial': 'El presentador indica un resultado parcial.',
                        'omitido_por_limite': 'El presentador omitió datos por el límite de tamaño.',
                        'error': 'El presentador indica un resultado de error.'}
            incidencia = {'fase': 'presentacion', 'codigo': estado, 'detalle': detalles[estado]}
            if incidencia not in documento['incidencias']:
                documento['incidencias'].append(incidencia)
                cambio = True
        return ResultadoVerificado(documento) if cambio else self


def _incidencia(codigo, detalle, **campos):
    return {'fase': 'adquisicion', 'codigo': codigo, 'detalle': detalle, **campos}


def _validar_original(original, herramienta):
    estados = ('completo', 'parcial', 'error')
    if herramienta == 'interfaces_red':
        estados += ('omitido_por_limite',)
    if (not isinstance(original, dict) or type(original.get('version')) is not int
            or original['version'] != 1 or original.get('herramienta') != herramienta
            or original.get('estado') not in estados):
        raise ValueError('Formato de origen no admitido.')


def adaptar_interfaces(original):
    """Recibe el diccionario legacy, sin volver a serializar ResultadoInterfaces."""
    _validar_original(original, 'interfaces_red')
    excluidos = {'version', 'herramienta', 'estado', 'fuentes', 'avisos', 'alcance', 'limitaciones'}
    incidencias = [_incidencia('aviso', aviso) for aviso in original.get('avisos', [])]
    fuentes = original.get('fuentes', {})
    for nombre, fuente in fuentes.items():
        if fuente.get('estado') != 'correcta':
            incidencias.append(_incidencia('fuente_no_utilizable', 'La fuente no es completamente utilizable.', fuente=nombre))
    omitido = original['estado'] == 'omitido_por_limite'
    if omitido:
        incidencias.append(_incidencia('adquisicion_no_disponible',
                                      'El formato anterior ya había omitido los datos; no se infiere cómo terminó su adquisición.'))
    return ResultadoVerificado({
        'version': 1, 'herramienta': 'interfaces_red',
        'estado_adquisicion': 'desconocido' if omitido else original['estado'],
        'estado_presentacion': 'pendiente', 'fuentes': fuentes,
        'datos': {k: v for k, v in original.items() if k not in excluidos},
        'incidencias': incidencias,
        'alcance': {'observaciones': original.get('alcance'), 'limitaciones': original.get('limitaciones'),
                    '_compatibilidad': {'formato': 'interfaces_v1', 'campos': list(original)}},
    })


def adaptar_memoria(original):
    _validar_original(original, 'memoria')
    excluidos = {'version', 'herramienta', 'estado', 'fuente', 'avisos', 'problemas_campos'}
    incidencias = [_incidencia('aviso', aviso) for aviso in original.get('avisos', [])]
    incidencias.extend(_incidencia('campo_no_utilizable', detalle, campo=campo)
                       for campo, detalle in original.get('problemas_campos', {}).items())
    fuente = original.get('fuente')
    if fuente is not None and fuente.get('estado') != 'correcta':
        incidencias.append(_incidencia('fuente_no_utilizable', 'La fuente no es utilizable.', fuente='meminfo'))
    return ResultadoVerificado({
        'version': 1, 'herramienta': 'memoria', 'estado_adquisicion': original['estado'],
        'estado_presentacion': 'pendiente', 'fuentes': {'meminfo': fuente} if fuente is not None else {},
        'datos': {k: v for k, v in original.items() if k not in excluidos},
        'incidencias': incidencias,
        'alcance': {'actividad_intercambio': original.get('actividad_intercambio', {}).get('estado'),
                    'tipo_medicion': 'instantanea',
                    '_compatibilidad': {'formato': 'memoria_v1', 'campos': list(original)}},
    })


def formato_anterior(resultado):
    """Reconstruye campos, orden e incidencias originales para los presentadores.

    La lista de nombres preserva ausencia frente a campo vacío y extensiones.
    No duplica sus valores ni guarda otro documento autoritativo.
    """
    d = resultado.a_dict()
    formato = d['alcance']['_compatibilidad']['formato']
    interfaces = formato == 'interfaces_v1'
    if formato not in ('interfaces_v1', 'memoria_v1'):
        raise ValueError('Adaptador de origen desconocido.')
    estado = d['estado_adquisicion']
    if interfaces and estado == 'desconocido':
        estado = 'omitido_por_limite'
    campos = {'version': 1, 'herramienta': d['herramienta'], 'estado': estado, **d['datos']}
    avisos = [i['detalle'] for i in d['incidencias'] if i['fase'] == 'adquisicion' and i['codigo'] == 'aviso']
    if interfaces:
        campos.update(fuentes=d['fuentes'], avisos=avisos,
                      alcance=d['alcance']['observaciones'], limitaciones=d['alcance']['limitaciones'])
    else:
        campos.update(fuente=d['fuentes'].get('meminfo'), avisos=avisos,
                      problemas_campos={i['campo']: i['detalle'] for i in d['incidencias']
                                        if i['fase'] == 'adquisicion' and i['codigo'] == 'campo_no_utilizable'})
    return {nombre: campos[nombre] for nombre in d['alcance']['_compatibilidad']['campos']}
