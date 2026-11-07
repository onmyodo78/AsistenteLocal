"""Normalización pura de interfaces. No ejecuta comandos ni consulta la red."""
import json

CAMPOS = ('bytes', 'packets', 'errors', 'dropped')
LIMITACIONES = [
    'Estado administrativo, operativo y de NetworkManager son observaciones distintas.',
    'Radio desconocida: no se ha consultado su estado.',
    'Conectividad no comprobada: no se han realizado pruebas de destino.',
    'Contadores acumulados; no son velocidades ni prueban tráfico actual.',
    'Las fuentes se consultan secuencialmente; no forman una instantánea atómica.',
]
OMITIDO = {'version': 1, 'herramienta': 'interfaces_red',
           'estado': 'omitido_por_limite', 'interfaces': [],
           'limitacion': 'Datos omitidos por presupuesto; no es un listado vacío.'}
MIN_JSON = len(json.dumps(OMITIDO, ensure_ascii=True, separators=(',', ':')))


def _base(nombre):
    return {'nombre': nombre, 'administrativo': 'desconocido',
            'operativo': 'desconocido', 'radio': 'desconocida',
            'conectividad': 'no_comprobada', 'networkmanager': None,
            'contadores': {sentido: {k: None for k in CAMPOS} for sentido in ('rx', 'tx')}}


def _objeto_unico(pares):
    objeto = {}
    for clave, valor in pares:
        if clave in objeto:
            raise ValueError('Claves JSON duplicadas; fuente descartada.')
        objeto[clave] = valor
    return objeto


def _constante_invalida(valor):
    raise ValueError('Constante JSON no estándar: ' + valor)


def _ip(texto):
    filas = json.loads(texto, object_pairs_hook=_objeto_unico, parse_constant=_constante_invalida)
    if not isinstance(filas, list):
        raise ValueError('Se esperaba una lista JSON de interfaces.')
    interfaces, avisos = {}, []
    for fila in filas:
        if not isinstance(fila, dict) or not isinstance(fila.get('ifname'), str) or not fila['ifname']:
            raise ValueError('Interfaz sin nombre válido; listado descartado.')
        nombre = fila['ifname']
        if nombre in interfaces:
            raise ValueError('Nombres duplicados; listado descartado.')
        dato = _base(nombre)
        flags = fila.get('flags')
        if isinstance(flags, list) and all(isinstance(f, str) for f in flags):
            dato['administrativo'] = 'UP' if 'UP' in flags else 'DOWN'
        else:
            avisos.append('Banderas administrativas ausentes o inválidas.')
        estado = fila.get('operstate')
        if isinstance(estado, str) and estado:
            dato['operativo'] = estado
        else:
            avisos.append('Estado operativo ausente o inválido.')
        stats = fila.get('stats64', fila.get('stats'))
        for sentido in ('rx', 'tx'):
            valores = stats.get(sentido) if isinstance(stats, dict) else None
            for campo in CAMPOS:
                valor = valores.get(campo) if isinstance(valores, dict) else None
                if type(valor) is int and valor >= 0:
                    dato['contadores'][sentido][campo] = valor
                else:
                    avisos.append('Hay contadores ausentes o inválidos.')
        interfaces[nombre] = dato
    return interfaces, sorted(set(avisos))


def _campos_nm(linea):
    campos, campo, escape = [], [], False
    for caracter in linea:
        if escape:
            if caracter not in (':', '\\'):
                raise ValueError('Escape nmcli no reconocido.')
            campo.append(caracter)
            escape = False
        elif caracter == '\\':
            escape = True
        elif caracter == ':':
            campos.append(''.join(campo))
            campo = []
        else:
            campo.append(caracter)
    if escape:
        raise ValueError('Escape nmcli incompleto.')
    campos.append(''.join(campo))
    if len(campos) != 4 or not campos[0]:
        raise ValueError('Fila nmcli inválida.')
    return campos


def _nm(texto):
    dispositivos = {}
    for linea in texto.splitlines():
        if not linea.strip():
            continue
        nombre, tipo, estado, conexion = _campos_nm(linea)
        if nombre in dispositivos:
            raise ValueError('Dispositivo nmcli duplicado.')
        dispositivos[nombre] = {'tipo_observado': tipo or None,
                                'estado_observado': estado or None,
                                'conexion_observada': conexion or None}
    return dispositivos


def normalizar(fuentes):
    """Cada fuente contiene estado de ejecución, stdout, stderr y código."""
    fuentes = {nombre: dict(fuentes[nombre]) for nombre in ('ip', 'nmcli')}
    interfaces, dispositivos, avisos = {}, {}, []
    for nombre, parser in (('ip', _ip), ('nmcli', _nm)):
        fuente = fuentes[nombre]
        texto = fuente.pop('stdout', '')
        # No interpretar ni siquiera un prefijo válido de un comando fallido/truncado.
        if fuente['estado'] != 'correcta':
            continue
        try:
            datos = parser(texto)
            if nombre == 'ip':
                interfaces, avisos = datos
            else:
                dispositivos = datos
        except (ValueError, TypeError, RecursionError) as error:
            fuente['estado'] = 'formato_invalido'
            fuente['detalle'] = str(error)[:300]
    ip_correcta = fuentes['ip']['estado'] == 'correcta'
    nm_correcta = fuentes['nmcli']['estado'] == 'correcta'
    cantidad_ip = len(interfaces) if ip_correcta else None
    if ip_correcta and nm_correcta and set(interfaces) != set(dispositivos):
        avisos.append('Las fuentes enumeran dispositivos distintos; no son una instantánea atómica.')
    for nombre, fuente in fuentes.items():
        if fuente.get('stderr'):
            avisos.append(f'La fuente {nombre} emitió avisos; revisar sus metadatos.')
    for dispositivo in dispositivos.values():
        if dispositivo['tipo_observado'] is None or dispositivo['estado_observado'] is None:
            avisos.append('Hay campos de NetworkManager desconocidos.')
    for nombre, dispositivo in dispositivos.items():
        interfaces.setdefault(nombre, _base(nombre))['networkmanager'] = dispositivo
    estados = [f['estado'] == 'correcta' for f in fuentes.values()]
    estado = 'completo' if all(estados) and not avisos else 'parcial'
    if not any(estados):
        estado = 'error'
    return {'version': 1, 'herramienta': 'interfaces_red', 'estado': estado,
            'fuentes': fuentes, 'avisos': sorted(set(avisos)), 'limitaciones': LIMITACIONES,
            'procedencia': {'administrativo': 'bandera UP de ip',
                            'operativo': 'operstate de ip', 'contadores': 'stats64/stats de ip',
                            'networkmanager': 'campos literales de nmcli'},
            'interfaces': list(interfaces.values()),
            'alcance': {'interfaces_enumeradas_ip': cantidad_ip, 'listado_ip': 'completo' if ip_correcta else 'no_disponible',
                       'radio': 'no_medida', 'conectividad': 'no_comprobada'}}


def _etiqueta(texto):
    visible = texto[:40]
    while len(json.dumps(visible, ensure_ascii=True)) > 48:
        visible = visible[:-1]
    return json.dumps(visible, ensure_ascii=True) + (' [abreviado]' if visible != texto else '')


def resumen(datos):
    if datos['estado'] == 'omitido_por_limite':
        return 'Interfaces: datos omitidos por presupuesto; no es un listado vacío.'
    lineas = [f"Interfaces — resultado {datos['estado']}."]
    registros = datos['interfaces']
    if datos['estado'] == 'error':
        lineas.append('Sin registros utilizables; cantidad de interfaces desconocida.')
    else:
        lineas.append(f'Registros observados entre fuentes: {len(registros)}; no equivale a interfaces activas.')
    for dato in registros[:6]:
        # json.dumps escapa controles y mantiene nombres en una sola línea.
        nombre = _etiqueta(dato['nombre'])
        operativo = _etiqueta(dato['operativo'])
        nm = dato['networkmanager']
        estado_nm = nm.get('estado_observado') if nm else None
        etiqueta_nm = _etiqueta(estado_nm) if estado_nm is not None else 'desconocido'
        lineas.append(f"{nombre}: administrativo={dato['administrativo']}; operativo={operativo}; NetworkManager={etiqueta_nm}.")
    if len(registros) > 6:
        lineas.append('Vista breve: se muestran seis registros; los datos enviados indican su alcance.')
    lineas.append('Radio: desconocida. Conectividad: no comprobada. Contadores: acumulados, no velocidades.')
    lineas.append('Fuentes: ' + '; '.join(n + '=' + f['estado'] for n, f in datos['fuentes'].items()))
    if datos['estado'] != 'completo':
        lineas.append('Hay datos incompletos o errores; no deducir ausencia de interfaces ni contadores cero.')
    return '\n'.join(lineas)


def informe_verificado(datos, limite=18000):
    """Informe final sin texto del modelo; devuelve texto y estado presentado."""
    estado = datos['estado']
    if estado not in ('completo', 'parcial', 'error', 'omitido_por_limite'):
        raise ValueError('Estado de adquisición desconocido.')
    lineas = ['Informe determinista de interfaces — generado por Python', resumen(datos)]
    if estado != 'omitido_por_limite':
        registros = datos['interfaces'][:6]
        if registros:
            lineas.append('Contadores acumulados de la vista breve (no son velocidades):')
        for dato in registros:
            partes = []
            for sentido in ('rx', 'tx'):
                valores = dato['contadores'][sentido]
                campos = ', '.join(
                    f"{campo}={valores[campo] if valores[campo] is not None else 'desconocido'}"
                    for campo in CAMPOS)
                partes.append(f'{sentido.upper()}: {campos}')
            lineas.append(_etiqueta(dato['nombre']) + ': ' + '; '.join(partes))
        if len(datos['interfaces']) > 6:
            lineas.append('Presentación parcial: la vista breve está limitada a seis registros.')
            if estado == 'completo':
                estado = 'parcial'
        lineas.extend([
            'Claves de lectura:',
            '- Administrativo: UP indica habilitación administrativa; no confirma conectividad.',
            '- Operativo: se conserva el estado informado por ip. DOWN no determina el estado de la radio.',
            '- NetworkManager: su estado se presenta por separado; no prueba acceso a un destino.',
            '- Clasificación física/virtual: no determinada.',
        ])
    texto = '\n'.join(lineas)
    if len(texto) > limite:
        texto = 'Informe omitido por límite de tamaño; no permite afirmar ausencia de interfaces.'
        estado = 'omitido_por_limite'
    if len(texto) > limite:
        raise ValueError('No cabe el aviso de informe omitido.')
    return texto, estado


class ResultadoInterfaces(str):
    """Compatible con el contrato textual existente; siempre contiene JSON íntegro."""
    def __new__(cls, datos, limite):
        if limite < MIN_JSON:
            raise ValueError('Presupuesto insuficiente para un resultado estructurado.')
        texto = json.dumps(datos, ensure_ascii=True, separators=(',', ':'), allow_nan=False)
        if len(texto) > limite:
            datos = dict(OMITIDO)
            texto = json.dumps(datos, ensure_ascii=True, separators=(',', ':'))
        return super().__new__(cls, texto)

    @property
    def datos(self):
        """Copia independiente obtenida del único JSON autoritativo e inmutable."""
        return json.loads(self)

    def ajustar(self, limite):
        return ResultadoInterfaces(self.datos, limite)
