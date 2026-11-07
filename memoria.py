"""Instantánea determinista de RAM/swap. Sin modelo ni medición de actividad."""
CAMPOS = ('MemTotal', 'MemAvailable', 'MemFree', 'SwapTotal', 'SwapFree')
REQUERIDOS = ('MemTotal', 'MemAvailable', 'SwapTotal', 'SwapFree')

# Solo este lector se ejecuta en un hijo, para que el ejecutor existente pueda
# interrumpir una lectura bloqueada. Ruta fija; sin rutas ni código del usuario.
LECTOR_MEMINFO = '''import sys
try:
    with open('/proc/meminfo', 'rb') as fuente:
        datos = fuente.read(int(sys.argv[1]) + 1)
except FileNotFoundError:
    sys.exit(66)
except PermissionError:
    sys.exit(77)
except OSError:
    sys.exit(74)
sys.stdout.buffer.write(datos)
'''


def comando_meminfo(interprete, limite):
    if type(limite) is not int or limite <= 0:
        raise ValueError('Límite de captura inválido.')
    return [interprete, '-B', '-c', LECTOR_MEMINFO, str(limite)]


def normalizar_memoria(fuente):
    """Fuente: estado, código, stdout y presencia de avisos; no conserva texto bruto."""
    valores = {campo: None for campo in CAMPOS}
    problemas = {}
    avisos = []
    if fuente['estado'] == 'correcta':
        vistos = set()
        for linea in fuente.get('stdout', '').splitlines():
            if not linea.strip():
                continue
            if ':' not in linea:
                avisos.append('Hay líneas de formato no reconocido.')
                continue
            clave, texto = linea.split(':', 1)
            clave = clave.strip()
            if clave not in CAMPOS:
                continue  # /proc/meminfo contiene también campos sin unidad kB.
            if clave in vistos:
                valores[clave] = None
                problemas[clave] = 'campo duplicado'
                continue
            vistos.add(clave)
            partes = texto.split()
            if (len(partes) != 2 or partes[1] != 'kB'
                    or not partes[0].isascii() or not partes[0].isdecimal()):
                problemas[clave] = 'valor o unidad inválidos'
                continue
            try:
                valores[clave] = int(partes[0]) * 1024
            except ValueError:
                problemas[clave] = 'valor numérico inválido'
        for clave in REQUERIDOS:
            if clave not in vistos:
                problemas[clave] = 'campo ausente'
        for menor, mayor in (('MemAvailable', 'MemTotal'), ('MemFree', 'MemTotal'),
                             ('SwapFree', 'SwapTotal')):
            if valores[menor] is not None and valores[mayor] is not None and valores[menor] > valores[mayor]:
                valores[menor] = None
                problemas[menor] = 'supera el total observado; dato no utilizable'
        if fuente.get('avisos'):
            avisos.append('El lector emitió avisos; no se interpretan como datos.')
    else:
        avisos.append('La fuente no es utilizable; no se interpreta su salida, aunque contenga un prefijo válido.')

    def diferencia(total, libre):
        return valores[total] - valores[libre] if valores[total] is not None and valores[libre] is not None else None

    estado = 'completo'
    if not any(valor is not None for valor in valores.values()):
        estado = 'error'
    elif problemas or avisos:
        estado = 'parcial'
    return {
        'version': 1, 'herramienta': 'memoria', 'estado': estado,
        'fuente': {'ruta': '/proc/meminfo', 'estado': fuente['estado'], 'codigo': fuente.get('codigo'),
                   'unidad_esperada': 'kB de Linux (1024 bytes)'},
        'unidad_normalizada': 'bytes',
        'ram': {'total_bytes': valores['MemTotal'], 'disponible_estimada_bytes': valores['MemAvailable'],
                'utilizada_estimada_bytes': diferencia('MemTotal', 'MemAvailable'),
                'libre_bytes': valores['MemFree']},
        'swap': {'total_bytes': valores['SwapTotal'], 'libre_bytes': valores['SwapFree'],
                 'ocupada_bytes': diferencia('SwapTotal', 'SwapFree')},
        'actividad_intercambio': {'estado': 'no_medida', 'entrada_bytes_s': None, 'salida_bytes_s': None},
        'problemas_campos': problemas, 'avisos': sorted(set(avisos)),
    }


def _cantidad(valor):
    if valor is None:
        return 'desconocido'
    # Redondeo decimal a la mitad hacia arriba, exacto y sin float.
    divisor = 1024**3
    centesimas, resto = divmod(valor * 100, divisor)
    if resto * 2 >= divisor:
        centesimas += 1
    return f'{valor} B ({centesimas // 100}.{centesimas % 100:02d} GiB, aprox.)'


def informe_memoria(datos, limite=18000):
    estado = datos['estado']
    if estado not in ('completo', 'parcial', 'error'):
        raise ValueError('Estado de memoria desconocido.')
    ram, swap = datos['ram'], datos['swap']
    lineas = [
        'Informe determinista de memoria — generado por Python',
        f'Resultado: {estado}. Fuente: /proc/meminfo; lectura={datos["fuente"]["estado"]}.',
        'Unidades: kB de Linux = 1024 B; valores normalizados en bytes. GiB = 1024³ B.',
        'RAM total visible para el kernel: ' + _cantidad(ram['total_bytes']),
        'RAM disponible estimada (MemAvailable): ' + _cantidad(ram['disponible_estimada_bytes']),
        'RAM utilizada estimada (MemTotal - MemAvailable): ' + _cantidad(ram['utilizada_estimada_bytes']),
        'RAM libre (MemFree, dato opcional): ' + _cantidad(ram['libre_bytes']),
        'Swap total: ' + _cantidad(swap['total_bytes']),
        'Swap libre: ' + _cantidad(swap['libre_bytes']),
        'Swap ocupada (SwapTotal - SwapFree): ' + _cantidad(swap['ocupada_bytes']),
        'Actividad de intercambio: no_medida. No se han obtenido tasas de entrada/salida.',
    ]
    if estado != 'completo':
        lineas.append('Datos incompletos o errores: los valores desconocidos no significan cero.')
    for campo, problema in datos['problemas_campos'].items():
        lineas.append(f'{campo}: {problema}.')
    lineas.extend(datos['avisos'])
    lineas.extend([
        'Límites de interpretación:',
        '- Swap ocupada no demuestra actividad de intercambio actual ni su ausencia.',
        '- Disponible es una estimación del kernel; no equivale a RAM libre ni garantiza suficiencia futura.',
        '- Utilizada estimada no es la suma del consumo de procesos y puede diferir de otras definiciones de free.',
        '- No se suman libre y disponible. Total visible no equivale necesariamente a RAM físicamente instalada.',
        '- Esta instantánea no diagnostica fugas, presión de memoria, rendimiento ni actividad de disco.',
    ])
    texto = '\n'.join(lineas)
    if len(texto) > limite:
        texto = 'Informe de memoria omitido por límite de tamaño; no permite concluir valores de RAM o swap.'
        estado = 'omitido_por_limite'
    if len(texto) > limite:
        raise ValueError('No cabe el aviso de informe omitido.')
    return texto, estado
