"""Sockets TCP/UDP: consultas fijas, parser estricto e informe sin modelo.

Los extremos completos del resultado interno son sensibles; no se imprimen ni
se registran. No se solicitan procesos, DNS, servicios ni conexiones de prueba.
"""
import ipaddress
import re
from resultado_verificado import ResultadoVerificado

MAX_REGISTROS_FUENTE = 500
MAX_REGISTROS_VISIBLES = 20
FUENTES = (
    ('tcp4', 'tcp', 'ipv4', ('ss', '-H', '-O', '-n', '-a', '-t', '-4')),
    ('tcp6', 'tcp', 'ipv6', ('ss', '-H', '-O', '-n', '-a', '-t', '-6')),
    ('udp4', 'udp', 'ipv4', ('ss', '-H', '-O', '-n', '-a', '-u', '-4')),
    ('udp6', 'udp', 'ipv6', ('ss', '-H', '-O', '-n', '-a', '-u', '-6')),
)
ESTADOS_TCP = frozenset(('ESTAB', 'SYN-SENT', 'SYN-RECV', 'FIN-WAIT-1', 'FIN-WAIT-2',
                         'TIME-WAIT', 'UNCONN', 'CLOSE-WAIT', 'LAST-ACK', 'LISTEN',
                         'CLOSING', 'NEW-SYN-RECV', 'BOUND-INACTIVE'))
ESTADOS_UDP = frozenset(('UNCONN', 'ESTAB'))
ESTADOS_FUENTE = frozenset(('correcta', 'truncada', 'tiempo_agotado', 'ejecutable_ausente',
                           'permiso_denegado', 'error_comando', 'error_sistema',
                           'avisos_no_interpretados', 'formato_invalido', 'limite_registros'))


class FuenteInvalida(ValueError):
    def __init__(self, codigo='formato_invalido'):
        # No se incorpora ninguna línea, extremo o fragmento de entrada al error.
        super().__init__('Fuente de sockets no interpretable con seguridad.')
        self.codigo = codigo


def _entero(texto, maximo):
    if (not texto or not texto.isascii() or not texto.isdecimal()
            or len(texto) > 20):
        raise FuenteInvalida()
    valor = int(texto)
    if valor > maximo:
        raise FuenteInvalida()
    return valor


def extremo(texto, familia):
    if familia not in ('ipv4', 'ipv6'):
        raise FuenteInvalida()
    corchetes = texto.startswith('[')
    zona_externa = None
    if corchetes:
        cierre = texto.find(']')
        if cierre < 0:
            raise FuenteInvalida()
        direccion = texto[1:cierre]
        sufijo = texto[cierre+1:]
        if sufijo.startswith('%'):
            zona_externa, separador, puerto = sufijo[1:].partition(':')
            if not separador or '%' in direccion:
                raise FuenteInvalida()
        elif sufijo.startswith(':'):
            puerto = sufijo[1:]
        else:
            raise FuenteInvalida()
    else:
        direccion, separador, puerto = texto.rpartition(':')
        if not separador:
            raise FuenteInvalida()
    if not direccion or any(c in direccion for c in '[]'):
        raise FuenteInvalida()
    numero = None if puerto == '*' else _entero(puerto, 65535)
    zona = zona_externa
    if '%' in direccion:
        if direccion.count('%') != 1:
            raise FuenteInvalida()
        direccion, zona = direccion.split('%')
    if zona is not None and not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', zona):
        raise FuenteInvalida()
    if direccion == '*':
        if corchetes or zona is not None:
            raise FuenteInvalida()
        direccion_normalizada = None
        tipo = 'comodin'
    else:
        try:
            ip = ipaddress.ip_address(direccion)
        except ValueError:
            raise FuenteInvalida() from None
        if ip.version != (4 if familia == 'ipv4' else 6) or (corchetes and ip.version != 6):
            raise FuenteInvalida()
        direccion_normalizada = ip.compressed
        tipo = 'ip'
    return {'direccion': direccion_normalizada, 'tipo_direccion': tipo, 'zona': zona,
            'puerto': numero, 'tipo_puerto': 'comodin' if puerto == '*' else 'numerico'}


def parsear_fuente(texto, protocolo, familia, limite=MAX_REGISTROS_FUENTE):
    if (not isinstance(texto, str) or type(limite) is not int or limite < 0
            or protocolo not in ('tcp', 'udp') or familia not in ('ipv4', 'ipv6')):
        raise FuenteInvalida()
    if not texto.isascii() or any(ord(c) < 32 and c not in '\n\r\t' for c in texto):
        raise FuenteInvalida()
    filas = [linea for linea in texto.splitlines() if linea.strip()]
    if len(filas) > limite:
        raise FuenteInvalida('limite_registros')
    registros = []
    permitidos = ESTADOS_TCP if protocolo == 'tcp' else ESTADOS_UDP
    for fila in filas:
        campos = fila.split()
        if len(campos) != 5 or campos[0] not in permitidos:
            raise FuenteInvalida()
        estado, rx, tx, local, remoto = campos
        registros.append({'protocolo': protocolo, 'familia': familia, 'estado': estado,
                          'cola_recepcion': _entero(rx, 2**64-1),
                          'cola_envio': _entero(tx, 2**64-1),
                          'local': extremo(local, familia), 'remoto': extremo(remoto, familia),
                          'procesos': {'estado': 'no_solicitados', 'valores': None}})
    return registros


def normalizar_conexiones(fuentes):
    registros, metadatos, recuentos, incidencias = [], {}, {}, []
    utilizables = 0
    for nombre, protocolo, familia, _ in FUENTES:
        fuente = fuentes[nombre]
        estado = fuente['estado'] if fuente['estado'] in ESTADOS_FUENTE else 'error_sistema'
        bloque = None
        if estado == 'correcta':
            try:
                bloque = parsear_fuente(fuente.get('stdout', ''), protocolo, familia)
            except FuenteInvalida as error:
                estado = error.codigo
        metadatos[nombre] = {'estado': estado, 'codigo': fuente.get('codigo'),
                             'protocolo': protocolo, 'familia': familia}
        if bloque is None:
            recuentos[nombre] = None
            incidencias.append({'fase': 'adquisicion', 'codigo': estado, 'fuente': nombre,
                                 'detalle': 'Fuente descartada; su recuento es desconocido, no cero.'})
            continue
        utilizables += 1
        estados = {}
        for indice, registro in enumerate(bloque, 1):
            registro.update(fuente=nombre, id=f'{nombre}-{indice}')
            registros.append(registro)  # No se deduplican extremos: pueden ser sockets distintos.
            estados[registro['estado']] = estados.get(registro['estado'], 0) + 1
        recuentos[nombre] = {'total': len(bloque), 'por_estado': estados}
    estado = 'completo' if utilizables == len(FUENTES) else ('parcial' if utilizables else 'error')
    return ResultadoVerificado({
        'version': 1, 'herramienta': 'conexiones', 'estado_adquisicion': estado,
        'estado_presentacion': 'pendiente', 'fuentes': metadatos,
        'datos': {'registros': registros, 'recuentos_por_fuente': recuentos,
                  'total_registros': len(registros) if utilizables == len(FUENTES) else None},
        'incidencias': incidencias,
        'alcance': {'protocolos': ['tcp', 'udp'], 'familias': ['ipv4', 'ipv6'],
                    'unidad_conteo': 'registros_de_sockets', 'consultas': 'secuenciales_no_atomicas',
                    'espacio_red': 'visible_al_proceso', 'procesos': 'no_solicitados',
                    'conectividad': 'no_comprobada', 'dns': 'no_solicitado',
                    'limite_registros_por_fuente': MAX_REGISTROS_FUENTE,
                    'limite_registros_visibles': MAX_REGISTROS_VISIBLES,
                    'extremos_internos': 'sensibles_no_exportar_automaticamente',
                    'presentacion': 'sin_direcciones_ip_zonas_ni_extremos_remotos'},
    })


def _local_visible(local):
    if local['tipo_direccion'] == 'comodin':
        direccion = 'comodín'
    else:
        ip = ipaddress.ip_address(local['direccion'])
        direccion = 'comodín' if ip.is_unspecified else ('loopback' if ip.is_loopback else 'dirección local oculta')
    puerto = '*' if local['tipo_puerto'] == 'comodin' else str(local['puerto'])
    return f'{direccion}; puerto={puerto}'


def informe_conexiones(resultado, limite=18000):
    d = resultado.a_dict()
    estado = d['estado_adquisicion']
    datos = d['datos']
    lineas = ['Informe determinista de conexiones — generado por Python', f'Adquisición: {estado}.',
              'Unidad: registros de sockets observados, no clientes ni conexiones lógicas únicas.']
    for nombre, protocolo, _, _ in FUENTES:
        fuente = d['fuentes'][nombre]
        conteo = datos['recuentos_por_fuente'][nombre]
        if conteo is None:
            lineas.append(f'{nombre}: fuente={fuente["estado"]}; recuento desconocido.')
        elif protocolo == 'tcp':
            estados = conteo['por_estado']
            escucha, establecidos = estados.get('LISTEN', 0), estados.get('ESTAB', 0)
            otros = conteo['total'] - escucha - establecidos
            lineas.append(f'{nombre}: {conteo["total"]} registros; TCP LISTEN={escucha}, ESTAB={establecidos}, otros={otros}.')
        else:
            estados = ', '.join(f'{e}={n}' for e, n in sorted(conteo['por_estado'].items())) or 'sin filas'
            lineas.append(f'{nombre}: {conteo["total"]} registros UDP; estados observados: {estados}.')
    total = datos['total_registros']
    lineas.append('Total de las cuatro fuentes: ' + (str(total) if total is not None else 'desconocido') + '.')
    registros = datos['registros']
    if registros:
        lineas.append(f'Vista breve: {min(len(registros), MAX_REGISTROS_VISIBLES)} de {len(registros)} registros utilizables; extremos remotos ocultos.')
    for registro in registros[:MAX_REGISTROS_VISIBLES]:
        lineas.append(f'{registro["id"]} {registro["protocolo"]}/{registro["familia"]} estado={registro["estado"]}; '
                      f'colas RX={registro["cola_recepcion"]}, TX={registro["cola_envio"]}; '
                      f'local={_local_visible(registro["local"])}; remoto=oculto por privacidad.')
    if len(registros) > MAX_REGISTROS_VISIBLES:
        lineas.append('Presentación parcial: hay más registros de los mostrados; los recuentos conservan su alcance indicado.')
        estado = 'parcial'
    lineas.extend([
        'Procesos: no solicitados; no se atribuyen nombres, servicios ni permisos por su ausencia.',
        'Colas: valores Recv-Q/Send-Q observados; su significado depende del estado, no son una medida de tráfico.',
        'UDP no representa una sesión TCP; sus estados no prueban entrega de datos.',
        'Escucha o dirección comodín no demuestran accesibilidad desde Internet.',
        'Conectividad: no comprobada. No se evalúan seguridad, reputación ni funcionamiento de VPN.',
        'Las consultas son secuenciales y solo cubren el espacio de nombres de red visible al proceso.',
        'Privacidad: no se muestran IP locales/remotas ni zonas IPv6; tampoco puertos remotos. El resultado interno contiene extremos sensibles.',
    ])
    texto = '\n'.join(lineas)
    if len(texto) > limite:
        texto = 'Informe de sockets omitido por límite de tamaño; no permite concluir ausencia de conexiones.'
        estado = 'omitido_por_limite'
    if len(texto) > limite:
        raise ValueError('No cabe el aviso de informe omitido.')
    return texto, resultado.con_presentacion(estado)
