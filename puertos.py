"""Vista pura de TCP LISTEN y UDP sobre una instantánea de conexiones.

El extremo local interno es sensible. No adquiere datos ni resuelve nombres.
"""
import ipaddress

from conexiones import FUENTES, MAX_REGISTROS_VISIBLES
from resultado_verificado import ResultadoVerificado


def derivar_puertos(resultado_conexiones):
    d = resultado_conexiones.a_dict()
    if d['herramienta'] != 'conexiones':
        raise ValueError('Se esperaba una instantánea de conexiones.')
    registros = []
    recuentos = {}
    for nombre, protocolo, _, _ in FUENTES:
        origen = d['datos']['recuentos_por_fuente'][nombre]
        if origen is None:
            recuentos[nombre] = None
            continue
        seleccionados = [r for r in d['datos']['registros'] if r['fuente'] == nombre
                         and (protocolo == 'udp' or r['estado'] == 'LISTEN')]
        estados = {}
        for r in seleccionados:
            registros.append({k: r[k] for k in
                              ('id', 'fuente', 'protocolo', 'familia', 'estado', 'local')})
            estados[r['estado']] = estados.get(r['estado'], 0) + 1
        recuentos[nombre] = {'total': len(seleccionados), 'por_estado': estados,
                             'excluidos': origen['total'] - len(seleccionados)}
    return ResultadoVerificado({
        'version': 1, 'herramienta': 'puertos',
        'estado_adquisicion': d['estado_adquisicion'], 'estado_presentacion': 'pendiente',
        'fuentes': d['fuentes'],
        'datos': {'registros': registros, 'recuentos_por_fuente': recuentos,
                  'recuentos_origen_por_fuente': d['datos']['recuentos_por_fuente'],
                  'total_registros': len(registros) if all(v is not None for v in recuentos.values()) else None},
        # Solo se heredan incidencias de adquisición del normalizador seguro.
        'incidencias': [i for i in d['incidencias'] if i['fase'] == 'adquisicion'],
        'alcance': {**d['alcance'], 'origen': 'conexiones',
                    'seleccion': 'tcp_LISTEN_y_todos_los_udp_validos',
                    'extremos_internos': 'locales_sensibles_no_exportar_automaticamente',
                    'presentacion': 'puertos_locales_sin_ip_ni_calificadores'},
    })


def _local_visible(local):
    if local['tipo_direccion'] == 'comodin':
        categoria = 'comodín'
    else:
        ip = ipaddress.ip_address(local['direccion'])
        categoria = 'comodín' if ip.is_unspecified else ('loopback' if ip.is_loopback else 'dirección local oculta')
    puerto = '*' if local['tipo_puerto'] == 'comodin' else str(local['puerto'])
    return f'{categoria}; puerto={puerto}'


def informe_puertos(resultado, limite=18000):
    d = resultado.a_dict()
    if d['herramienta'] != 'puertos':
        raise ValueError('Se esperaba una instantánea de puertos.')
    estado = d['estado_adquisicion']
    datos = d['datos']
    lineas = ['Informe determinista de puertos — generado por Python',
              f'Adquisición: {estado}.',
              'Unidad: registros de sockets observados; un número de puerto puede aparecer en varios registros.',
              'Selección: TCP LISTEN y todos los registros UDP válidos de la misma adquisición de conexiones.']
    for nombre, protocolo, _, _ in FUENTES:
        conteo = datos['recuentos_por_fuente'][nombre]
        if conteo is None:
            lineas.append(f'{nombre}: fuente={d["fuentes"][nombre]["estado"]}; recuento desconocido.')
        else:
            estados = ', '.join(f'{e}={n}' for e, n in sorted(conteo['por_estado'].items())) or 'sin filas seleccionadas'
            lineas.append(f'{nombre}: {conteo["total"]} registros seleccionados; {estados}; excluidos={conteo["excluidos"]}.')
    total = datos['total_registros']
    lineas.append('Total seleccionado de las cuatro fuentes: ' + (str(total) if total is not None else 'desconocido') + '.')
    registros = datos['registros']
    if registros:
        lineas.append(f'Vista breve: {min(len(registros), MAX_REGISTROS_VISIBLES)} de {len(registros)} registros seleccionados utilizables.')
    for r in registros[:MAX_REGISTROS_VISIBLES]:
        lineas.append(f'{r["id"]} {r["protocolo"]}/{r["familia"]} estado={r["estado"]}; local={_local_visible(r["local"])}.')
    if len(registros) > MAX_REGISTROS_VISIBLES:
        lineas.append('Presentación parcial: hay más registros seleccionados; los recuentos conservan su alcance indicado.')
        estado = 'parcial'
    lineas.extend([
        'TCP LISTEN indica escucha observada. UDP UNCONN indica ausencia de par conectado; UDP ESTAB indica un par conectado, no una sesión TCP ni entrega comprobada.',
        'Procesos: no solicitados. No se atribuyen servicios por el número de puerto.',
        'Conectividad: no comprobada. No se determina apertura del cortafuegos, publicación en Internet ni accesibilidad desde otra máquina.',
        'Comodín no demuestra accesibilidad externa; IPv6 no implica cobertura IPv4.',
        'Consultas secuenciales, no atómicas, en el espacio de nombres de red visible al proceso.',
        'Se heredan los límites de conexiones: el exceso de registros TCP excluidos también puede invalidar una fuente completa.',
        'Privacidad: se muestran puertos locales; se ocultan IP y calificadores. El resultado interno contiene extremos locales sensibles y no se exporta automáticamente.',
    ])
    texto = '\n'.join(lineas)
    if len(texto) > limite:
        texto = 'Informe de puertos omitido por límite de tamaño; no permite concluir ausencia de sockets.'
        estado = 'omitido_por_limite'
    if len(texto) > limite:
        raise ValueError('No cabe el aviso de informe omitido.')
    return texto, resultado.con_presentacion(estado)
