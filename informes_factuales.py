"""Informes puros de Python: sin modelo, comandos, red ni estado de sesión.

Los informes Debian proyectan únicamente estados cerrados y recuentos válidos.
No incorporan texto libre de resultados, preguntas ni respuestas del modelo.
"""
import json


def resumen_factual_debian(datos):
    """Solo estados cerrados y recuentos: sin filas, versiones ni procedencias."""
    datos = datos if type(datos) is dict else {}

    def numero(valor):
        return str(valor) if type(valor) is int and 0 <= valor <= 2**63-1 else 'desconocido'

    inventario = datos.get('estado_inventario', datos.get('estado_adquisicion'))
    inventario = inventario if type(inventario) is str else None
    etiquetas_dpkg = {'completo': 'completo', 'parcial': 'parcial', 'error': 'fallido'}
    apt = datos.get('actualizaciones')
    apt = apt if type(apt) is dict else {}
    estado_apt = apt.get('estado_adquisicion')
    estado_apt = estado_apt if type(estado_apt) is str else None
    etiquetas_apt = {'completo': 'completa', 'parcial': 'parcial', 'error': 'fallida'}
    total_dpkg = datos.get('total_instalados') if inventario == 'completo' else None
    total_apt = apt.get('total_posibles') if inventario == estado_apt == 'completo' else None
    lineas = [
        'Hechos de auditoría Debian (calculados por Python):',
        'Inventario dpkg: ' + etiquetas_dpkg.get(inventario, 'desconocido') +
            '. Total de paquetes instalados: ' + numero(total_dpkg) + '.',
        'Adquisición APT: ' + etiquetas_apt.get(estado_apt, 'no disponible') +
            '. Total de posibles actualizaciones: ' + numero(total_apt) + '.',
    ]
    if numero(total_apt) == 'desconocido':
        lineas.append('Las candidatas desconocidas no permiten confirmar ausencia de actualizaciones.')
    else:
        lineas.append('Recuento según índices locales; frescura no verificada e instalabilidad no comprobada.')
    for nombre, fuente in (('dpkg', datos.get('fuente')), ('APT', apt)):
        if type(fuente) is dict and fuente.get('motivo') in ('terminacion_no_confirmada', 'error_recogida'):
            lineas.append('No se ha confirmado la recogida o el cierre del proceso ' + nombre + '.')
    lineas.append('Simulación APT: no realizada; no hay un plan de actualización confirmado.')
    lineas.append('Correlación CVE Debian: no_implementado; comprobación no realizada.')
    lineas.append('Seguridad: no evaluada; no se puede confirmar ausencia de vulnerabilidades.')
    return '\n'.join(lineas)


def informe_correlacion_debian(resultado):
    try:
        dato = json.loads(resultado)
    except (ValueError, TypeError):
        dato = {}
    if (type(dato) is dict and dato.get('estado') == 'no_implementado'
            and dato.get('estado_adquisicion') == 'no_realizada'):
        return ('Correlación Debian: no_implementado. Comprobación no realizada. '
                'Seguridad no evaluada; no permite confirmar ausencia de vulnerabilidades.')
    return 'Comprobación no realizada o resultado no verificable. Seguridad no evaluada.'


def informe_fallo_adquisicion():
    return ('Comprobación no realizada: adquisición fallida o tiempo agotado. '
            'No se reintenta. Seguridad no evaluada.')


def informe_plan(d):
    lineas = ['INFORME FACTUAL DE PYTHON — solo lectura',
        f"Distribución: {d['distribucion']}; gestor: {d['gestor']}; estado: {d['estado']}",
        'Actualizaciones candidatas: ' + d['candidatas']['estado'],
        'Simulación del resolvedor: ' + d['simulacion']['estado']]
    lineas.append('Capacidades detectadas: ' + '; '.join(
        k + '=' + ('sí' if v else 'no') for k, v in sorted(d['capacidades'].items())))
    for titulo, filas in [('Candidatas (no son una transacción)', d['candidatas']['paquetes']),
        ('Actualizaciones previstas', d['simulacion']['actualizaciones']),
        ('Instalaciones adicionales', d['simulacion']['instalaciones']),
        ('Eliminaciones previstas', d['simulacion']['eliminaciones']),
        ('Retenciones explícitas', d['simulacion']['retenciones'])]:
        lineas.append(titulo + f' ({len(filas)} filas):')
        lineas.extend(f"  {p['nombre']}:{p['arquitectura'] or 'desconocida'} {p['anterior'] or 'no comprobada'} -> {p['propuesta'] or 'no propuesta'}" for p in filas)
        if not filas:
            lineas.append('  Sin filas; interpretar según estado y limitaciones.')
    lineas.append('Retenciones: ' + d['simulacion']['retenciones_estado'])
    lineas.append('Total no actualizado según resolvedor: ' + ('desconocido' if d['simulacion']['no_actualizados_total'] is None else str(d['simulacion']['no_actualizados_total'])))
    lineas.append('Comparación candidatas/resolvedor: ' + d['comparacion']['estado'])
    for p in d['comparacion']['no_previstas']:
        lineas.append(f"  Candidata no prevista: {p['nombre']}:{p['arquitectura']} -> {p['propuesta']}")
    for c in ('candidatas','simulacion'):
        lineas.extend('Error ' + c + ': ' + e for e in d[c]['errores'])
    lineas.extend('Limitación: ' + x for x in d['limitaciones'])
    ejecucion = ('Ejecución real: no autorizada por este plan; requiere el ejecutor APT separado.'
                 if d['gestor']=='apt' else 'Ejecución real: no implementada y no autorizada.')
    lineas.extend([ejecucion, 'Huella: ' + d['huella']])
    return '\n'.join(lineas)
