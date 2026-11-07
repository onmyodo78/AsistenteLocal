"""Representaciones puras en bytes: sin archivos, SQLite, reloj ni adquisiciones.

CSV: coma, UTF-8 BOM, CRLF; vacíos significan null. 'valor' se interpreta según
 tipo/estado_valor. Importar enteros largos como texto en hojas de cálculo.
Markdown: 'null' indica ausencia, 'true'/'false' booleanos; tablas sin HTML.
"""
import csv
import io
import json
import re

from informe_exportacion import validar_informe, catalogo_metricas, preparar_informe

VERSION_REPRESENTACION = 1
MAX_REPRESENTACION_BYTES = 4 * 1024 * 1024
BASE = ('formato_representacion', 'version_representacion', 'formato_informe', 'version_formato', 'version_privacidad', 'version_catalogo',
        'fecha_preparacion_utc', 'resultado_orden', 'herramienta', 'distribucion',
        'procedencia', 'version_contrato_origen', 'version_origen', 'version_adaptador',
        'version_metricas', 'version_privacidad_origen', 'fecha_observacion_utc',
        'ejecucion', 'calidad', 'cobertura', 'representacion', 'soporte_metricas')
ESPECIFICAS = ('tipo_fila', 'componente', 'componente_ejecucion', 'componente_calidad',
              'componente_cobertura', 'metrica', 'tipo', 'unidad', 'significado',
              'estado_valor', 'valor', 'codigo')
COLUMNAS = BASE + ESPECIFICAS
GRUPOS = (
    ('componente', 'Componentes', ('componente', 'componente_ejecucion', 'componente_calidad', 'componente_cobertura')),
    ('metrica', 'Métricas', ('metrica', 'tipo', 'unidad', 'significado', 'estado_valor', 'valor')),
    ('omision', 'Omisiones', ('codigo',)),
    ('limitacion', 'Limitaciones', ('codigo',)),
)


class ErrorGenerador(ValueError):
    pass


def proyectar_hechos(informe):
    """Única proyección cerrada y ordenada utilizada por todos los formatos."""
    d = validar_informe(informe)
    catalogo = {m['identificador']: m for m in catalogo_metricas()}
    filas = []
    for r in d['resultados']:
        o = r['origen']
        base = dict(formato_representacion='informe_representacion_v1',
            version_representacion=VERSION_REPRESENTACION, formato_informe=d['formato'], version_formato=d['version_formato'],
            version_privacidad=d['version_privacidad'], version_catalogo=d['version_catalogo'],
            fecha_preparacion_utc=d['fecha_preparacion_utc'], resultado_orden=r['orden'],
            herramienta=o['herramienta'], distribucion=o['distribucion'], procedencia=o['procedencia'],
            version_contrato_origen=o['version'], version_origen=o['version_origen'],
            version_adaptador=o['version_adaptador'], version_metricas=o['version_metricas'],
            version_privacidad_origen=o['version_privacidad'], fecha_observacion_utc=r['fecha_observacion_utc'],
            ejecucion=o['ejecucion'], calidad=o['calidad'], cobertura=o['cobertura'],
            representacion=r['representacion'], soporte_metricas=r['soporte_metricas'])
        def agregar(**datos):
            fila = {k: None for k in COLUMNAS}
            fila.update(base)
            fila.update(datos)
            filas.append(fila)
        agregar(tipo_fila='resultado')
        for c in r['componentes']:
            agregar(tipo_fila='componente', componente=c['identificador'],
                componente_ejecucion=c['ejecucion'], componente_calidad=c['calidad'], componente_cobertura=c['cobertura'])
        for m in r['metricas']:
            entrada = catalogo[m['identificador']]
            if any(m[k] != entrada[k] for k in ('tipo', 'unidad', 'significado')):
                raise ErrorGenerador('catalogo_incompatible')
            agregar(tipo_fila='metrica', metrica=m['identificador'], tipo=m['tipo'],
                unidad=m['unidad'], significado=m['significado'], estado_valor=m['estado_valor'], valor=m['valor'])
        for campo, tipo in (('omisiones', 'omision'), ('limitaciones', 'limitacion')):
            for codigo in r[campo]:
                agregar(tipo_fila=tipo, codigo=codigo)
    return dict(formato='informe_representacion_v1', version_representacion=VERSION_REPRESENTACION,
                columnas=list(COLUMNAS), filas=filas)


def _limitar(contenido):
    if len(contenido) > MAX_REPRESENTACION_BYTES:
        raise ErrorGenerador('limite_representacion')
    return contenido


def generar_json(informe):
    d = proyectar_hechos(informe)
    return _limitar((json.dumps(d, ensure_ascii=False, allow_nan=False, indent=2)+'\n').encode('utf-8'))


def _csv_celda(v):
    if v is None:
        return ''
    if type(v) is bool:
        return 'true' if v else 'false'
    if type(v) is int:
        return str(v)
    if type(v) is not str or any(ord(c) < 32 or ord(c) == 127 for c in v):
        raise ErrorGenerador('celda_csv_no_admitida')
    # Entrecomillar no evita fórmulas: rechazar texto peligroso, sin alterarlo.
    if v.lstrip().startswith(('=', '+', '-', '@')):
        raise ErrorGenerador('celda_csv_no_admitida')
    return v


def generar_csv(informe):
    d = proyectar_hechos(informe)
    salida = io.StringIO(newline='')
    writer = csv.writer(salida, delimiter=',', lineterminator='\r\n', quoting=csv.QUOTE_MINIMAL)
    writer.writerow([_csv_celda(k) for k in COLUMNAS])
    for fila in d['filas']:
        writer.writerow([_csv_celda(fila[k]) for k in COLUMNAS])
    return _limitar(salida.getvalue().encode('utf-8-sig'))


def _markdown_celda(v):
    if v is None:
        return 'null'
    if type(v) is bool:
        return 'true' if v else 'false'
    if type(v) is int:
        return str(v)
    if type(v) is not str or any(ord(c) < 32 or ord(c) == 127 for c in v):
        raise ErrorGenerador('celda_markdown_no_admitida')
    # Entidades, HTML, enlaces y sintaxis de tabla no se insertan sin escapar.
    return re.sub(r'([\\`*_{}\[\]()#+.!|<>~&=-])', r'\\\1', v)


def _tabla(columnas, filas):
    lineas = ['| '+' | '.join(_markdown_celda(k) for k in columnas)+' |',
              '| '+' | '.join('---' for _ in columnas)+' |']
    lineas += ['| '+' | '.join(_markdown_celda(v) for v in fila)+' |' for fila in filas]
    return lineas


def generar_markdown(informe):
    d = proyectar_hechos(informe)
    lineas = ['# Informe de AsistenteLocal', '',
              '## Formato de representación', '']
    lineas += _tabla(('campo', 'valor'), [('formato', d['formato']),
        ('version_representacion', d['version_representacion'])])
    lineas += ['', 'Los valores null indican ausencia; estado_valor distingue desconocido y no_recogida.', '']
    # Los metadatos incluyen versiones y fechas y aparecen una vez por resultado.
    for resultado in [f for f in d['filas'] if f['tipo_fila'] == 'resultado']:
        orden = resultado['resultado_orden']
        lineas += [f'## Resultado {orden}', '', '### Versiones, fechas y estados', '']
        lineas += _tabla(('campo', 'valor'), [(k, resultado[k]) for k in BASE])
        for tipo, titulo, columnas in GRUPOS:
            filas = [f for f in d['filas'] if f['resultado_orden'] == orden and f['tipo_fila'] == tipo]
            lineas += ['', f'### {titulo}', '']
            lineas += _tabla(columnas, [[f[k] for k in columnas] for f in filas])
        lineas.append('')
    return _limitar(('\n'.join(lineas)+'\n').encode('utf-8'))


def generar_desde_registros(registros, formato, *, fecha_preparacion_utc, observaciones=None):
    """Atajo puro: preparar_informe más el generador seleccionado explícitamente."""
    if type(formato) is not str or formato not in ('json', 'csv', 'markdown'):
        raise ErrorGenerador('formato_no_admitido')
    informe = preparar_informe(registros, fecha_preparacion_utc=fecha_preparacion_utc,
                              observaciones=observaciones)
    return {'json': generar_json, 'csv': generar_csv, 'markdown': generar_markdown}[formato](informe)
