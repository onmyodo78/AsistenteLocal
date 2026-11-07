"""Generación y reconstrucción semántica de tres representaciones, solo en memoria."""
import builtins
import copy
import csv
import io
import json
import re
import unittest
from unittest.mock import patch

import exportacion_generadores as g
import informe_exportacion as e
import historial_contratos as h
from test_informe_exportacion import informe, memoria, FECHA
from test_historial_contratos import debian, apt_error, fedora_error

ENTEROS = {'version_representacion', 'version_formato', 'version_privacidad', 'version_catalogo',
           'resultado_orden', 'version_contrato_origen', 'version_origen', 'version_adaptador',
           'version_metricas', 'version_privacidad_origen'}


def convertir(fila):
    d = dict(fila)
    for k,v in d.items():
        if v in ('', 'null'):
            d[k] = None
        elif k in ENTEROS:
            d[k] = int(v)
    if d['valor'] is not None:
        d['valor'] = int(d['valor']) if d['tipo'] == 'entero' else {'true': True, 'false': False}[d['valor']]
    return d


def leer_csv(datos):
    return [convertir(f) for f in csv.DictReader(io.StringIO(datos.decode('utf-8-sig'), newline=''))]


def leer_md(datos):
    lineas = datos.decode('utf-8').splitlines()
    filas = []
    base = None
    tipo = None
    cabecera = None
    def celdas(linea):
        campos = re.split(r'(?<!\\)\|', linea)[1:-1]
        return [re.sub(r'\\(.)', r'\1', c.strip()) for c in campos]
    for linea in lineas:
        if linea.startswith('## Resultado '):
            base = {}
        elif linea == '### Versiones, fechas y estados':
            tipo = 'resultado'
        elif linea.startswith('### '):
            tipo = next(t for t,titulo,_ in g.GRUPOS if linea == '### '+titulo)
        elif linea.startswith('| '):
            campos = celdas(linea)
            if campos[0] in ('campo', 'componente', 'metrica', 'codigo'):
                cabecera = campos
            elif set(campos) == {'---'}:
                continue
            elif base is not None:
                if tipo == 'resultado':
                    base[campos[0]] = campos[1]
                    if len(base) == len(g.BASE):
                        f = {k: '' for k in g.COLUMNAS}
                        f.update(base, tipo_fila='resultado')
                        filas.append(convertir(f))
                else:
                    f = {k: '' for k in g.COLUMNAS}
                    f.update(base, tipo_fila=tipo)
                    f.update(zip(cabecera, campos))
                    filas.append(convertir(f))
    return filas


class Generadores(unittest.TestCase):
    def completo(self):
        m = memoria()
        m['metricas']['ram_libre_bytes'] = None
        del m['metricas']['swap_ocupada_bytes']
        d = debian(2)
        d.update(estado_inventario='completo', estado_adquisicion='parcial', actualizaciones=apt_error())
        f = h.adaptar_auditoria(fedora_error(), 'fedora')
        f['metricas']['reinicio_pendiente_kernel'] = False
        return informe([m, h.adaptar_auditoria(d, 'debian13'), f,
                        h.estado_conocido('disco', 'debian13', 'no_ejecutado')])

    def test_equivalencia_completa_tres_formatos(self):
        d = self.completo()
        filas = g.proyectar_hechos(d)['filas']
        self.assertEqual(json.loads(g.generar_json(d))['filas'], filas)
        self.assertEqual(leer_csv(g.generar_csv(d)), filas)
        self.assertEqual(leer_md(g.generar_markdown(d)), filas)

    def test_json_utf8_versiones_y_tipos_nativos(self):
        d = self.completo()
        datos = g.generar_json(d)
        self.assertIn('Estimación'.encode(), datos)
        p = json.loads(datos)
        self.assertEqual(p['version_representacion'], 1)
        self.assertEqual(p['columnas'], list(g.COLUMNAS))
        valores = [f['valor'] for f in p['filas'] if f['tipo_fila'] == 'metrica']
        self.assertTrue(any(type(v) is int for v in valores))
        self.assertTrue(any(v is None for v in valores))
        self.assertTrue(any(type(v) is bool for v in valores))

    def test_csv_bom_crlf_columnas_estables(self):
        datos = g.generar_csv(informe())
        self.assertTrue(datos.startswith(b'\xef\xbb\xbf'))
        self.assertNotIn(b'\n', datos.replace(b'\r\n', b''))
        self.assertEqual(next(csv.reader(io.StringIO(datos.decode('utf-8-sig')))), list(g.COLUMNAS))

    def test_desconocidos_no_recogidos_cero_y_booleanos(self):
        filas = leer_csv(g.generar_csv(self.completo()))
        estados = {f['estado_valor'] for f in filas if f['tipo_fila'] == 'metrica'}
        self.assertEqual(estados, {'conocido', 'desconocido', 'no_recogida'})
        for f in filas:
            if f['tipo_fila'] == 'metrica' and f['estado_valor'] != 'conocido':
                self.assertIsNone(f['valor'])
        self.assertTrue(any(f['valor'] is False for f in filas))
        self.assertTrue(any(type(f['valor']) is int and f['valor'] == 0 for f in filas))

    def test_componentes_independientes(self):
        filas = leer_md(g.generar_markdown(self.completo()))
        componentes = {f['componente']: f for f in filas if f['tipo_fila'] == 'componente'}
        self.assertEqual(componentes['apt']['componente_ejecucion'], 'error')
        self.assertEqual(componentes['dpkg']['componente_ejecucion'], 'correcto')
        self.assertEqual(componentes['apt']['componente_cobertura'], 'no_verificada')

    def test_resultado_sin_metricas_y_fechas_ausentes(self):
        d = informe([h.estado_conocido('disco', 'fedora', 'no_verificado')])
        for filas in (json.loads(g.generar_json(d))['filas'], leer_csv(g.generar_csv(d)), leer_md(g.generar_markdown(d))):
            self.assertEqual(sum(f['tipo_fila'] == 'resultado' for f in filas), 1)
            self.assertFalse(any(f['tipo_fila'] == 'metrica' for f in filas))
            self.assertTrue(all(f['fecha_observacion_utc'] is None for f in filas))
            self.assertTrue(any(f['codigo'] == 'sin_metricas_estructuradas_para_resultado' for f in filas))

    def test_fechas_disponibles_en_tres_formatos(self):
        obs = '2026-11-05T11:00:00Z'
        d = informe(observaciones=[dict(fecha_utc=obs, verificada=True)])
        for filas in (json.loads(g.generar_json(d))['filas'], leer_csv(g.generar_csv(d)), leer_md(g.generar_markdown(d))):
            self.assertTrue(all(f['fecha_observacion_utc'] == obs for f in filas))
            self.assertTrue(all(f['fecha_preparacion_utc'] == FECHA for f in filas))

    def test_orden_determinista_y_no_mutacion(self):
        d = self.completo()
        antes = copy.deepcopy(d)
        for generador in (g.generar_json, g.generar_csv, g.generar_markdown):
            self.assertEqual(generador(d), generador(d))
        self.assertEqual(d, antes)

    def test_formulas_csv_rechazadas_sin_formulas_para_enteros(self):
        for texto in ('=1+1', '+SUM(A1)', '-1+1', '@SUM(A1)', '  =1', '\t=1', '\r=1', '\n=1'):
            with self.assertRaises(g.ErrorGenerador):
                g._csv_celda(texto)
        self.assertEqual(g._csv_celda(2**63-1), '9223372036854775807')
        r = memoria()
        r['metricas']['ram_total_bytes'] = 2**63-1
        datos = g.generar_csv(informe([r]))
        self.assertIn(b'9223372036854775807', datos)
        self.assertNotIn(b'="', datos)

    def test_escape_markdown_sin_html_ni_enlaces(self):
        texto = '<script>&[enlace](destino)|`codigo`_x_*y*'
        escapado = g._markdown_celda(texto)
        for simbolo in ('<', '>', '&', '[', ']', '(', ')', '|', '`', '_', '*'):
            self.assertIn('\\'+simbolo, escapado)
        with self.assertRaises(g.ErrorGenerador):
            g._markdown_celda('linea\notra')

    def test_datos_privados_o_peligrosos_no_entran_en_generadores(self):
        for cambiar in (lambda d: d.update(hostname='privado'),
                        lambda d: d['resultados'][0].update(stdout='/privado'),
                        lambda d: d['resultados'][0]['metricas'][0].update(valor='=1'),
                        lambda d: d['resultados'][0]['metricas'][0].update(significado='<script>')):
            d = informe()
            cambiar(d)
            for generador in (g.generar_json, g.generar_csv, g.generar_markdown):
                with self.assertRaises(e.ErrorInforme):
                    generador(d)

    def test_limites_cada_representacion_sin_truncar(self):
        d = informe()
        with patch.object(g, 'MAX_REPRESENTACION_BYTES', 10):
            for generador in (g.generar_json, g.generar_csv, g.generar_markdown):
                with self.assertRaisesRegex(g.ErrorGenerador, '^limite_representacion$'):
                    generador(d)
        with patch.object(e, 'MAX_INFORME_BYTES', 10):
            for generador in (g.generar_json, g.generar_csv, g.generar_markdown):
                with self.assertRaises(e.ErrorInforme):
                    generador(d)

    def test_no_finitos_rechazados_antes_generar(self):
        for valor in (float('nan'), float('inf')):
            d = informe()
            d['resultados'][0]['metricas'][0]['valor'] = valor
            for generador in (g.generar_json, g.generar_csv, g.generar_markdown):
                with self.assertRaises(e.ErrorInforme):
                    generador(d)

    def test_atajo_preparacion_y_formato_explicito(self):
        for formato, generador in (('json', g.generar_json), ('csv', g.generar_csv), ('markdown', g.generar_markdown)):
            self.assertEqual(g.generar_desde_registros([memoria()], formato, fecha_preparacion_utc=FECHA), generador(informe()))
        with self.assertRaises(g.ErrorGenerador):
            g.generar_desde_registros([memoria()], 'xlsx', fecha_preparacion_utc=FECHA)

    def test_no_escrituras_adquisiciones_ni_imports_sqlite(self):
        d = informe()
        importar = builtins.__import__
        def prohibir(nombre, *args, **kw):
            if 'sqlite' in nombre or nombre in ('historial_controlador', 'historial_persistente'):
                raise AssertionError('dependencia no permitida')
            return importar(nombre, *args, **kw)
        with patch('builtins.__import__', side_effect=prohibir), \
             patch('builtins.open', side_effect=AssertionError('archivo')), \
             patch('os.mkdir', side_effect=AssertionError('directorio')), \
             patch('subprocess.Popen', side_effect=AssertionError('adquisicion')):
            for generador in (g.generar_json, g.generar_csv, g.generar_markdown):
                self.assertIs(type(generador(d)), bytes)
