"""Contrato de exportación: fixtures y datos en memoria, sin generadores ni E/S."""
import copy
import json
import unittest
from unittest.mock import patch

import historial_contratos as h
import informe_exportacion as e
from test_historial_contratos import debian, apt_error, fedora_error
from resultado_verificado import adaptar_memoria
from test_memoria_verificada import normalizar

FECHA = '2026-11-05T12:00:00Z'


def memoria():
    return h.adaptar_verificado(adaptar_memoria(normalizar()), 'debian13')


def informe(registros=None, **kw):
    return e.preparar_informe([memoria()] if registros is None else registros,
        fecha_preparacion_utc=FECHA, **kw)


class InformeExportacion(unittest.TestCase):
    def test_contrato_versionado_y_copia_validada(self):
        d = informe()
        self.assertEqual(d['formato'], 'informe_exportacion_v1')
        self.assertEqual(d['version_catalogo'], 1)
        self.assertEqual(d['version_privacidad'], 1)
        self.assertEqual(e.validar_informe(d), d)
        copia = e.validar_informe(d)
        copia['resultados'].clear()
        self.assertEqual(len(d['resultados']), 1)

    def test_catalogo_cerrado_completo_tipos_unidades(self):
        catalogo = e.catalogo_metricas()
        self.assertEqual({c['identificador'] for c in catalogo}, set().union(*[set(m) for m in h.METRICAS.values()]))
        for c in catalogo:
            self.assertIn(c['tipo'], ('entero', 'booleano'))
            self.assertIn(c['unidad'], ('byte', 'paquete', 'aviso', 'registro_socket', 'unidad_service', 'interfaz', 'indicador'))
            self.assertTrue(c['significado'])
        catalogo[0]['unidad'] = 'privado'
        self.assertNotIn('privado', [c['unidad'] for c in e.catalogo_metricas()])

    def test_conocido_desconocido_y_no_recogida(self):
        r = memoria()
        r['metricas']['ram_libre_bytes'] = None
        del r['metricas']['swap_ocupada_bytes']
        d = informe([r])
        valores = {m['identificador']:m for m in d['resultados'][0]['metricas']}
        self.assertEqual(valores['ram_total_bytes']['estado_valor'], 'conocido')
        self.assertEqual(valores['ram_libre_bytes']['estado_valor'], 'desconocido')
        self.assertIsNone(valores['ram_libre_bytes']['valor'])
        self.assertEqual(valores['swap_ocupada_bytes']['estado_valor'], 'no_recogida')
        self.assertIsNone(valores['swap_ocupada_bytes']['valor'])
        self.assertEqual(e.validar_informe(d), d)

    def test_cero_y_booleano_no_son_desconocidos(self):
        r = h.adaptar_auditoria(fedora_error(), 'fedora')
        r['metricas']['reinicio_pendiente_kernel'] = False
        d = informe([r])
        valores = {m['identificador']:m for m in d['resultados'][0]['metricas']}
        self.assertEqual(valores['reinicio_pendiente_kernel']['estado_valor'], 'conocido')
        self.assertIs(valores['reinicio_pendiente_kernel']['valor'], False)
        self.assertEqual(valores['paquetes_rpm_recogidos']['valor'], 0)
        self.assertEqual(valores['paquetes_rpm']['estado_valor'], 'desconocido')

    def test_preserva_estados_procedencia_versiones(self):
        r = memoria()
        r.update(ejecucion='parcial', calidad='parcial', cobertura='parcial')
        d = informe([r])['resultados'][0]
        for k in ('ejecucion', 'calidad', 'cobertura', 'procedencia', 'version', 'version_origen', 'version_adaptador', 'version_metricas'):
            self.assertEqual(d['origen'][k], r[k])

    def test_fechas_diferenciadas_y_no_inventadas(self):
        d = informe()
        self.assertIsNone(d['resultados'][0]['fecha_observacion_utc'])
        self.assertIn('fecha_observacion_no_disponible', d['resultados'][0]['omisiones'])
        obs = dict(fecha_utc='2026-11-05T11:00:00Z', verificada=True)
        d = informe(observaciones=[obs])
        self.assertNotEqual(d['fecha_preparacion_utc'], d['resultados'][0]['fecha_observacion_utc'])
        self.assertEqual(e.validar_informe(d), d)
        for mala in (dict(obs, verificada=False), dict(obs, verificada=1), dict(obs, ruta='/privado'),
                     dict(obs, fecha_utc='2026-11-05T13:00:00Z'), dict(obs, fecha_utc='ayer')):
            with self.assertRaises(e.ErrorInforme):
                informe(observaciones=[mala])

    def test_sin_adaptador_no_se_confunde_con_error(self):
        sin = h.estado_conocido('disco', 'debian13', 'correcto')
        fallido = memoria()
        fallido.update(ejecucion='error', calidad='no_disponible')
        d = informe([sin, fallido])
        disco, ram = d['resultados']
        self.assertEqual(disco['soporte_metricas'], 'sin_adaptador_estructurado')
        self.assertEqual(disco['representacion'], 'solo_estado_declarado')
        self.assertEqual(disco['origen']['ejecucion'], 'correcto')
        self.assertEqual(ram['soporte_metricas'], 'adaptador_disponible')
        self.assertEqual(ram['origen']['ejecucion'], 'error')

    def test_separacion_dpkg_apt_y_cobertura(self):
        d = debian(2)
        d.update(estado_adquisicion='parcial', estado_inventario='completo', actualizaciones=apt_error())
        r = informe([h.adaptar_auditoria(d, 'debian13')])['resultados'][0]
        componentes = {c['identificador']:c for c in r['componentes']}
        self.assertEqual(componentes['dpkg']['ejecucion'], 'correcto')
        self.assertEqual(componentes['apt']['ejecucion'], 'error')
        self.assertEqual(r['origen']['cobertura'], 'no_verificada')
        m = {m['identificador']:m for m in r['metricas']}
        self.assertEqual(m['apt_total_posibles']['estado_valor'], 'desconocido')
        self.assertEqual(m['dpkg_total_instalados']['valor'], 3078)
        self.assertIn('dpkg_no_es_auditoria_cve', r['limitaciones'])

    def test_omisiones_y_limitaciones_cerradas(self):
        r = informe()['resultados'][0]
        self.assertIn('ejecucion_no_acredita_seguridad', r['limitaciones'])
        self.assertIn('identidades_excluidas', r['omisiones'])
        for campo in ('omisiones', 'limitaciones'):
            d = informe()
            d['resultados'][0][campo].append('texto privado')
            with self.assertRaises(e.ErrorInforme):
                e.validar_informe(d)

    def test_orden_determinista_con_repeticiones_y_fechas(self):
        r1, r2 = memoria(), h.estado_conocido('sistema', 'fedora', 'no_ejecutado')
        a = informe([r2, r1, r1])
        b = informe([r1, r2, r1])
        self.assertEqual(a, b)
        self.assertEqual([r['orden'] for r in a['resultados']], [0,1,2])
        self.assertEqual([m['identificador'] for m in a['resultados'][0]['metricas']], sorted(h.MEMORIA))
        self.assertEqual(e.validar_informe(a), a)

    def test_privacidad_y_claves_arbitrarias(self):
        for campo in ('usuario', 'hostname', 'ip', 'mac', 'ruta', 'procesos', 'paquetes', 'servicios', 'documentos', 'stdout', 'respuesta_lmstudio'):
            r = memoria()
            r[campo] = 'privado'
            with self.assertRaisesRegex(e.ErrorInforme, '^informe_exportacion_invalido$'):
                informe([r])
            d = informe()
            d['resultados'][0][campo] = 'privado'
            with self.assertRaises(e.ErrorInforme):
                e.validar_informe(d)

    def test_tipos_versiones_y_no_finitos(self):
        for valor in (True, -1, 1.2, float('nan'), float('inf'), '12', 2**63):
            r = memoria()
            r['metricas']['ram_total_bytes'] = valor
            with self.assertRaises(e.ErrorInforme):
                informe([r])
        for campo in ('version_formato', 'version_privacidad', 'version_catalogo'):
            for valor in (True, 2, '1'):
                d = informe()
                d[campo] = valor
                with self.assertRaises(e.ErrorInforme):
                    e.validar_informe(d)

    def test_unidades_significados_y_estados_no_se_pueden_alterar(self):
        for campo, valor in (('tipo', 'texto'), ('unidad', 'MB'), ('significado', 'seguro'),
                             ('estado_valor', 'desconocido'), ('identificador', 'privado')):
            d = informe()
            d['resultados'][0]['metricas'][0][campo] = valor
            with self.assertRaises(e.ErrorInforme):
                e.validar_informe(d)

    def test_metricas_backend_incompatible_rechazadas(self):
        r = h.adaptar_auditoria(fedora_error(), 'fedora')
        r['metricas']['dpkg_instalados'] = 1
        with self.assertRaises(e.ErrorInforme):
            informe([r])

    def test_limites_sin_truncamiento(self):
        with self.assertRaises(e.ErrorInforme):
            informe([])
        with self.assertRaises(e.ErrorInforme):
            informe([memoria()]*(e.MAX_RESULTADOS+1))
        for limite in ('MAX_INFORME_BYTES', 'MAX_NODOS', 'MAX_PROFUNDIDAD'):
            with patch.object(e, limite, 1):
                with self.assertRaises(e.ErrorInforme):
                    informe()
        with self.assertRaises(e.ErrorInforme):
            informe(observaciones=[])

    def test_no_mutacion_de_entradas_ni_e_s(self):
        r = memoria()
        antes = copy.deepcopy(r)
        with patch('builtins.open', side_effect=AssertionError('archivo')), \
             patch('os.mkdir', side_effect=AssertionError('directorio')), \
             patch('subprocess.Popen', side_effect=AssertionError('adquisicion')):
            d = informe([r])
            e.validar_informe(d)
        self.assertEqual(r, antes)
        self.assertNotIn('sqlite', json.dumps(d).lower())
