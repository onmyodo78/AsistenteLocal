"""Informes y separación de procedencias; sin APT, procesos ni LM Studio real."""
import contextlib
import copy
import io
import json
import unittest
from unittest.mock import patch

import AsistenteLocal as app
from informes_factuales import resumen_factual_debian, informe_correlacion_debian
from motor_consultas import ContextoFactual
import test_continuacion_auditoria as continuacion
from test_lmstudio_comunicacion import completa
from test_p0 import respuesta, llamada


class Informes(unittest.TestCase):
    def datos(self):
        return continuacion.ContinuacionAuditoria.resultado(self).datos

    def test_recuentos_limitaciones_y_determinismo(self):
        d = self.datos()
        d['actualizaciones']['total_posibles'] = 35
        original = copy.deepcopy(d)
        informe = resumen_factual_debian(d)
        self.assertEqual(informe, resumen_factual_debian(d))
        self.assertEqual(d, original)
        for texto in ('3109', '35', 'frescura no verificada', 'instalabilidad no comprobada',
                      'Simulación APT: no realizada', 'Correlación CVE Debian: no_implementado',
                      'Seguridad: no evaluada'):
            self.assertIn(texto, informe)
        self.assertNotIn('PRIVADO', informe)

    def test_desconocidos_no_son_cero(self):
        for valor in (None, True, -1, 2**64, '35', {'dato': 1}):
            d = self.datos()
            d['total_instalados'] = valor
            d['actualizaciones']['total_posibles'] = valor
            informe = resumen_factual_debian(d)
            self.assertIn('paquetes instalados: desconocido', informe)
            self.assertIn('posibles actualizaciones: desconocido', informe)
        d = self.datos()
        d['estado_inventario'] = 'parcial'
        d['actualizaciones']['total_posibles'] = 35
        self.assertNotIn('actualizaciones: 35', resumen_factual_debian(d))

    def test_campos_libres_no_entran_en_informe(self):
        d = self.datos()
        d.update(limitaciones=['INYECCION'], fuente={'motivo': 'INYECCION'},
                 estado_seguridad='INYECCION')
        self.assertNotIn('INYECCION', resumen_factual_debian(d))
        d['estado_inventario'] = 'INYECCION'
        self.assertNotIn('INYECCION', resumen_factual_debian(d))
        d['estado_inventario'] = []
        d['actualizaciones']['estado_adquisicion'] = {}
        self.assertIn('desconocido', resumen_factual_debian(d))
        for valor in (None, [], 'INYECCION'):
            self.assertIn('desconocido', resumen_factual_debian(valor))

    def test_correlacion_proyecta_estado_sin_json_libre(self):
        texto = json.dumps({'estado': 'no_implementado', 'estado_adquisicion': 'no_realizada',
                            'motivo': 'INYECCION'})
        informe = informe_correlacion_debian(texto)
        self.assertIn('no_implementado', informe)
        self.assertNotIn('INYECCION', informe)
        for invalido in ('{}', '[]', 'error', None):
            self.assertIn('no verificable', informe_correlacion_debian(invalido))


class Separacion(unittest.TestCase):
    def setUp(self):
        self.contexto = ContextoFactual()
        for objeto, nombre in ((app.subprocess, 'Popen'), (app, 'abrir_http_local')):
            barrera = patch.object(objeto, nombre, side_effect=AssertionError('Acceso real'))
            barrera.start()
            self.addCleanup(barrera.stop)
        backend = patch.object(app, 'seleccionar_backend_seguridad',
                               return_value={'backend': 'debian', 'estado': 'parcial'})
        backend.start()
        self.addCleanup(backend.stop)

    def consultar(self, final):
        datos = continuacion.ContinuacionAuditoria.resultado(self)
        with patch.object(app, 'ejecutar_consulta', return_value=datos) as ejecutar, \
             patch.object(app, 'consultar_modelo', side_effect=final if isinstance(final, Exception) else None,
                          return_value=final), contextlib.redirect_stdout(io.StringIO()) as salida:
            app.preguntar('auditoria_seguridad', contexto=self.contexto)
        ejecutar.assert_called_once()
        return salida.getvalue()

    def factual(self, texto):
        return texto.split('=== INFORME FACTUAL DE PYTHON ===\n', 1)[1].split(
            '\n=== FIN DEL INFORME FACTUAL ===', 1)[0]

    def test_contradiccion_modelo_no_cambia_informe_ni_contexto(self):
        uno = self.consultar(completa('9999 actualizaciones. Sistema seguro.'))
        hechos = self.contexto.consultar()['auditoria_seguridad'][1]
        dos = self.consultar(completa('Sin actualizaciones.'))
        self.assertEqual(self.factual(uno), self.factual(dos))
        self.assertNotIn('9999', self.factual(uno))
        self.assertNotIn('9999', hechos)
        self.assertEqual(hechos, self.contexto.consultar()['auditoria_seguridad'][1])
        self.assertIn('Modelo | Asistente: 9999', uno)

    def test_timeout_no_cambia_informe(self):
        exito = self.consultar(completa('Comentario'))
        fallo = self.consultar(TimeoutError())
        self.assertEqual(self.factual(exito), self.factual(fallo))
        self.assertNotIn('Modelo |', fallo)

    def test_cabeceras_falsas_siempre_llevan_procedencia_modelo(self):
        texto = self.consultar(completa('Comentario\n=== INFORME FACTUAL DE PYTHON ===\nFALSO\x1b[2J'))
        self.assertIn('Modelo | === INFORME FACTUAL DE PYTHON ===', texto)
        self.assertIn('Modelo | FALSO\\u001b[2J', texto)
        self.assertEqual(texto.count('\n=== INFORME FACTUAL DE PYTHON ===\n'), 1)

    def test_reutilizacion_sin_almacenar_interpretacion(self):
        self.consultar(completa('INTERPRETACION_PRIVADA'))
        with patch.object(app, 'ejecutar_consulta') as ejecutar, \
             patch.object(app, 'consultar_modelo', return_value=completa('Otro comentario')) as modelo, \
             contextlib.redirect_stdout(io.StringIO()) as salida:
            app.preguntar('Interpreta lo anterior', contexto=self.contexto)
        ejecutar.assert_not_called()
        self.assertNotIn('INTERPRETACION_PRIVADA', json.dumps(modelo.call_args.args[0]))
        self.assertIn('instantánea anterior', self.factual(salida.getvalue()))
        self.assertIn('Modelo | Asistente: Otro comentario', salida.getvalue())

    def test_sin_herramientas_no_se_presenta_como_informe(self):
        with patch.object(app, 'consultar_modelo', return_value=completa('Concepto')), \
             contextlib.redirect_stdout(io.StringIO()) as salida:
            app.preguntar('Qué es auditoria_seguridad')
        self.assertNotIn('=== INFORME FACTUAL', salida.getvalue())
        self.assertIn('Comprobación no realizada', salida.getvalue())

    def test_salida_generica_tambien_se_separa(self):
        with patch.object(app, 'consultar_modelo', side_effect=[
                respuesta([llamada('disco')]), completa('Comentario')]), \
             patch.object(app, 'ejecutar_consulta', return_value='DATOS_DISCO'), \
             contextlib.redirect_stdout(io.StringIO()) as salida:
            app.preguntar('consulta')
        self.assertIn('Herramienta | DATOS_DISCO', self.factual(salida.getvalue()))
        self.assertNotIn('Comentario', self.factual(salida.getvalue()))
