"""Planes, sesión e integración HTTP simulada; sin herramientas del anfitrión."""
import contextlib
import io
import json
import unittest
from unittest.mock import patch

import AsistenteLocal as app
from motor_consultas import ContextoFactual, planificar, MAX_TEXTO, VIDA_SEGUNDOS
from test_p0 import respuesta, llamada
import test_continuacion_auditoria as continuacion
from test_lmstudio_comunicacion import HTTP, completa


class Planes(unittest.TestCase):
    def test_seleccion(self):
        for texto in ('Audita Debian 13', 'Comprueba las actualizaciones de Debian',
                      'auditoria_seguridad', 'auditoría de seguridad'):
            self.assertEqual(planificar(texto).nombres, ('auditoria_seguridad',))
        self.assertEqual(planificar('Ejecuta auditoria_seguridad y correlacion_seguridad').nombres,
                         ('auditoria_seguridad', 'correlacion_seguridad'))

    def test_conceptos_y_negacion(self):
        for texto in ('Qué es auditoria_seguridad', 'Cómo funciona la correlación CVE',
                      'No ejecutes auditoria_seguridad', 'Sin consultar correlacion_seguridad'):
            p = planificar(texto)
            self.assertFalse(p.nombres)
            self.assertTrue(p.conceptual)

    def test_referencia_y_nueva(self):
        self.assertTrue(planificar('Interpreta lo anterior sin repetir').reutilizar)
        self.assertTrue(planificar('Reutiliza auditoria_seguridad anterior').reutilizar)
        self.assertFalse(planificar('Ejecuta una nueva auditoria_seguridad').reutilizar)


class Contexto(unittest.TestCase):
    def test_limites_caducidad_copia_y_cierre(self):
        ahora = [0.]
        c = ContextoFactual(lambda: ahora[0])
        with self.assertRaises(ValueError):
            c.guardar('terminal', 'dato')
        with self.assertRaises(ValueError):
            c.guardar('auditoria_seguridad', 'x' * (MAX_TEXTO + 1))
        c.guardar('auditoria_seguridad', 'hechos')
        copia = c.consultar()
        copia.clear()
        self.assertTrue(c.consultar())
        ahora[0] = VIDA_SEGUNDOS
        self.assertFalse(c.consultar())
        c.guardar('auditoria_seguridad', 'otros')
        c.cerrar()
        self.assertFalse(c.consultar())


class Motor(unittest.TestCase):
    def setUp(self):
        self.contexto = ContextoFactual()
        self.backend = patch.object(app, 'seleccionar_backend_seguridad', return_value={
            'backend': 'debian', 'estado': 'parcial'})
        self.backend.start()
        self.addCleanup(self.backend.stop)
        self.salida = io.StringIO()
        self.redirect = contextlib.redirect_stdout(self.salida)
        self.redirect.__enter__()
        self.addCleanup(self.redirect.__exit__, None, None, None)
        # Toda adquisición accidental hace fallar estas pruebas.
        for objeto, atributo in ((app.subprocess, 'Popen'), (app, 'abrir_http_local')):
            barrera = patch.object(objeto, atributo, side_effect=AssertionError('Acceso real prohibido'))
            barrera.start()
            self.addCleanup(barrera.stop)

    def auditoria(self):
        return continuacion.ContinuacionAuditoria.resultado(self)

    def preguntar(self, texto):
        app.preguntar(texto, contexto=self.contexto)

    def test_explicita_no_depende_del_modelo_y_compuesta(self):
        def consulta(nombre, deadline):
            return self.auditoria() if nombre == 'auditoria_seguridad' else json.dumps({'estado': 'no_implementado', 'estado_adquisicion': 'no_realizada'})
        with patch.object(app, 'ejecutar_consulta', side_effect=consulta) as ejecutar, \
             patch.object(app, 'consultar_modelo', return_value=completa('Interpretación')) as modelo:
            self.preguntar('Ejecuta auditoria_seguridad y correlacion_seguridad')
        self.assertEqual([c.args[0] for c in ejecutar.call_args_list],
                         ['auditoria_seguridad', 'correlacion_seguridad'])
        modelo.assert_called_once()
        self.assertFalse(modelo.call_args.kwargs['permitir_herramientas'])
        mensajes = modelo.call_args.args[0]
        self.assertEqual([m['role'] for m in mensajes], ['system', 'user', 'assistant', 'tool', 'tool'])
        self.assertIn('3109', self.salida.getvalue())
        self.assertIn('no_implementado', self.salida.getvalue())

    def test_reutilizacion_saneada_y_adquisicion_nueva(self):
        with patch.object(app, 'ejecutar_consulta', return_value=self.auditoria()) as ejecutar, \
             patch.object(app, 'consultar_modelo', return_value=completa('MODELO_PRIVADO')) as modelo:
            self.preguntar('auditoria_seguridad')
            self.preguntar('Interpreta auditoria_seguridad anterior')
            ejecutar.assert_called_once()
            mensajes = json.dumps(modelo.call_args.args[0])
            self.assertIn('3109', mensajes)
            self.assertNotIn('PRIVADO', mensajes)
            self.assertIn('instant', mensajes)
            self.assertFalse(modelo.call_args.kwargs['permitir_herramientas'])
            self.preguntar('Ejecuta una nueva auditoria_seguridad')
            self.assertEqual(ejecutar.call_count, 2)

    def test_sin_evidencia_no_adquiere(self):
        with patch.object(app, 'ejecutar_consulta') as ejecutar, \
             patch.object(app, 'consultar_modelo', return_value=completa('Sin datos')):
            self.preguntar('Interpreta auditoria_seguridad anterior')
        ejecutar.assert_not_called()
        self.assertIn('comprobación no realizada', self.salida.getvalue())

    def test_negacion_de_explicacion_no_consulta_modelo_ni_adquiere(self):
        for texto in ('No expliques auditoria_seguridad',
                      'No me expliques auditoria_seguridad anterior',
                      'Sin interpretar correlacion_seguridad'):
            with self.subTest(texto=texto), \
                 patch.object(app, 'ejecutar_consulta') as ejecutar, \
                 patch.object(app, 'consultar_modelo') as modelo:
                p = planificar(texto)
                self.assertFalse(p.nombres or p.reutilizar or p.conceptual or p.explicar)
                self.preguntar(texto)
                ejecutar.assert_not_called()
                modelo.assert_not_called()

    def test_contexto_rechaza_blancos_sin_perder_hechos_ni_repetir(self):
        self.contexto.guardar('auditoria_seguridad', 'HECHO_SINTETICO')
        for texto in (' ', '\t', '\n', ' \t\n '):
            with self.subTest(texto=repr(texto)), \
                 patch.object(app, 'ejecutar_consulta') as ejecutar, \
                 patch.object(app, 'consultar_modelo', return_value=completa(texto)) as modelo:
                self.salida.seek(0)
                self.salida.truncate()
                self.preguntar('Interpreta auditoria_seguridad anterior')
                ejecutar.assert_not_called()
                modelo.assert_called_once()
                self.assertIn('HECHO_SINTETICO', self.salida.getvalue())
                self.assertNotIn('Modelo | Asistente:', self.salida.getvalue())
                self.assertIn('no está disponible', self.salida.getvalue())
                self.assertIn('HECHO_SINTETICO', self.contexto.consultar()['auditoria_seguridad'][1])

    def test_contexto_payload_agrupa_hechos_antes_de_pregunta(self):
        self.contexto.guardar('auditoria_seguridad', 'HECHO_SINTETICO')
        pregunta = 'Interpreta auditoria_seguridad anterior sin repetir'
        with patch.object(app, 'abrir_http_local', return_value=HTTP(json.dumps(completa('Explicación')).encode())) as abrir, \
             patch.object(app, 'registrar_metadatos'), \
             patch.object(app, 'ejecutar_consulta') as ejecutar:
            self.preguntar(pregunta)
        ejecutar.assert_not_called()
        abrir.assert_called_once()
        payload = json.loads(abrir.call_args.args[0].data)
        self.assertEqual([m['role'] for m in payload['messages']], ['system', 'user'])
        self.assertIn('HECHO_SINTETICO', payload['messages'][0]['content'])
        self.assertIn('instantánea anterior', payload['messages'][0]['content'])
        self.assertEqual(payload['messages'][1]['content'], pregunta)
        self.assertEqual(payload['tool_choice'], 'none')
        self.assertNotIn('tools', payload)
        self.assertEqual(payload['max_tokens'], 1800)
        self.assertLessEqual(abrir.call_args.kwargs['timeout'], 90)

    def test_conceptual_no_ejecuta_aunque_modelo_lo_pida(self):
        with patch.object(app, 'ejecutar_consulta') as ejecutar, \
             patch.object(app, 'consultar_modelo', return_value=respuesta([llamada('auditoria_seguridad')])):
            self.preguntar('Qué es auditoria_seguridad')
        ejecutar.assert_not_called()

    def test_timeout_interpretacion_no_repite_y_conserva_hechos(self):
        with patch.object(app, 'ejecutar_consulta', return_value=self.auditoria()) as ejecutar, \
             patch.object(app, 'consultar_modelo', side_effect=TimeoutError()):
            self.preguntar('auditoria_seguridad')
            self.preguntar('Interpreta lo anterior')
        ejecutar.assert_called_once()
        self.assertIn('3109', self.contexto.consultar()['auditoria_seguridad'][1])

    def test_error_adquisicion_sustituye_exito_y_completa_plan(self):
        with patch.object(app, 'ejecutar_consulta', side_effect=[self.auditoria(), TimeoutError(), 'no_implementado']) as ejecutar, \
             patch.object(app, 'consultar_modelo', return_value=completa('Fin')):
            self.preguntar('auditoria_seguridad')
            self.preguntar('Nueva auditoria_seguridad y correlacion_seguridad')
            self.preguntar('Interpreta lo anterior')
        self.assertEqual(ejecutar.call_count, 3)
        hecho = self.contexto.consultar()['auditoria_seguridad'][1]
        self.assertNotIn('3109', hecho)
        self.assertIn('no realizada', hecho)

    def test_modelo_no_puede_reabrir_plan(self):
        with patch.object(app, 'ejecutar_consulta', return_value=self.auditoria()) as ejecutar, \
             patch.object(app, 'consultar_modelo', return_value=respuesta([llamada('auditoria_seguridad')])):
            self.preguntar('auditoria_seguridad')
        ejecutar.assert_called_once()

    def test_integracion_payload_http(self):
        with patch.object(app, 'abrir_http_local', return_value=HTTP(json.dumps(completa('Fin')).encode())) as abrir, \
             patch.object(app, 'registrar_metadatos'), \
             patch.object(app, 'ejecutar_consulta', return_value=self.auditoria()):
            self.preguntar('auditoria_seguridad')
        abrir.assert_called_once()
        cuerpo = json.loads(abrir.call_args.args[0].data)
        self.assertEqual(cuerpo['tool_choice'], 'none')
        self.assertNotIn('tools', cuerpo)
        self.assertEqual(cuerpo['max_tokens'], 1800)
        self.assertLessEqual(abrir.call_args.kwargs['timeout'], 90)

    def test_limites_existentes_sin_cambios(self):
        self.assertEqual((app.MAX_SECONDS, app.MAX_MODEL_SECONDS, app.MAX_ROUNDS,
                          app.MAX_CALLS_PER_RESPONSE, app.MAX_CALLS,
                          app.MAX_OUTPUT, app.MAX_TOTAL_OUTPUT),
                         (120, 45, 4, 4, 8, 18000, 60000))

    def test_despachador_real_debian_compuesto_sin_comandos(self):
        seleccion = {'backend': 'debian', 'estado': 'parcial',
                     'distribucion': {'id': 'debian', 'version_id': '13'}}
        with patch.object(app, 'seleccionar_backend_seguridad', return_value=seleccion), \
             patch.object(app, 'inventario_debian', return_value=self.auditoria().datos) as inventario, \
             patch.object(app, 'consultar_correlacion', side_effect=AssertionError('Correlación Fedora')), \
             patch.object(app, 'consultar_modelo', return_value=completa('Fin')):
            self.preguntar('Audita Debian y consulta la correlación CVE')
        inventario.assert_called_once()
        self.assertIn('no_implementado', self.contexto.consultar()['correlacion_seguridad'][1])

    def test_main_contexto_persiste_y_se_limpia(self):
        sesiones = []
        def pregunta(texto):
            c = app._CONTEXTO_FACTUAL.get()
            sesiones.append(c)
            if texto == 'primera':
                c.guardar('auditoria_seguridad', 'Hechos')
            else:
                self.assertIn('auditoria_seguridad', c.consultar())
        with patch.object(app.sys, 'argv', ['AsistenteLocal.py']), \
             patch.object(app, 'informar_entorno'), \
             patch('builtins.input', side_effect=['primera', 'segunda', 'salir']), \
             patch.object(app, 'preguntar', side_effect=pregunta):
            app.main()
        self.assertIs(sesiones[0], sesiones[1])
        self.assertFalse(sesiones[0].consultar())
        self.assertIsNone(app._CONTEXTO_FACTUAL.get())

    def test_resultado_no_verificable_no_inventa_estado(self):
        self.assertNotIn('no_implementado', app.hecho_seguridad('correlacion_seguridad', 'error'))

    def test_caducidad_no_repite_herramientas(self):
        ahora = [0.]
        self.contexto = ContextoFactual(lambda: ahora[0])
        self.contexto.guardar('auditoria_seguridad', 'Hechos')
        ahora[0] = VIDA_SEGUNDOS
        with patch.object(app, 'ejecutar_consulta') as ejecutar, \
             patch.object(app, 'consultar_modelo', return_value=completa('Sin datos')):
            self.preguntar('Reutiliza la auditoria_seguridad anterior')
        ejecutar.assert_not_called()
        self.assertIn('comprobación no realizada', self.salida.getvalue())

    def test_limite_total_no_ejecuta_plan_fuera_de_presupuesto(self):
        with patch.object(app, 'MAX_TOTAL_OUTPUT', 0), \
             patch.object(app, 'ejecutar_consulta') as ejecutar, \
             patch.object(app, 'consultar_modelo', return_value=completa('Fin')):
            self.preguntar('auditoria_seguridad y correlacion_seguridad')
        ejecutar.assert_not_called()

    def test_interrupcion_nueva_no_deja_exito_anterior(self):
        self.contexto.guardar('auditoria_seguridad', '3109')
        with patch.object(app, 'ejecutar_consulta', side_effect=KeyboardInterrupt()), \
             patch.object(app, 'consultar_modelo') as modelo:
            with self.assertRaises(KeyboardInterrupt):
                self.preguntar('Nueva auditoria_seguridad')
        modelo.assert_not_called()
        hecho = self.contexto.consultar()['auditoria_seguridad'][1]
        self.assertNotIn('3109', hecho)
        self.assertIn('no confirmada', hecho)
