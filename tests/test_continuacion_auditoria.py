"""Continuación HTTP simulada: sin LM Studio, procesos ni APT reales."""
import contextlib
import copy
import io
import json
import unittest
from unittest.mock import patch

import AsistenteLocal as app
from test_lmstudio_comunicacion import HTTP, completa
from test_p0 import llamada, respuesta


class ContinuacionAuditoria(unittest.TestCase):
    def resultado(self):
        return app.ResultadoDebian({
            'backend': 'debian', 'herramienta': 'auditoria_seguridad',
            'estado_inventario': 'completo', 'total_instalados': 3109,
            'inventario_dpkg': [{'dato': 'PRIVADO_INVENTARIO'}],
            'actualizaciones': {'estado_adquisicion': 'completo', 'total_posibles': 0,
                               'frescura': 'no_verificada', 'instalabilidad': 'no_evaluada',
                               'candidatos': [{'dato': 'PRIVADO_CANDIDATOS'}]},
            'estado_seguridad': 'no_evaluada',
            'limitaciones': ['Seguridad no evaluada']}, app.MAX_OUTPUT)

    def ciclo(self, final, resultado=None, nombre='auditoria_seguridad'):
        if resultado is None:
            resultado = self.resultado()
        inicial = HTTP(json.dumps(respuesta([llamada(nombre)])).encode())
        ultimo = final if isinstance(final, Exception) else HTTP(json.dumps(final).encode())
        with patch.object(app, 'abrir_http_local', side_effect=[inicial, ultimo]) as abrir, \
             patch.object(app, 'registrar_metadatos'), \
             patch.object(app, 'ejecutar_consulta', return_value=resultado) as ejecutar, \
             contextlib.redirect_stdout(io.StringIO()) as salida:
            app.preguntar('Consulta autorizada')
        ejecutar.assert_called_once()
        self.assertEqual(ejecutar.call_args.args[0], nombre)
        self.assertEqual(abrir.call_count, 2)
        cuerpos = [json.loads(c.args[0].data) for c in abrir.call_args_list]
        self.assertEqual(cuerpos[0]['tool_choice'], 'auto')
        self.assertEqual(cuerpos[1]['tool_choice'], 'none' if nombre == 'auditoria_seguridad' else 'auto')
        if app.INSTRUCCION_CONTINUACION_AUDITORIA:
            self.assertNotIn(app.INSTRUCCION_CONTINUACION_AUDITORIA, cuerpos[0]['messages'][0]['content'])
        self.assertTrue(cuerpos[0]['tools'])
        if nombre == 'auditoria_seguridad':
            self.assertNotIn('tools', cuerpos[1])
        else:
            self.assertEqual(cuerpos[0]['tools'], cuerpos[1]['tools'])
        for i,c in enumerate(abrir.call_args_list):
            limite = app.MAX_INTERPRETATION_SECONDS if i==1 and nombre=='auditoria_seguridad' else app.MAX_MODEL_SECONDS
            self.assertTrue(0 < c.kwargs['timeout'] <= limite)
        return salida.getvalue(), cuerpos[1]

    def test_exito_conserva_resultado_y_parametros(self):
        resultado = self.resultado()
        original = copy.deepcopy(resultado.datos)
        texto, cuerpo = self.ciclo(completa('Comentario'), resultado)
        tool = [m for m in cuerpo['messages'] if m['role'] == 'tool']
        self.assertEqual(len(tool), 1)
        self.assertEqual(tool[0]['content'], resultado.ajustar(app.MAX_OUTPUT))
        self.assertEqual(resultado.datos, original)
        self.assertNotIn('PRIVADO', tool[0]['content'])
        self.assertLessEqual(len(tool[0]['content']), 5000)
        for esperado in ('3109', 'frescura no verificada', 'instalabilidad no comprobada',
                         'Seguridad: no evaluada', 'Comentario'):
            self.assertIn(esperado, texto)
        self.assertEqual(cuerpo['max_tokens'], 1800)
        self.assertEqual(cuerpo['temperature'], .2)

    def test_ab_solo_cambia_instruccion_en_system_existente(self):
        # A reproduce el prompt anterior; B añade solo la instrucción autorizada.
        with patch.object(app, 'INSTRUCCION_CONTINUACION_AUDITORIA', ''):
            texto_a, cuerpo_a = self.ciclo(completa('Comentario'))
        texto_b, cuerpo_b = self.ciclo(completa('Comentario'))
        self.assertEqual(texto_a, texto_b)
        self.assertEqual([m['role'] for m in cuerpo_b['messages']],
                         ['system', 'user', 'assistant', 'tool'])
        self.assertEqual(cuerpo_b['messages'][0]['content'],
                         cuerpo_a['messages'][0]['content'] + '\n\n' + app.INSTRUCCION_CONTINUACION_AUDITORIA)
        cuerpo_b['messages'][0]['content'] = cuerpo_a['messages'][0]['content']
        self.assertEqual(cuerpo_a, cuerpo_b)

    def test_no_ejecuta_llamadas_aunque_servidor_ignore_none(self):
        for nombre in ('auditoria_seguridad', 'memoria'):
            with self.subTest(nombre=nombre):
                texto, _ = self.ciclo(respuesta([llamada(nombre, ident='segunda')]))
                self.assertIn('no está disponible', texto)
                self.assertIn('3109', texto)

    def test_ab_omision_tools_conserva_resto_payload(self):
        _, continuacion = self.ciclo(completa('Comentario'))
        mensajes = copy.deepcopy(continuacion['messages'])
        cuerpos = []
        for omitir in (False, True):
            with patch.object(app, 'abrir_http_local',
                              return_value=HTTP(json.dumps(completa('Comentario')).encode())) as abrir, \
                 patch.object(app, 'registrar_metadatos'):
                app.consultar_modelo(mensajes, permitir_herramientas=False, omitir_tools=omitir)
            cuerpos.append(json.loads(abrir.call_args.args[0].data))
        self.assertTrue(cuerpos[0].pop('tools'))
        self.assertNotIn('tools', cuerpos[1])
        self.assertEqual(cuerpos[0], cuerpos[1])
        self.assertEqual(continuacion, cuerpos[1])
        self.assertEqual(mensajes, continuacion['messages'])
        self.assertIn(app.INSTRUCCION_CONTINUACION_AUDITORIA, mensajes[0]['content'])

    def test_fallos_no_reintentan_y_conservan_hechos(self):
        for final in (TimeoutError('PRIVADO'), {}, respuesta(),
                      completa('PARCIAL', 'length'), completa('PARCIAL', 'content_filter')):
            with self.subTest(final=final):
                texto, _ = self.ciclo(final)
                self.assertIn('no está disponible', texto)
                self.assertIn('3109', texto)
                self.assertIn('Seguridad: no evaluada', texto)
                self.assertNotIn('PRIVADO', texto)
                self.assertNotIn('PARCIAL', texto)

    def test_desconocidos_y_errores_se_conservan(self):
        datos = self.resultado().datos
        datos.update(estado_inventario='parcial', total_instalados=None,
                     fuente={'motivo': 'error_recogida'})
        datos['actualizaciones'].update(estado_adquisicion='error', total_posibles=None)
        resultado = app.ResultadoDebian(datos, app.MAX_OUTPUT)
        texto, cuerpo = self.ciclo(completa('Comentario'), resultado)
        self.assertIn('desconocido', texto)
        self.assertIn('No se ha confirmado', texto)
        self.assertEqual(json.loads(cuerpo['messages'][-1]['content'])['fuente'],
                         {'motivo': 'error_recogida'})

    def test_otras_herramientas_conservan_auto(self):
        for nombre in app.herramientas_disponibles():
            if nombre == 'auditoria_seguridad':
                continue
            with self.subTest(nombre=nombre):
                _, cuerpo = self.ciclo(completa('Comentario'), 'Resultado local', nombre)
                self.assertFalse(any(app.INSTRUCCION_CONTINUACION_AUDITORIA in m.get('content', '')
                                     for m in cuerpo['messages'] if isinstance(m.get('content'), str)))

    def test_auditoria_rechazada_no_fuerza_final(self):
        with patch.object(app, 'consultar_modelo', side_effect=[
                respuesta([llamada('auditoria_seguridad', argumentos='{"x":1}')]),
                completa('Fin')]) as modelo, \
             patch.object(app, 'ejecutar_consulta') as ejecutar, \
             contextlib.redirect_stdout(io.StringIO()):
            app.preguntar('Consulta')
        ejecutar.assert_not_called()
        self.assertTrue(modelo.call_args.kwargs['permitir_herramientas'])
        self.assertNotIn('omitir_tools', modelo.call_args.kwargs)
        self.assertNotIn(app.INSTRUCCION_CONTINUACION_AUDITORIA,
                         modelo.call_args.args[0][0]['content'])
