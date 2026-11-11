# El protocolo assistant/tool se prueba directamente; el router público se cubre en test_operaciones_locales.
import contextlib
import http.client
import io
import json
import unittest
import urllib.error
from unittest.mock import Mock, patch
from types import SimpleNamespace

import AsistenteLocal as app
import lmstudio_metrics as metricas
from interfaces_red import ResultadoInterfaces
from test_interfaces_red import datos, llamada, respuesta


class HTTP(io.BytesIO):
    status = 200


def completa(texto='Fin', final='stop'):
    r = respuesta(texto=texto)
    r['choices'][0]['finish_reason'] = final
    return r


class Comunicacion(unittest.TestCase):
    def consultar(self, cuerpo=None, error=None, http=None):
        if http is None:
            http = HTTP(json.dumps(cuerpo if cuerpo is not None else completa()).encode())
        with patch.object(app, 'abrir_http_local', side_effect=error, return_value=http) as abrir, \
             patch.object(app, 'registrar_metadatos') as registrar:
            fallo = None
            valor = None
            try:
                valor = app.consultar_modelo([{'role': 'user', 'content': 'PRIVADO_PROMPT'}])
            except Exception as e:
                fallo = e
        self.assertEqual(registrar.call_count, 1)
        return valor, fallo, registrar.call_args.args[0], abrir

    def test_duracion_por_fase_y_total(self):
        reloj = [0.0]
        def ahora():
            return reloj[0]
        class ConLatencia(HTTP):
            def read1(self, n):
                bloque = super().read1(n)
                if bloque:
                    reloj[0] += 3
                return bloque
        http = ConLatencia(json.dumps(completa()).encode())
        def abrir(*args, **kwargs):
            reloj[0] += 2
            return http
        validar = app.validar_respuesta
        def validacion(r):
            reloj[0] += 1
            return validar(r)
        with patch.object(app.time, 'monotonic', side_effect=ahora), \
             patch.object(app, 'abrir_http_local', side_effect=abrir), \
             patch.object(app, 'validar_respuesta', side_effect=validacion), \
             patch.object(app, 'registrar_metadatos') as registrar:
            app.consultar_modelo([])
        m = registrar.call_args.args[0]
        self.assertEqual(m['duraciones_s'], {'preparacion': 0, 'conexion_y_cabeceras': 2,
                                           'conexion_tcp': None, 'envio_peticion': None, 'espera_cabeceras': None,
                                           'lectura_cuerpo': 3, 'cierre': 0, 'validacion': 1})
        self.assertEqual(m['total_s'], 6)
        self.assertEqual(m['estado_http'], 200)
        self.assertEqual(m['finish_reason'], 'stop')
        self.assertIsNone(m['tipo_error'])
        self.assertTrue(http.closed)

    def test_timeout_antes_de_cabeceras(self):
        _, error, m, abrir = self.consultar(error=TimeoutError('SECRETO_ERROR'))
        self.assertIsInstance(error, TimeoutError)
        self.assertEqual(m['fase_error'], 'conexion_y_cabeceras')
        self.assertEqual(m['tipo_error'], 'TimeoutError')
        self.assertIsNone(m['duraciones_s']['lectura_cuerpo'])
        self.assertIsNone(m['duraciones_s']['validacion'])
        self.assertIsNone(m['estado_http'])
        self.assertEqual(abrir.call_count, 1)

    def test_timeout_lectura_despues_de_bloque(self):
        class Cortada(HTTP):
            def __init__(self):
                super().__init__(b'')
                self.leida = False
            def read1(self, n):
                if not self.leida:
                    self.leida = True
                    return b'{"partial":'
                raise TimeoutError('SECRETO_CUERPO')
        http = Cortada()
        _, error, m, _ = self.consultar(http=http)
        self.assertIsInstance(error, TimeoutError)
        self.assertEqual(m['fase_error'], 'lectura_cuerpo')
        self.assertEqual(m['bytes_cuerpo'], len(b'{"partial":'))
        self.assertEqual(m['estado_http'], 200)
        self.assertIsNone(m['duraciones_s']['validacion'])
        self.assertTrue(http.closed)

    def test_http_error_sin_leer_cuerpo_sensible(self):
        for codigo in (401, 429, 500, 503):
            cuerpo = io.BytesIO(b'SECRETO_CUERPO_HTTP')
            error = urllib.error.HTTPError('http://usuario:CLAVE@local', codigo,
                                           'SECRETO_RAZON', {'Authorization': 'SECRETO'}, cuerpo)
            try:
                _, capturado, m, _ = self.consultar(error=error)
                self.assertIs(capturado, error)
                self.assertEqual(m['estado_http'], codigo)
                self.assertEqual(m['tipo_error'], 'HTTPError')
                self.assertEqual(cuerpo.tell(), 0)
                self.assertNotIn('SECRETO', json.dumps(m))
            finally:
                error.close()

    def test_json_incompleto_y_estructura_invalida(self):
        for contenido in (b'{', b'{}', b'{"choices":[]}'):
            with self.subTest(contenido=contenido):
                http = HTTP(contenido)
                _, error, m, _ = self.consultar(http=http)
                self.assertIsInstance(error, app.RespuestaInvalida)
                self.assertEqual(m['fase_error'], 'validacion')
                self.assertEqual(m['tipo_error'], 'RespuestaInvalida')
                self.assertEqual(m['bytes_cuerpo'], len(contenido))
                self.assertTrue(http.closed)

    def test_incomplete_read(self):
        class Incompleta(HTTP):
            def read1(self, n):
                raise http.client.IncompleteRead(b'SECRETO_PARCIAL', 100)
        respuesta_http = Incompleta(b'')
        _, error, m, _ = self.consultar(http=respuesta_http)
        self.assertIsInstance(error, http.client.IncompleteRead)
        self.assertEqual(m['tipo_error'], 'IncompleteRead')
        self.assertEqual(m['bytes_cuerpo'], len(b'SECRETO_PARCIAL'))
        self.assertEqual(m['fase_error'], 'lectura_cuerpo')
        self.assertNotIn('SECRETO', json.dumps(m))
        self.assertTrue(respuesta_http.closed)

    def test_metadata_disponible_aunque_mensaje_incompleto(self):
        r = {'choices': [{'finish_reason': 'length', 'message': {'role': 'assistant', 'content': None}}],
             'usage': {'completion_tokens': 1800}}
        _, error, m, _ = self.consultar(r)
        self.assertIsInstance(error, app.RespuestaInvalida)
        self.assertEqual(m['finish_reason'], 'length')
        self.assertEqual(m['uso_tokens'], {'completion_tokens': 1800})

    def test_cierre_de_respuesta_es_fase_independiente(self):
        class CierreFallido(HTTP):
            def __exit__(self, *args):
                super().__exit__(*args)
                raise OSError('SECRETO_CIERRE')
        http = CierreFallido(json.dumps(completa()).encode())
        _, error, m, _ = self.consultar(http=http)
        self.assertIsInstance(error, OSError)
        self.assertEqual(m['fase_error'], 'cierre')
        self.assertIsNone(m['duraciones_s']['validacion'])
        self.assertTrue(http.closed)

    def test_privacidad_allowlist_de_finish_reason_y_tokens(self):
        r = completa('SECRETO_RESPUESTA', 'SECRETO_FINISH')
        r['usage'] = {'prompt_tokens': 111, 'completion_tokens': 22, 'total_tokens': 133,
                      'texto': 'SECRETO_USO', 'prompt_tokens_details': {'cached_tokens': 10, 'otro': 'SECRETO'},
                      'completion_tokens_details': {'reasoning_tokens': 7, 'contenido': 'SECRETO'}}
        r['choices'][0]['message']['reasoning'] = 'SECRETO_RAZONAMIENTO'
        _, error, m, abrir = self.consultar(r)
        self.assertIsNone(error)
        self.assertIsNone(m['finish_reason'])
        self.assertEqual(m['uso_tokens'], {'prompt_tokens': 111, 'completion_tokens': 22, 'total_tokens': 133,
                                         'prompt_tokens_details': {'cached_tokens': 10},
                                         'completion_tokens_details': {'reasoning_tokens': 7}})
        self.assertNotIn('SECRETO', json.dumps(m))
        self.assertNotIn('PRIVADO', json.dumps(m))
        self.assertEqual(m['bytes_peticion'], len(abrir.call_args.args[0].data))

    def test_contadores_invalidos_no_se_copian(self):
        for valor in ('PRIVADO', True, -1, 3.4, 2**80, None):
            with self.subTest(valor=valor):
                r = completa()
                r['usage'] = {'total_tokens': valor}
                _, _, m, _ = self.consultar(r)
                self.assertIsNone(m['uso_tokens'])

    def test_limites_y_parametros_sin_cambios(self):
        http = HTTP(json.dumps(completa()).encode())
        socket = Mock()
        http.fp = SimpleNamespace(raw=SimpleNamespace(_sock=socket))
        _, _, m, abrir = self.consultar(http=http)
        peticion = json.loads(abrir.call_args.args[0].data)
        self.assertEqual(peticion['model'], app.MODEL)
        self.assertEqual(peticion['temperature'], .2)
        self.assertEqual(peticion['max_tokens'], 1800)
        self.assertNotIn('stream', peticion)
        self.assertNotIn('reasoning_effort', peticion)
        self.assertLessEqual(abrir.call_args.kwargs['timeout'], 45)
        self.assertTrue(all(0 < c.args[0] <= 45 for c in socket.settimeout.call_args_list))
        self.assertEqual(app.MAX_SECONDS, 120)
        self.assertEqual(app.MAX_MODEL_SECONDS, 45)

    def test_presupuesto_global_restante_limita_cabeceras_y_cuerpo(self):
        reloj = [0.0]
        socket = Mock()
        http = HTTP(json.dumps(completa()).encode())
        http.fp = SimpleNamespace(raw=SimpleNamespace(_sock=socket))
        def abrir(*args, **kwargs):
            self.assertEqual(kwargs['timeout'], 5)
            reloj[0] = 4
            return http
        with patch.object(app.time, 'monotonic', side_effect=lambda: reloj[0]), \
             patch.object(app, 'abrir_http_local', side_effect=abrir), \
             patch.object(app, 'registrar_metadatos'):
            app.consultar_modelo([], deadline=5)
        self.assertTrue(all(c.args[0] <= 1 for c in socket.settimeout.call_args_list))

    def test_global_agotado_no_envia_peticion(self):
        with patch.object(app.time, 'monotonic', return_value=100), \
             patch.object(app, 'abrir_http_local') as abrir, \
             patch.object(app, 'registrar_metadatos') as registrar, self.assertRaises(TimeoutError):
            app.consultar_modelo([], deadline=99)
        abrir.assert_not_called()
        self.assertEqual(registrar.call_count, 1)

    def test_plazo_de_lectura_no_se_reinicia_por_bloque(self):
        reloj = [0.0]
        class Lenta(HTTP):
            def read1(self, n):
                bloque = super().read1(n)
                reloj[0] += 46
                return bloque
        http = Lenta(json.dumps(completa()).encode())
        with patch.object(app.time, 'monotonic', side_effect=lambda: reloj[0]), \
             patch.object(app, 'abrir_http_local', return_value=http), \
             patch.object(app, 'registrar_metadatos') as registrar, self.assertRaises(TimeoutError):
            app.consultar_modelo([], deadline=120)
        self.assertEqual(registrar.call_args.args[0]['fase_error'], 'lectura_cuerpo')
        self.assertTrue(http.closed)

    def test_emisor_descarta_campos_sensibles_inesperados(self):
        datos = metricas.MedicionHTTP().finalizar()
        datos.update(prompt='SECRETO', respuesta='SECRETO', credenciales='SECRETO',
                     finish_reason='SECRETO', tipo_error='SECRETO', fase_error='SECRETO')
        datos['duraciones_s']['prompt'] = 'SECRETO'
        datos['uso_tokens'] = {'total_tokens': 20, 'contenido': 'SECRETO'}
        with contextlib.redirect_stderr(io.StringIO()) as salida:
            metricas.registrar_metadatos(datos)
        self.assertNotIn('SECRETO', salida.getvalue())
        seguro = json.loads(salida.getvalue().split(' ', 1)[1])
        self.assertEqual(seguro['uso_tokens'], {'total_tokens': 20})
        self.assertNotIn('prompt', seguro)

    def test_error_del_destino_de_metricas_no_cambia_respuesta(self):
        with patch.object(app, 'abrir_http_local', return_value=HTTP(json.dumps(completa()).encode())), \
             patch.object(app, 'registrar_metadatos', side_effect=OSError('destino cerrado')):
            self.assertEqual(app.consultar_modelo([])['choices'][0]['message']['content'], 'Fin')

    def test_registro_real_solo_emite_metadatos(self):
        with contextlib.redirect_stderr(io.StringIO()) as salida:
            m = metricas.MedicionHTTP()
            metricas.registrar_metadatos(m.finalizar())
        linea = salida.getvalue().strip()
        self.assertTrue(linea.startswith('LMSTUDIO_METRICAS '))
        self.assertEqual(json.loads(linea.split(' ', 1)[1])['bytes_peticion'], 0)


class RecuperacionInterfaces(unittest.TestCase):
    def ciclo(self, final, herramienta='interfaces_red'):
        dato = ResultadoInterfaces(datos(), app.MAX_OUTPUT) if herramienta == 'interfaces_red' else 'Informe disco'
        consulta = llamada(herramienta)
        with patch.object(app, 'consultar_modelo', side_effect=[respuesta([consulta]), final]) as modelo, \
             patch.object(app, 'ejecutar_consulta', return_value=dato) as ejecutar, \
             contextlib.redirect_stdout(io.StringIO()) as salida:
            app._preguntar_con_herramientas('Consulta autorizada')
        self.assertEqual(modelo.call_count, 2)
        self.assertEqual(ejecutar.call_count, 1)
        return salida.getvalue()

    def test_timeout_conserva_hechos_sin_reintentar(self):
        texto = self.ciclo(TimeoutError('SECRETO_ERROR'))
        self.assertIn('Hechos de interfaces_red', texto)
        self.assertIn('Radio: desconocida', texto)
        self.assertIn('interpretación de LM Studio no está disponible', texto)
        self.assertIn('No se reintenta', texto)
        self.assertNotIn('SECRETO', texto)

    def test_error_http_cierra_cuerpo_y_conserva_hechos(self):
        cuerpo = io.BytesIO(b'SECRETO')
        error = urllib.error.HTTPError(app.API_URL, 503, 'SECRETO', {}, cuerpo)
        texto = self.ciclo(error)
        self.assertTrue(cuerpo.closed)
        self.assertIn('Se conserva el resumen factual', texto)
        self.assertNotIn('SECRETO', texto)

    def test_error_de_conexion_o_lectura_incompleta(self):
        for error in (urllib.error.URLError('SECRETO'), http.client.IncompleteRead(b'SECRETO', 20)):
            with self.subTest(error=type(error).__name__):
                self.assertIn('no está disponible', self.ciclo(error))

    def test_respuesta_vacia_o_invalida(self):
        for final in ({'choices': []}, respuesta(), app.RespuestaInvalida('SECRETO')):
            with self.subTest(final=type(final).__name__):
                self.assertIn('Se conserva el resumen factual', self.ciclo(final))

    def test_respuesta_truncada_no_se_presenta_como_final(self):
        for motivo in ('length', 'content_filter'):
            texto = self.ciclo(completa('SECRETO_PARCIAL', motivo))
            self.assertIn('no está disponible', texto)
            self.assertNotIn('SECRETO_PARCIAL', texto)

    def test_sin_hechos_previos_el_error_se_propaga(self):
        with patch.object(app, 'consultar_modelo', side_effect=TimeoutError()), \
             patch.object(app, 'ejecutar_consulta') as ejecutar, self.assertRaises(TimeoutError):
            app._preguntar_con_herramientas('interfaces')
        ejecutar.assert_not_called()

    def test_otras_herramientas_siguen_propagando_error(self):
        for error in (TimeoutError(), app.RespuestaInvalida()):
            with self.subTest(tipo=type(error).__name__), self.assertRaises(type(error)):
                self.ciclo(error, herramienta='disco')

    def test_ciclo_completo_cliente_instrumentado_con_fallo_final(self):
        inicial = HTTP(json.dumps(respuesta([llamada()])).encode())
        with patch.object(app, 'abrir_http_local', side_effect=[inicial, TimeoutError('SECRETO')]) as abrir, \
             patch.object(app, 'registrar_metadatos') as registrar, \
             patch.object(app, 'ejecutar_consulta', return_value=ResultadoInterfaces(datos(), app.MAX_OUTPUT)) as ejecutar, \
             contextlib.redirect_stdout(io.StringIO()) as salida:
            app._preguntar_con_herramientas('interfaces')
        self.assertEqual(abrir.call_count, 2)
        self.assertEqual(registrar.call_count, 2)
        self.assertEqual(ejecutar.call_count, 1)
        self.assertEqual(registrar.call_args.args[0]['tipo_error'], 'TimeoutError')
        self.assertEqual(registrar.call_args.args[0]['fase_error'], 'conexion_y_cabeceras')
        self.assertIn('Hechos de interfaces_red', salida.getvalue())
        self.assertIn('no está disponible', salida.getvalue())
        self.assertNotIn('SECRETO', salida.getvalue())

    def test_length_de_otras_herramientas_conserva_salida(self):
        texto = self.ciclo(completa('Texto parcial de disco', 'length'), herramienta='disco')
        self.assertIn('Asistente: Texto parcial de disco', texto)
        self.assertNotIn('no está disponible', texto)

    def test_exito_mantiene_separacion(self):
        texto = self.ciclo(completa('Comentario correcto'))
        self.assertIn('Interpretación del modelo — no verificada', texto)
        self.assertIn('Asistente: Comentario correcto', texto)
        self.assertNotIn('no está disponible', texto)


class DiagnosticoExplicacion(unittest.TestCase):
    PREGUNTA = ('Comprueba cuánta memoria RAM y swap tengo disponible, explícame '
                'para qué sirve la swap y no utilices sudo')

    def respuesta(self, contenido='La swap respalda páginas de memoria virtual en almacenamiento.'):
        return {'id': 'PRIVADO_ID', 'model': 'openai/gpt-oss-20b', 'object': 'chat.completion',
                'choices': [{'index': 0, 'finish_reason': 'stop',
                             'message': {'role': 'assistant', 'content': contenido}}],
                'usage': {'prompt_tokens': 1331, 'completion_tokens': 33, 'total_tokens': 1364}}

    def ciclo(self, respuesta):
        cuerpo = respuesta if isinstance(respuesta, bytes) else json.dumps(respuesta).encode()
        http = HTTP(cuerpo)
        resultado = dict(operacion='memoria', capacidad='disponible', autorizacion='permitida_lectura_local',
                         ejecucion='finalizada', verificacion='completo', motivo='resultado_de_adquisicion',
                         informe='RAM disponible: 4096 B. Swap libre: 2048 B.')
        with patch.object(app, 'abrir_http_local', return_value=http) as abrir, \
             patch.object(app, 'registrar_metadatos') as registrar, \
             patch.object(app, 'ejecutar_comando', side_effect=AssertionError('Adquisición prohibida')), \
             patch.object(app.subprocess, 'Popen', side_effect=AssertionError('Proceso prohibido')), \
             contextlib.redirect_stdout(io.StringIO()) as salida:
            app._explicar_peticion_local(self.PREGUNTA, [resultado], (), app.time.monotonic()+120, 18000)
        abrir.assert_called_once()  # Sin reintento ni otra petición.
        registrar.assert_called_once()
        self.assertTrue(http.closed)
        datos = registrar.call_args.args[0]
        with contextlib.redirect_stderr(io.StringIO()) as registro:
            metricas.registrar_metadatos(datos)
        self.assertNotIn('PRIVADO', registro.getvalue())
        self.assertNotIn(self.PREGUNTA, registro.getvalue())
        self.assertEqual(resultado['verificacion'], 'completo')
        return salida.getvalue(), datos, json.loads(abrir.call_args.args[0].data)

    def test_payload_exacto_y_respuesta_corta_aceptada(self):
        salida, datos, payload = self.ciclo(self.respuesta('La swap respalda páginas de memoria virtual.'))
        self.assertIsNone(datos['tipo_error'])
        self.assertEqual(payload['model'], 'openai/gpt-oss-20b')
        self.assertEqual(payload['tool_choice'], 'none')
        self.assertNotIn('tools', payload)
        self.assertNotIn('response_format', payload)
        self.assertNotIn('reasoning_effort', payload)
        self.assertNotIn('stream', payload)
        self.assertEqual(payload['max_tokens'], 1800)
        self.assertEqual(payload['temperature'], .2)
        self.assertEqual([m['role'] for m in payload['messages']], ['system', 'user', 'system'])
        self.assertEqual(payload['messages'][1]['content'], self.PREGUNTA)
        self.assertIn('4096', payload['messages'][2]['content'])
        self.assertIn('Modelo |', salida)
        self.assertIn('Interpretación del modelo', salida)

    def test_stop_con_33_tokens_y_solo_razonamiento_reproduce_rechazo(self):
        r = self.respuesta(None)
        r['choices'][0]['message']['reasoning_content'] = 'PRIVADO_RAZONAMIENTO'
        salida, datos, _ = self.ciclo(r)
        self.assertEqual(datos['estado_http'], 200)
        self.assertEqual(datos['finish_reason'], 'stop')
        self.assertEqual(datos['uso_tokens']['completion_tokens'], 33)
        self.assertEqual(datos['fase_error'], 'validacion')
        self.assertEqual(datos['tipo_error'], 'RespuestaInvalida')
        self.assertEqual(datos['motivo_validacion'], 'sin_texto_ni_herramientas')
        self.assertEqual(datos['forma_respuesta']['content_tipo'], 'null')
        self.assertTrue(datos['forma_respuesta']['reasoning_presente'])
        self.assertIn('Motivo de validación: sin_texto_ni_herramientas', salida)
        self.assertNotIn('PRIVADO', salida)
        self.assertNotIn('Modelo |', salida)

    def test_vacio_ausente_y_espacios_diferenciados(self):
        for contenido, motivo in (('', 'sin_texto_ni_herramientas'), (None, 'sin_texto_ni_herramientas'),
                                  (' \n\t', 'explicacion_vacia')):
            with self.subTest(contenido=contenido):
                salida, datos, _ = self.ciclo(self.respuesta(contenido))
                self.assertEqual(datos['motivo_validacion'], motivo)
                self.assertNotIn('Modelo |', salida)
        r = self.respuesta()
        del r['choices'][0]['message']['content']
        _, datos, _ = self.ciclo(r)
        self.assertEqual(datos['forma_respuesta']['content_tipo'], 'ausente')
        self.assertEqual(datos['motivo_validacion'], 'sin_texto_ni_herramientas')

    def test_tipos_no_textuales_no_se_adaptan(self):
        for contenido in ([], [{'type': 'text', 'text': 'PRIVADO'}], {'text': 'PRIVADO'}, 33):
            with self.subTest(contenido=contenido):
                salida, datos, _ = self.ciclo(self.respuesta(contenido))
                self.assertEqual(datos['motivo_validacion'], 'contenido_no_textual')
                self.assertNotIn('PRIVADO', salida)
                self.assertNotIn('Modelo |', salida)

    def test_json_y_roles_invalidos_distinguidos(self):
        for r, motivo in ((b'{PRIVADO', 'json_invalido'), ([], 'respuesta_no_objeto'),
                          ({'choices': []}, 'choices_invalidas'),
                          ({'choices': [{'message': {'role': 'user', 'content': 'PRIVADO'}}]}, 'assistant_invalido')):
            with self.subTest(motivo=motivo):
                _, datos, _ = self.ciclo(r)
                self.assertEqual(datos['motivo_validacion'], motivo)

    def test_campos_adicionales_y_tool_calls_nulo_no_cambian_texto_publico(self):
        r = self.respuesta('La swap puede contener páginas poco utilizadas.')
        r['choices'][0]['message'].update(reasoning='PRIVADO', tool_calls=None, campo_inesperado='PRIVADO')
        salida, datos, _ = self.ciclo(r)
        self.assertIsNone(datos['tipo_error'])
        self.assertTrue(datos['forma_respuesta']['reasoning_presente'])
        self.assertNotIn('PRIVADO', salida)
        self.assertIn('La swap puede', salida)

    def test_herramientas_y_function_call_no_se_ejecutan(self):
        for campo, valor in (('tool_calls', [{'id': 'x', 'type': 'function',
                'function': {'name': 'memoria', 'arguments': '{}'}}]),
                             ('function_call', {'name': 'memoria', 'arguments': '{}'})):
            r = self.respuesta('Texto breve.')
            r['choices'][0]['message'][campo] = valor
            salida, datos, _ = self.ciclo(r)
            self.assertEqual(datos['motivo_validacion'], 'herramientas_en_explicacion')
            self.assertEqual(datos['fase_error'], 'validacion')
            self.assertNotIn('Modelo |', salida)

    def test_finish_reason_incompleto_o_inesperado(self):
        for final in ('length', 'content_filter', 'tool_calls', 'PRIVADO'):
            r = self.respuesta()
            r['choices'][0]['finish_reason'] = final
            _, datos, _ = self.ciclo(r)
            self.assertEqual(datos['motivo_validacion'], 'explicacion_no_final')

    def test_guardia_semantica_ahora_tiene_metricas(self):
        for contenido in ('He comprobado la RAM.', 'Ejecuta sudo para consultar memoria.'):
            salida, datos, _ = self.ciclo(self.respuesta(contenido))
            self.assertEqual(datos['motivo_validacion'], 'afirmacion_operativa_o_recomendacion_administrativa')
            self.assertEqual(datos['fase_error'], 'validacion')
            self.assertNotIn(contenido, salida)

    def test_diagnosticos_son_doble_lista_blanca(self):
        datos = metricas.MedicionHTTP().finalizar()
        datos.update(motivo_validacion='PRIVADO', forma_respuesta=dict(content_tipo='PRIVADO',
                     reasoning_presente='PRIVADO', content_vacio=True, respuesta='PRIVADO'))
        with contextlib.redirect_stderr(io.StringIO()) as registro:
            metricas.registrar_metadatos(datos)
        self.assertNotIn('PRIVADO', registro.getvalue())
        salida = json.loads(registro.getvalue().split(' ', 1)[1])
        self.assertIsNone(salida['motivo_validacion'])
        self.assertIsNone(salida['forma_respuesta']['content_tipo'])
        self.assertIsNone(salida['forma_respuesta']['reasoning_presente'])
        self.assertTrue(salida['forma_respuesta']['content_vacio'])

    def test_modo_explicacion_exige_herramientas_omitidas_y_desactivadas(self):
        with patch.object(app, 'abrir_http_local') as abrir, patch.object(app, 'registrar_metadatos'):
            for opciones in ({}, {'permitir_herramientas': False}):
                with self.assertRaises(ValueError):
                    app.consultar_modelo([], solo_explicacion=True, **opciones)
            abrir.assert_not_called()
