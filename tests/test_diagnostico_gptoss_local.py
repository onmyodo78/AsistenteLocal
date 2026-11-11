"""El corredor real solo se ejercita con dobles de HTTP en estas regresiones."""
import contextlib
import io
import json
import time
import unittest
from unittest.mock import patch

import diagnostico_gptoss_local as d
from test_lmstudio_comunicacion import HTTP


class DiagnosticoSeguro(unittest.TestCase):
    def payload(self):
        return dict(model='openai/gpt-oss-20b', messages=[dict(role='user', content='PROMPT_PRIVADO')],
                    tool_choice='none', max_tokens=1800)

    def respuesta(self, texto='La swap respalda memoria virtual.'):
        return dict(choices=[dict(finish_reason='stop', message=dict(role='assistant',
                    content=texto, reasoning='RAZONAMIENTO_PRIVADO'))])

    def test_positivo_solo_retorna_metadatos(self):
        http = HTTP(json.dumps(self.respuesta('CONTENIDO_PRIVADO')).encode())
        with patch.object(d, 'abrir_http_local', return_value=http) as abrir:
            r = d.probar(self.payload(), time.monotonic()+120)
        abrir.assert_called_once()
        self.assertEqual(abrir.call_args.args[0].full_url, 'http://127.0.0.1:1234/v1/chat/completions')
        self.assertLessEqual(abrir.call_args.kwargs['timeout'], 45)
        self.assertTrue(r['explicacion_admisible'])
        self.assertEqual(r['caracteres_final'], len('CONTENIDO_PRIVADO'))
        self.assertNotIn('PRIVADO', json.dumps(r))
        self.assertTrue(http.closed)

    def test_vacio_y_herramientas_siguen_rechazados_sin_reintentos(self):
        for cuerpo in (self.respuesta(''), dict(choices=[dict(finish_reason='tool_calls',
                message=dict(role='assistant', content=None, tool_calls=[dict(id='x',type='function',
                function=dict(name='memoria',arguments='{}'))]))])):
            with patch.object(d, 'abrir_http_local', return_value=HTTP(json.dumps(cuerpo).encode())) as abrir, \
                 patch.object(d.app, 'ejecutar_consulta', side_effect=AssertionError('Adquisición prohibida')):
                r = d.probar(self.payload(), time.monotonic()+120)
            self.assertFalse(r['explicacion_admisible'])
            abrir.assert_called_once()

    def test_salida_excesiva_json_invalido_y_error_http_no_filtran_contenido(self):
        for cuerpo, codigo in ((b'PRIVADO{', 'json_invalido'),
                               (b'x' * (d.app.MAX_HTTP_BYTES+1), 'http_excesivo')):
            with patch.object(d, 'abrir_http_local', return_value=HTTP(cuerpo)):
                r = d.probar(self.payload(), time.monotonic()+120)
            self.assertEqual(r['motivo_validacion'], codigo)
            self.assertNotIn('PRIVADO', str(r))

    def test_deadline_previo_no_inicia_http(self):
        with patch.object(d, 'abrir_http_local') as abrir:
            r = d.probar(self.payload(), time.monotonic()-1)
        abrir.assert_not_called()
        self.assertFalse(r['explicacion_admisible'])
        self.assertEqual(r['tipo_error'], 'TimeoutError')

    def test_cli_exige_opt_in_y_cantidad_acotada(self):
        for args in ([], ['--real','--casos']+['A']*6, ['--real','--seed','-1']):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit), \
                 patch.object(d, 'probar', side_effect=AssertionError('Inferencia no autorizada')):
                d.main(args)

    def test_cli_semilla_no_cambia_herramientas_ni_imprime_cuerpo(self):
        with patch.object(d, 'privacidad_configurada', return_value=True), \
             patch.object(d, 'probar', return_value={'explicacion_admisible':True}) as probar, \
             contextlib.redirect_stdout(io.StringIO()) as salida:
            d.main(['--real','--casos','A','B','--seed','7'])
        self.assertEqual(probar.call_count, 2)
        for call in probar.call_args_list:
            self.assertEqual(call.args[0]['seed'],7)
            self.assertEqual(call.args[0]['tool_choice'],'none')
            self.assertNotIn('tools',call.args[0])
            self.assertEqual(call.args[0]['max_tokens'],1800)
        self.assertNotIn('messages',salida.getvalue())
        self.assertNotIn('content',salida.getvalue())

    def test_cli_no_envia_si_no_confirma_privacidad(self):
        with patch.object(d, 'privacidad_configurada', return_value=False), \
             patch.object(d, 'probar') as probar, contextlib.redirect_stderr(io.StringIO()), \
             self.assertRaises(SystemExit):
            d.main(['--real'])
        probar.assert_not_called()

    def test_sondeo_privacidad_no_acepta_configuracion_ambigua(self):
        for contenido, esperado in (('{"logSensitiveData": false}',True),
                                     ('{"logSensitiveData": true}',False),
                                     ('{"logSensitiveData": 0}',False), ('{}',False), ('[]',False), ('invalido',False)):
            with self.subTest(contenido=contenido), patch.object(d.Path, 'read_text', return_value=contenido):
                self.assertEqual(d.privacidad_configurada(),esperado)
