"""Fallos simulados: nunca se contacta con el servidor ni se altera el sistema."""
import contextlib
import io
import json
import subprocess
import sys
import unittest
from unittest.mock import patch
import urllib.error

import AsistenteLocal as app


class ErroresSimulados(unittest.TestCase):
    def comprobar_recuperacion(self, error, mensaje):
        with patch.object(sys, 'argv', ['AsistenteLocal.py']), \
             patch('builtins.input', side_effect=['primera', 'segunda', 'salir']), \
             patch.object(app, 'consultar_modelo', side_effect=[error,
                 {'choices': [{'message': {'role': 'assistant', 'content': 'Recuperado'}}]}]) as modelo, \
             patch.object(app, 'ejecutar_consulta') as ejecutar, \
             patch.object(app, 'ALLOW_EXTERNAL', False), \
             contextlib.redirect_stdout(io.StringIO()) as salida:
            app.main()
            self.assertIn(mensaje, salida.getvalue())
            self.assertIn('Recuperado', salida.getvalue())
            self.assertEqual(modelo.call_count, 2)
            ejecutar.assert_not_called()

    def test_http_401_404_429_500_503(self):
        for codigo in (401, 404, 429, 500, 503):
            with self.subTest(codigo=codigo):
                cuerpo = io.BytesIO(b'error simulado')
                error = urllib.error.HTTPError(app.API_URL, codigo, 'simulado', {}, cuerpo)
                self.comprobar_recuperacion(error, f'Error HTTP de LM Studio ({codigo})')
                self.assertTrue(cuerpo.closed)

    def test_conexion_rechazada_y_timeout(self):
        self.comprobar_recuperacion(
            urllib.error.URLError(ConnectionRefusedError('simulado')),
            'Error conectando con LM Studio')
        self.comprobar_recuperacion(TimeoutError('simulado'), 'Consulta interrumpida')

    def test_respuesta_invalida_recuperable(self):
        self.comprobar_recuperacion(app.RespuestaInvalida('JSON simulado inválido'),
                                   'Consulta interrumpida')

    def test_errores_http_del_transporte(self):
        for codigo in (400, 404, 429, 500, 503):
            error = urllib.error.HTTPError(app.API_URL, codigo, 'simulado', {}, None)
            with self.subTest(codigo=codigo), \
                 patch.object(app, 'abrir_http_local', side_effect=error), \
                 self.assertRaises(urllib.error.HTTPError) as capturado:
                app.consultar_modelo([])
            self.assertEqual(capturado.exception.code, codigo)
            error.close()

    def test_timeout_lectura_cierra_respuesta(self):
        class HTTP(io.BytesIO):
            def read1(self, size):
                raise TimeoutError('lectura simulada')
        http = HTTP(b'')
        with patch.object(app, 'abrir_http_local', return_value=http), \
             self.assertRaises(TimeoutError):
            app.consultar_modelo([])
        self.assertTrue(http.closed)

    def test_comandos_errores_simulados(self):
        casos = [(FileNotFoundError('simulado'), 'NO SE PUDO EJECUTAR'),
                 (PermissionError('simulado'), 'NO SE PUDO EJECUTAR'),
                 (TimeoutError('simulado'), 'TIEMPO AGOTADO'),
                 (subprocess.TimeoutExpired(['df'], 15), 'TIEMPO AGOTADO')]
        for error, texto in casos:
            with self.subTest(error=type(error).__name__), \
                 patch.object(app, 'ejecutar_comando', side_effect=error):
                self.assertIn(texto, app.ejecutar_consulta('disco'))
        with patch.object(app, 'ejecutar_comando', return_value=(1, '', 'permiso denegado', False)):
            resultado = app.ejecutar_consulta('disco')
            self.assertIn('ESTADO: ERROR', resultado)
            self.assertIn('permiso denegado', resultado)

    def test_fallo_parcial_no_impide_siguiente_comando(self):
        with patch.object(app, 'ejecutar_comando', side_effect=[
                FileNotFoundError('simulado'), (0, 'UDP simulado', '', False)]) as ejecutar:
            resultado = app.ejecutar_consulta('puertos')
        self.assertEqual(ejecutar.call_count, 2)
        self.assertIn('NO SE PUDO EJECUTAR', resultado)
        self.assertIn('UDP simulado', resultado)

    def test_documentos_permiso_simulado(self):
        with patch.object(app.os, 'open', side_effect=PermissionError('simulado')):
            self.assertIn('carpeta documental segura', app.listar_documentos())

    def test_trafico_error_lectura_simulado(self):
        with patch.object(app.os, 'listdir', side_effect=PermissionError('simulado')), \
             patch.object(app.time, 'sleep') as dormir:
            resultado = app.ejecutar_consulta('trafico_red')
        dormir.assert_not_called()
        self.assertIn('No se pudieron enumerar', resultado)


if __name__ == '__main__':
    unittest.main()
