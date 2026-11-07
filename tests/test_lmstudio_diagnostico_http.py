"""Errores HTTP simulados: no abre sockets ni contacta con LM Studio."""
import contextlib
import errno
import io
import json
import unittest
import urllib.error
from unittest.mock import patch

import AsistenteLocal as app
import lmstudio_metrics as metricas
from test_lmstudio_comunicacion import HTTP, completa


class DiagnosticoHTTP(unittest.TestCase):
    def consultar(self, error=None, contenido=None):
        http = HTTP(contenido if contenido is not None else json.dumps(completa()).encode())
        with patch.object(app, 'abrir_http_local', side_effect=error, return_value=http) as abrir, \
             contextlib.redirect_stderr(io.StringIO()) as salida:
            if error is None and contenido is None:
                app.consultar_modelo([])
            else:
                with self.assertRaises(type(error) if error is not None else app.RespuestaInvalida) as capturado:
                    app.consultar_modelo([])
                if error is not None:
                    self.assertIs(capturado.exception, error)
        self.assertEqual(abrir.call_count, 1)
        self.assertTrue(0 < abrir.call_args.kwargs['timeout'] <= 45)
        lineas = salida.getvalue().splitlines()
        self.assertEqual(len(lineas), 1)
        self.assertTrue(lineas[0].startswith('LMSTUDIO_METRICAS '))
        self.assertNotIn('SECRETO', lineas[0])
        return json.loads(lineas[0].split(' ', 1)[1])

    def test_correcta(self):
        m = self.consultar()
        self.assertEqual(m['estado_http'], 200)
        self.assertIsNone(m['tipo_error_sistema'])
        self.assertIsNone(m['tipo_error'])
        self.assertGreater(m['bytes_cuerpo'], 0)
        self.assertGreater(m['bytes_peticion'], 0)
        self.assertTrue(all(m['duraciones_s'][k] is not None for k in ('preparacion', 'conexion_y_cabeceras', 'lectura_cuerpo', 'cierre', 'validacion')))

    def test_directos_y_envueltos(self):
        for error, esperado in (
            (TimeoutError('SECRETO'), 'TimeoutError'),
            (ConnectionRefusedError(errno.ECONNREFUSED, 'SECRETO'), 'ConnectionRefusedError'),
            (PermissionError(errno.EACCES, 'SECRETO'), 'PermissionError'),
            (OSError(errno.EPERM, 'SECRETO'), 'PermissionError'),
            (OSError(errno.EIO, 'SECRETO'), 'OSError'),
        ):
            for envolver in (False, True):
                with self.subTest(esperado=esperado, envolver=envolver):
                    m = self.consultar(urllib.error.URLError(error) if envolver else error)
                    self.assertEqual(m['tipo_error_sistema'], esperado)
                    self.assertEqual(m['tipo_error'], 'URLError' if envolver else metricas.tipo_error(error))
                    self.assertEqual(m['fase_error'], 'conexion_y_cabeceras')
                    self.assertIsNone(m['estado_http'])
                    self.assertEqual(m['bytes_cuerpo'], 0)
                    self.assertIsNone(m['duraciones_s']['lectura_cuerpo'])

    def test_no_infiere_por_texto(self):
        for texto in ('SECRETO Permission denied', 'SECRETO Connection refused', 'SECRETO timed out'):
            m = self.consultar(urllib.error.URLError(texto))
            self.assertIsNone(m['tipo_error_sistema'])

    def test_http_error_no_es_error_sistema(self):
        cuerpo = io.BytesIO(b'SECRETO')
        error = urllib.error.HTTPError('http://SECRETO', 503, 'SECRETO', {}, cuerpo)
        try:
            m = self.consultar(error)
            self.assertEqual(m['estado_http'], 503)
            self.assertEqual(m['tipo_error'], 'HTTPError')
            self.assertIsNone(m['tipo_error_sistema'])
            self.assertEqual(cuerpo.tell(), 0)
        finally:
            error.close()

    def test_cuerpos_invalidos(self):
        for cuerpo in (b'{', b'{}', b'{"choices":[]}', b'\xff'):
            with self.subTest(cuerpo=cuerpo):
                m = self.consultar(contenido=cuerpo)
                self.assertEqual(m['fase_error'], 'validacion')
                self.assertEqual(m['tipo_error'], 'RespuestaInvalida')
                self.assertIsNone(m['tipo_error_sistema'])
                self.assertEqual(m['estado_http'], 200)
                self.assertEqual(m['bytes_cuerpo'], len(cuerpo))

    def test_timeout_lectura_no_se_atribuye_a_conexion(self):
        class Cortada(HTTP):
            def read1(self, n):
                raise TimeoutError('SECRETO')
        with patch.object(app, 'abrir_http_local', return_value=Cortada(b'')), \
             contextlib.redirect_stderr(io.StringIO()) as salida, self.assertRaises(TimeoutError):
            app.consultar_modelo([])
        m = json.loads(salida.getvalue().split(' ', 1)[1])
        self.assertEqual(m['fase_error'], 'lectura_cuerpo')
        self.assertEqual(m['tipo_error_sistema'], 'TimeoutError')
        self.assertEqual(m['estado_http'], 200)

    def test_emisor_filtra_campo_nuevo(self):
        for valor in ('SECRETO', {'SECRETO': 1}, ['SECRETO'], 42, None):
            datos = metricas.MedicionHTTP().finalizar()
            datos['tipo_error_sistema'] = valor
            with contextlib.redirect_stderr(io.StringIO()) as salida:
                metricas.registrar_metadatos(datos)
            self.assertIsNone(json.loads(salida.getvalue().split(' ', 1)[1])['tipo_error_sistema'])
            self.assertNotIn('SECRETO', salida.getvalue())
