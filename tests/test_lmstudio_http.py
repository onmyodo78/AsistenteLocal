"""Pruebas sin sockets reales del transporte por fases."""
import contextlib
import io
import json
import socket
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch
import AsistenteLocal as app
import lmstudio_http as transporte
from test_lmstudio_comunicacion import completa


class Transporte(unittest.TestCase):
    def ejecutar(self, fase=None, error=None, codigo=200):
        reloj = [0.0]
        eventos = []
        cuerpo = json.dumps(completa()).encode()
        class Socket:
            def __init__(self, limite):
                self.limite = limite
            def paso(self, nombre):
                eventos.append((nombre, self.limite - reloj[0]))
                reloj[0] += 1
                if nombre == fase:
                    raise error
            def connect(self, destino):
                assert destino == ('127.0.0.1', 1234)
                self.paso('conexion_tcp')
            def sendall(self, datos):
                self.paso('envio_peticion')
            def makefile(self, modo):
                propietario = self
                class Cabeceras(io.BytesIO):
                    def readline(self, *args):
                        propietario.paso('espera_cabeceras')
                        return super().readline(*args)
                return Cabeceras(f'HTTP/1.1 {codigo} Simulado\r\nContent-Length: {len(cuerpo)}\r\nConnection: close\r\n\r\n'.encode() + cuerpo)
            def close(self):
                eventos.append(('cerrado', None))
        with patch.object(transporte, 'SocketConPlazo', Socket), \
             patch.object(transporte.time, 'monotonic', side_effect=lambda: reloj[0]), \
             patch.dict('os.environ', {'http_proxy': 'http://externo:9999', 'no_proxy': ''}), \
             contextlib.redirect_stderr(io.StringIO()) as salida:
            if error or codigo >= 300:
                with self.assertRaises((OSError, urllib.error.URLError)) as capturado:
                    app.consultar_modelo([], deadline=45)
                if isinstance(capturado.exception, urllib.error.HTTPError):
                    capturado.exception.close()
            else:
                app.consultar_modelo([], deadline=45)
        return json.loads(salida.getvalue().split(' ', 1)[1]), eventos

    def test_exito_presupuesto_y_cierre(self):
        m, eventos = self.ejecutar()
        for fase in ('conexion_tcp', 'envio_peticion', 'espera_cabeceras'):
            self.assertIsNotNone(m['duraciones_s'][fase])
        presupuestos = [v for _, v in eventos if v is not None]
        self.assertEqual(presupuestos, sorted(presupuestos, reverse=True))
        self.assertEqual(presupuestos[0], 45)
        self.assertEqual(m['estado_http'], 200)
        self.assertIn(('cerrado', None), eventos)

    def test_errores_en_cada_fase(self):
        for fase in ('conexion_tcp', 'envio_peticion', 'espera_cabeceras'):
            for error in (TimeoutError('SECRETO'), ConnectionRefusedError('SECRETO'), PermissionError('SECRETO'), OSError('SECRETO')):
                with self.subTest(fase=fase, error=type(error).__name__):
                    m, eventos = self.ejecutar(fase, error)
                    self.assertEqual(m['fase_error'], fase)
                    self.assertIsNone(m['estado_http'])
                    self.assertNotIn('SECRETO', json.dumps(m))
                    self.assertEqual(sum(n == 'conexion_tcp' for n, _ in eventos), 1)
                    self.assertIn(('cerrado', None), eventos)

    def test_http_y_redirecciones(self):
        for codigo in (302, 401, 503):
            m, eventos = self.ejecutar(codigo=codigo)
            self.assertEqual(m['estado_http'], codigo)
            self.assertEqual(m['tipo_error'], 'HTTPError')
            self.assertEqual(sum(n == 'conexion_tcp' for n, _ in eventos), 1)
        self.assertIsNone(transporte.SinRedireccion().redirect_request(None, None, 302, '', {}, 'http://externo/'))

    def test_destinos_no_autorizados(self):
        for url in ('http://localhost:1234/v1/chat/completions', 'http://127.0.0.1:1234/otro', 'https://externo/', transporte.ENDPOINT + '?x=1'):
            with patch.object(transporte, 'SocketConPlazo') as crear, self.assertRaises(ValueError):
                transporte.abrir_http_local(urllib.request.Request(url, data=b'{}'), 45, None, 100)
            crear.assert_not_called()

    def test_cada_recepcion_descuenta_plazo(self):
        reloj = [0]
        with patch.object(socket.socket, '__init__', return_value=None), \
             patch.object(socket.socket, 'settimeout') as timeout, \
             patch.object(socket.socket, 'connect'), \
             patch.object(socket.socket, 'sendall'), \
             patch.object(socket.socket, 'recv_into', return_value=1) as recibir, \
             patch.object(transporte.time, 'monotonic', side_effect=lambda: reloj[0]):
            s = transporte.SocketConPlazo(5)
            s.connect(('127.0.0.1', 1234))
            reloj[0] = 1
            s.sendall(b'privado')
            reloj[0] = 3
            s.recv_into(bytearray(1))
            reloj[0] = 5
            with self.assertRaises(TimeoutError):
                s.recv_into(bytearray(1))
            self.assertEqual([c.args[0] for c in timeout.call_args_list], [5, 4, 2])
            self.assertEqual(recibir.call_count, 1)
