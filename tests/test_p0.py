# El protocolo assistant/tool se prueba directamente; el router público se cubre en test_operaciones_locales.
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import AsistenteLocal as app


def respuesta(llamadas=None, content=None):
    return {'choices': [{'message': {'role': 'assistant', 'content': content,
                                    'tool_calls': llamadas or []}}]}


def llamada(nombre='disco', argumentos='{}', ident='a'):
    return {'id': ident, 'type': 'function',
            'function': {'name': nombre, 'arguments': argumentos}}


class SeguridadP0(unittest.TestCase):
    def test_externas_bloqueadas_y_esquema(self):
        with patch.object(app, 'ALLOW_EXTERNAL', False), patch.object(app, 'ejecutar_comando') as run:
            self.assertNotIn('diagnostico_vpn', app.herramientas_disponibles())
            self.assertIn('RECHAZADA', app.ejecutar_consulta('diagnostico_vpn'))
            run.assert_not_called()
        with patch.object(app, 'ALLOW_EXTERNAL', True):
            self.assertIn('diagnostico_vpn', app.herramientas_disponibles())

    def test_validacion_estructural(self):
        invalidas = [None, [], {}, {'choices': []}, {'choices': [None]},
                     respuesta(content=42), respuesta([llamada(), llamada()]),
                     respuesta([{}]), respuesta([llamada(argumentos={})]),
                     respuesta([llamada(ident=str(i)) for i in range(5)]), respuesta()]
        for valor in invalidas:
            with self.subTest(valor=valor), self.assertRaises(app.RespuestaInvalida):
                app.validar_respuesta(valor)

    def test_argumentos_y_nombres_rechazados(self):
        for nombre, argumentos in [('disco', '[]'), ('disco', '{'),
                                   ('disco', '{"x":1}'), ('no_autorizada', '{}')]:
            with self.subTest(nombre=nombre, argumentos=argumentos):
                with patch.object(app, 'consultar_modelo', side_effect=[
                    respuesta([llamada(nombre, argumentos)]), respuesta(content='Fin')]), \
                     patch.object(app, 'ejecutar_consulta') as run, contextlib.redirect_stdout(io.StringIO()):
                    app._preguntar_con_herramientas('consulta')
                    run.assert_not_called()

    def test_repeticiones_y_respuesta_final(self):
        respuestas = [respuesta([llamada(ident=str(i))]) for i in range(app.MAX_ROUNDS)]
        respuestas.append(respuesta(content='Resumen'))
        with patch.object(app, 'consultar_modelo', side_effect=respuestas) as modelo, \
             patch.object(app, 'ejecutar_consulta', return_value='dato') as run, \
             contextlib.redirect_stdout(io.StringIO()) as out:
            app._preguntar_con_herramientas('consulta')
            self.assertEqual(run.call_count, 1)
            self.assertIn('Resumen', out.getvalue())
            self.assertFalse(modelo.call_args.kwargs['permitir_herramientas'])
            self.assertTrue(any(m['role'] == 'tool' for m in modelo.call_args.args[0]))

    def test_respuesta_final_no_ejecuta_herramientas(self):
        with patch.object(app, 'MAX_ROUNDS', 0), \
             patch.object(app, 'consultar_modelo', return_value=respuesta([llamada()])), \
             patch.object(app, 'ejecutar_consulta') as run, contextlib.redirect_stdout(io.StringIO()):
            app._preguntar_con_herramientas('consulta')
            run.assert_not_called()

    def test_limite_total_y_por_salida(self):
        self.assertEqual(len(app.limitar('x' * 50000)), app.MAX_OUTPUT)
        self.assertIn('TRUNCADO', app.limitar('x' * 50000))
        tandas = [respuesta([llamada(n, ident=n) for n in ['disco', 'memoria', 'puertos', 'sistema']]),
                  respuesta(content='Fin')]
        with patch.object(app, 'MAX_TOTAL_OUTPUT', 20000), \
             patch.object(app, 'consultar_modelo', side_effect=tandas) as modelo, \
             patch.object(app, 'ejecutar_consulta', return_value='x' * 50000) as run, \
             contextlib.redirect_stdout(io.StringIO()):
            app._preguntar_con_herramientas('consulta')
            tools = [m for m in modelo.call_args.args[0] if m['role'] == 'tool']
            self.assertLessEqual(sum(len(m['content']) for m in tools), 20000)
            self.assertEqual(run.call_count, 2)

    def test_documentos_aislados(self):
        # Todos los datos de prueba permanecen dentro del proyecto.
        with tempfile.TemporaryDirectory(dir=Path(app.__file__).parent) as tmp:
            root = Path(tmp)
            docs = root / 'documentos'
            docs.mkdir()
            (docs / 'normal.txt').write_text('prueba')
            (docs / '.oculto.txt').touch()
            (docs / 'nombre\n\x1b.txt').touch()
            (docs / 'enlace').symlink_to('normal.txt')
            with patch.object(app, '__file__', str(root / 'AsistenteLocal.py')):
                texto = app.listar_documentos()
                self.assertIn('6 bytes', texto)
                self.assertIn('.oculto.txt', texto)
                self.assertIn('no seguido', texto)
                self.assertIn('nombre\\n\\u001b.txt', texto)
                with patch.object(app, 'MAX_DOCUMENTS', 1):
                    self.assertIn('TRUNCADO', app.listar_documentos())
                docs.rename(root / 'otra')
                docs.symlink_to(root / 'otra', target_is_directory=True)
                self.assertIn('carpeta documental segura', app.listar_documentos())

    def test_documentos_independientes_del_directorio_de_trabajo(self):
        # Solo datos sintéticos: la carpeta del cwd actúa como señuelo.
        cwd_original = Path.cwd()
        with tempfile.TemporaryDirectory(dir=Path(app.__file__).resolve().parent) as tmp:
            raiz = Path(tmp)
            modulo = raiz / 'modulo'
            ajeno = raiz / 'otro_directorio'
            (modulo / 'documentos').mkdir(parents=True)
            (ajeno / 'documentos').mkdir(parents=True)
            (modulo / 'documentos' / 'del_modulo.txt').write_text('prueba')
            (ajeno / 'documentos' / 'del_cwd.txt').write_text('señuelo')
            with patch.object(app, '__file__', str(modulo / 'AsistenteLocal.py')), \
                 patch.object(app, 'ejecutar_comando', side_effect=AssertionError('No comandos')) as comando, \
                 patch.object(app, 'consultar_modelo', side_effect=AssertionError('No modelo')) as modelo, \
                 patch.object(app, 'abrir_http_local', side_effect=AssertionError('No HTTP')) as http:
                with contextlib.chdir(ajeno):
                    self.assertEqual(Path.cwd(), ajeno)
                    texto = app.listar_documentos()
                    self.assertIn('del_modulo.txt', texto)
                    self.assertIn('6 bytes', texto)
                    self.assertNotIn('del_cwd.txt', texto)
                self.assertEqual(Path.cwd(), cwd_original)
            comando.assert_not_called()
            modelo.assert_not_called()
            http.assert_not_called()

    def test_carpeta_ausente(self):
        with tempfile.TemporaryDirectory(dir=Path(app.__file__).parent) as tmp:
            with patch.object(app, '__file__', str(Path(tmp) / 'AsistenteLocal.py')):
                self.assertIn('No se pudo', app.listar_documentos())

    def test_saneamiento(self):
        texto = app.sanear('a\x1b[31m\u202eb\n')
        self.assertNotIn('\x1b', texto)
        self.assertNotIn('\u202e', texto)
        self.assertTrue(texto.endswith('\n'))

    def test_deadline_rechaza_antes_de_ejecutar(self):
        with patch.object(app, 'ejecutar_comando') as run, self.assertRaises(TimeoutError):
            app.ejecutar_consulta('disco', time.monotonic() - 1)
        run.assert_not_called()

    def test_comando_salida_y_errores(self):
        codigo, out, err, trunc = app.ejecutar_comando(
            [sys.executable, '-B', '-c', 'import sys; print("hola"); sys.stderr.write("aviso"); sys.exit(3)'], 3)
        self.assertEqual((codigo, out.strip(), err, trunc), (3, 'hola', 'aviso', False))

    def test_comando_salida_excesiva(self):
        codigo, out, err, trunc = app.ejecutar_comando(
            [sys.executable, '-B', '-c', 'import os;\nwhile True: os.write(1, b"x" * 4096)'], 3)
        self.assertTrue(trunc)
        self.assertLessEqual(len(out) + len(err), app.MAX_COMMAND_BYTES)

    def test_comando_timeout_y_ausente(self):
        with self.assertRaises(TimeoutError):
            app.ejecutar_comando([sys.executable, '-B', '-c', 'import time; time.sleep(10)'], .05)
        with self.assertRaises(OSError):
            app.ejecutar_comando(['/bin/asistentelocal-binario-inexistente'], 1)

    def test_presupuesto_llamadas(self):
        nombres = ['disco', 'memoria', 'puertos', 'sistema', 'vpn',
                   'conexiones', 'interfaces_red', 'cortafuegos']
        tandas = [respuesta([llamada(n, ident=n) for n in nombres[:4]]),
                  respuesta([llamada(n, ident=n) for n in nombres[4:]]),
                  respuesta(content='Fin')]
        with patch.object(app, 'consultar_modelo', side_effect=tandas) as modelo, \
             patch.object(app, 'ejecutar_consulta', return_value='dato') as run, \
             contextlib.redirect_stdout(io.StringIO()):
            app._preguntar_con_herramientas('consulta')
            self.assertEqual(run.call_count, app.MAX_CALLS)
            self.assertFalse(modelo.call_args.kwargs['permitir_herramientas'])

    def test_http_errores_y_plazo(self):
        for error in [TimeoutError('timeout'), app.urllib.error.URLError('sin conexión')]:
            with patch.object(app, 'abrir_http_local', side_effect=error), \
                 self.assertRaises(type(error)):
                app.consultar_modelo([])
        with patch.object(app, 'abrir_http_local') as abrir, self.assertRaises(TimeoutError):
            app.consultar_modelo([], deadline=time.monotonic() - 1)
        abrir.assert_not_called()

    def test_http_timeout_por_lectura(self):
        from types import SimpleNamespace
        from unittest.mock import Mock
        class HTTP(io.BytesIO):
            pass
        http = HTTP(json.dumps(respuesta(content='Fin')).encode())
        socket = Mock()
        http.fp = SimpleNamespace(raw=SimpleNamespace(_sock=socket))
        with patch.object(app, 'abrir_http_local', return_value=http):
            app.consultar_modelo([], deadline=time.monotonic() + 2)
        self.assertGreaterEqual(socket.settimeout.call_count, 1)
        self.assertLessEqual(socket.settimeout.call_args.args[0], 2)

    def test_http_validacion_limites_y_esquema(self):
        class HTTP(io.BytesIO):
            pass
        datos = json.dumps(respuesta(content='Hola')).encode()
        with patch.object(app, 'abrir_http_local', return_value=HTTP(datos)) as abrir:
            self.assertEqual(app.consultar_modelo([])['choices'][0]['message']['content'], 'Hola')
            payload = json.loads(abrir.call_args.args[0].data)
            self.assertNotIn('diagnostico_vpn', [t['function']['name'] for t in payload['tools']])
            self.assertLessEqual(abrir.call_args.kwargs['timeout'], app.MAX_MODEL_SECONDS)
        for datos in [b'no json', b'{}', b'x' * (app.MAX_HTTP_BYTES + 1)]:
            with patch.object(app, 'abrir_http_local', return_value=HTTP(datos)), \
                 self.assertRaises(app.RespuestaInvalida):
                app.consultar_modelo([])


if __name__ == '__main__':
    unittest.main()
