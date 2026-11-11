# El protocolo assistant/tool se prueba directamente; el router público se cubre en test_operaciones_locales.
"""Interacción humana simulada: sin diagnósticos, publicación ni archivos."""
import builtins
import contextlib
import io
import unittest
from unittest.mock import Mock, patch

import AsistenteLocal as app
import exportacion_interfaz as ui
from sesion_resultados import ColeccionSesion
from test_informe_exportacion import memoria
from test_p0 import respuesta, llamada


class InterfazLocal(unittest.TestCase):
    def setUp(self):
        self.coleccion = ColeccionSesion()
        self.addCleanup(self.coleccion.cerrar)
        self.uno = self.coleccion.insertar_saneado(memoria())
        self.dos = self.coleccion.insertar_saneado(memoria())
        self.interfaz = ui.InterfazExportacion(self.coleccion)
        self.addCleanup(self.interfaz.cerrar)

    def ejecutar(self, respuestas, tty=True):
        salida = io.StringIO()
        with patch.object(ui.sys.stdin, 'isatty', return_value=tty), \
             patch('builtins.input', side_effect=respuestas) as leer, \
             contextlib.redirect_stdout(salida):
            estado = self.interfaz.preparar_interactiva()
        return estado, salida.getvalue(), leer.call_count

    def test_md_y_csv_autorizan_sin_consumir(self):
        for formato in ('md', 'csv'):
            with patch.object(self.interfaz._control, 'consumir', side_effect=AssertionError('consumo')):
                estado, texto, _ = self.ejecutar(['1,2', formato, '/destino-privado/informe.'+formato, 'AUTORIZAR'])
            self.assertEqual(estado, 'autorizada')
            self.assertIn('Archivo no publicado', texto)
            self.assertIn('Vista previa saneada', texto)
            ident, token = self.interfaz._pendiente
            self.assertIn(token, self.interfaz._control._autorizaciones)
            vista = self.interfaz._control.vista_previa(ident)
            self.assertEqual(len(vista['resultados']), 2)
            self.assertEqual(vista['formato'], formato)
            self.assertNotIn('destino-privado', str(vista))

    def test_confirmaciones_vacias_invalidas_ambiguas(self):
        for respuesta in ('', 'si', 'sí', 'manual', 'AUTORIZAR si', 'autorizar', 'True'):
            estado, texto, _ = self.ejecutar(['1', 'md', '/informe.md', respuesta])
            self.assertEqual(estado, 'cancelada')
            self.assertIsNone(self.interfaz._pendiente)
            self.assertNotIn('Exportación autorizada', texto)

    def test_cancelar_en_cualquier_paso(self):
        valido = ['1', 'md', '/informe.md', 'AUTORIZAR']
        for paso in range(4):
            respuestas = valido[:paso]+['cancelar']
            estado, _, lecturas = self.ejecutar(respuestas)
            self.assertEqual(estado, 'cancelada')
            self.assertEqual(lecturas, paso+1)
            self.assertIsNone(self.interfaz._pendiente)

    def test_eof_interrupcion_en_cualquier_paso(self):
        valido = ['1', 'md', '/informe.md', 'AUTORIZAR']
        for excepcion in (EOFError(), KeyboardInterrupt()):
            for paso in range(4):
                estado, _, _ = self.ejecutar(valido[:paso]+[excepcion])
                self.assertEqual(estado, 'cancelada')
                self.assertIsNone(self.interfaz._pendiente)

    def test_no_interactiva_no_lee_ni_confirma(self):
        estado, texto, lecturas = self.ejecutar([], tty=False)
        self.assertEqual(estado, 'no_disponible')
        self.assertEqual(lecturas, 0)
        self.assertIn('entrada interactiva', texto)
        self.assertFalse(self.interfaz._control._activo)

    def test_selecciones_invalidas(self):
        for seleccion in ('999', '1,1', '1,privado', '0', '-1', 'todos', '1 2'):
            estado, texto, _ = self.ejecutar([seleccion])
            self.assertNotEqual(estado, 'autorizada')
            self.assertIsNone(self.interfaz._pendiente)
            self.assertNotIn('privado', texto)

    def test_coleccion_vacia_y_caducada(self):
        self.coleccion.vaciar()
        estado, texto, lecturas = self.ejecutar([])
        self.assertEqual(estado, 'no_disponible')
        self.assertIn('No hay resultados', texto)
        self.assertEqual(lecturas, 0)
        self.coleccion.cerrar()
        estado, texto, lecturas = self.ejecutar([])
        self.assertEqual(estado, 'no_disponible')
        self.assertEqual(lecturas, 0)

    def test_json_no_ofrecido_y_rechazado(self):
        estado, texto, lecturas = self.ejecutar(['1', 'json'])
        self.assertEqual(estado, 'cancelada')
        self.assertEqual(lecturas, 2)
        self.assertIn('Opciones disponibles: md y csv', texto)
        self.assertNotIn('JSON', texto)

    def test_destino_invalido_no_aparece_en_error(self):
        estado, texto, _ = self.ejecutar(['1', 'md', '/privado/../informe.csv'])
        self.assertEqual(estado, 'no_disponible')
        self.assertNotIn('/privado', texto)
        self.assertNotIn('Traceback', texto)

    def test_destino_humano_revisable_escapado(self):
        estado, texto, _ = self.ejecutar(['1', 'csv', '/usuario-privado/informe.csv', 'AUTORIZAR'])
        self.assertEqual(estado, 'autorizada')
        self.assertIn("'/usuario-privado/informe.csv'", texto)
        ident, _ = self.interfaz._pendiente
        self.assertNotIn('usuario-privado', self.interfaz._control._preparadas[ident]['contenido'].decode('utf-8-sig'))

    def test_repreparar_revoca_permiso_anterior(self):
        self.ejecutar(['1', 'md', '/informe.md', 'AUTORIZAR'])
        viejo_id, viejo_token = self.interfaz._pendiente
        self.ejecutar(['2', 'csv', '/otro.csv', 'AUTORIZAR'])
        self.assertNotEqual(viejo_id, self.interfaz._pendiente[0])
        self.assertNotIn(viejo_token, self.interfaz._control._autorizaciones)
        self.interfaz.cerrar()
        self.assertFalse(self.interfaz._control._autorizaciones)

    def test_confirmacion_solo_tras_vista(self):
        entradas = iter(['1', 'md', '/informe.md', 'AUTORIZAR'])
        salida = io.StringIO()
        def leer(prompt):
            respuesta = next(entradas)
            if respuesta == 'AUTORIZAR':
                self.assertIn('Vista previa saneada', salida.getvalue())
                self.assertIn('Destino introducido', salida.getvalue())
            return respuesta
        with patch.object(ui.sys.stdin, 'isatty', return_value=True), patch('builtins.input', side_effect=leer), contextlib.redirect_stdout(salida):
            self.assertEqual(self.interfaz.preparar_interactiva(), 'autorizada')

    def test_main_intercepta_antes_de_preguntar(self):
        with patch.object(app.sys, 'argv', ['AsistenteLocal.py']), \
             patch.object(app, 'ColeccionSesion', return_value=self.coleccion), \
             patch.object(app, 'InterfazExportacion', return_value=self.interfaz), \
             patch.object(app, 'informar_entorno'), patch.object(ui.sys.stdin, 'isatty', return_value=True), \
             patch('builtins.input', side_effect=[':exportar', '1', 'md', '/informe.md', 'AUTORIZAR', 'consulta', 'salir']), \
             patch.object(app, 'preguntar') as preguntar, \
             patch.object(app, 'consultar_modelo', side_effect=AssertionError('modelo')), \
             contextlib.redirect_stdout(io.StringIO()):
            app.main()
        preguntar.assert_called_once_with('consulta')
        self.assertIsNone(self.interfaz._pendiente)
        self.assertFalse(self.interfaz._control._autorizaciones)
        self.assertEqual(len(app.TOOLS), 14)
        self.assertNotIn(':exportar', app.TOOLS)

    def test_modelo_y_resultados_no_se_interpretan_como_comando(self):
        with patch.object(app, 'consultar_modelo', return_value=respuesta(content=':exportar')), \
             patch.object(app, 'InterfazExportacion', side_effect=AssertionError('interfaz')), \
             contextlib.redirect_stdout(io.StringIO()):
            app._preguntar_con_herramientas('consulta')
        with patch.object(app, 'consultar_modelo', side_effect=[respuesta([llamada(':exportar')]), respuesta(content='fin')]), \
             patch.object(app, 'ejecutar_consulta') as ejecutar, contextlib.redirect_stdout(io.StringIO()):
            app._preguntar_con_herramientas('consulta')
        ejecutar.assert_not_called()
        self.assertEqual(self.coleccion.estado()['registros'], 2)

    def test_sin_escrituras_adquisiciones_imports_sqlite_escritor(self):
        importar = builtins.__import__
        def comprobar(nombre, *a, **kw):
            if 'sqlite' in nombre or nombre in ('exportacion_escritor', 'historial_persistente', 'historial_controlador'):
                raise AssertionError('dependencia no admitida')
            return importar(nombre, *a, **kw)
        with patch('builtins.__import__', side_effect=comprobar), \
             patch('builtins.open', side_effect=AssertionError('archivo')), \
             patch('os.open', side_effect=AssertionError('descriptor')), \
             patch('os.mkdir', side_effect=AssertionError('directorio')), \
             patch('subprocess.Popen', side_effect=AssertionError('adquisicion')), \
             patch.object(self.interfaz._control, 'consumir', side_effect=AssertionError('consumo')):
            estado, _, _ = self.ejecutar(['1', 'csv', '/informe.csv', 'AUTORIZAR'])
        self.assertEqual(estado, 'autorizada')

    def test_caducidad_real_simulada_coleccion(self):
        ahora = [0.]
        coleccion = ColeccionSesion(reloj=lambda: ahora[0])
        self.addCleanup(coleccion.cerrar)
        coleccion.insertar_saneado(memoria())
        self.interfaz.cerrar()
        self.interfaz = ui.InterfazExportacion(coleccion)
        self.addCleanup(self.interfaz.cerrar)
        ahora[0] = 1800.
        estado, texto, lecturas = self.ejecutar([])
        self.assertEqual(estado, 'no_disponible')
        self.assertEqual(lecturas, 0)
        self.assertIsNone(self.interfaz._pendiente)
        self.assertNotIn('Traceback', texto)

    def test_perdida_de_tty_antes_confirmar_no_autoriza(self):
        with patch.object(ui.sys.stdin, 'isatty', side_effect=[True]*5+[False]), \
             patch('builtins.input', side_effect=['1', 'md', '/informe.md', 'AUTORIZAR']), \
             contextlib.redirect_stdout(io.StringIO()):
            estado = self.interfaz.preparar_interactiva()
        self.assertEqual(estado, 'cancelada')
        self.assertFalse(self.interfaz._control._autorizaciones)
