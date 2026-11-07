import contextlib
import io
import unittest
from unittest.mock import patch
import AsistenteLocal as app


class Entorno(unittest.TestCase):
    def test_informe_sin_ejecutar_comandos(self):
        with patch.object(app.shutil, 'which', return_value=None), \
             patch.object(app.os.path, 'isfile', return_value=False), \
             patch.dict(app.os.environ, {'FLATPAK_ID': 'com.visualstudio.code'}), \
             patch.object(app.subprocess, 'Popen') as ejecutar:
            datos = app.entorno_ejecucion()
            self.assertTrue(datos['flatpak'])
            self.assertEqual(set(datos['dependencias']), set(app.TOOLS))
            self.assertEqual(datos['dependencias']['vpn']['nmcli']['estado'], 'ausente')
            ejecutar.assert_not_called()

    def test_ruta_disponible(self):
        with patch.object(app.shutil, 'which', side_effect=lambda n: '/usr/bin/' + n):
            self.assertEqual(app.entorno_ejecucion()['dependencias']['disco']['df'],
                             {'ruta': '/usr/bin/df', 'estado': 'disponible'})

    def test_archivo_sin_ejecucion(self):
        with patch.object(app.shutil, 'which', return_value=None), \
             patch.object(app.os.path, 'isfile', return_value=True), \
             patch.object(app.os, 'access', return_value=False):
            self.assertEqual(app.entorno_ejecucion()['dependencias']['vpn']['nmcli']['estado'],
                             'sin permiso de ejecución')

    def test_distingue_ausente_y_permiso_en_ejecucion(self):
        for error, esperado in [(FileNotFoundError('simulado'), 'EJECUTABLE AUSENTE'),
                                (PermissionError('simulado'), 'PERMISO DENEGADO')]:
            with self.subTest(error=type(error).__name__), \
                 patch.object(app, 'ejecutar_comando', side_effect=error):
                self.assertIn('CAUSA: ' + esperado, app.ejecutar_consulta('disco'))

    def test_aviso_informativo(self):
        for backend, mensaje in (('fedora', 'terminal nativa de Fedora'),
                                 ('debian', 'terminal nativa del anfitrión Debian 13')):
            with self.subTest(backend=backend), \
                 patch.object(app, 'seleccionar_backend_seguridad',
                              return_value=dict(backend=backend, estado='disponible')), \
                 patch.dict(app.os.environ, {'FLATPAK_ID': 'com.visualstudio.code'}), \
                 contextlib.redirect_stdout(io.StringIO()) as salida:
                app.informar_entorno()
            self.assertIn(mensaje, salida.getvalue())
            self.assertIn('No se usa un puente automático', salida.getvalue())
