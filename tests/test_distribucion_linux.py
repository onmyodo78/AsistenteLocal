import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

import distribucion_linux as distro


class Deteccion(unittest.TestCase):
    def test_fedora_y_debian_13(self):
        for texto, ident, version, codename in [
            ('NAME="Fedora Linux"\nID=fedora\nVERSION_ID=44\n', 'fedora', '44', None),
            ("# comentario\nID='debian'\nVERSION_ID=\"13\"\nVERSION_CODENAME=trixie\n", 'debian', '13', 'trixie')]:
            with self.subTest(ident=ident), patch.object(Path, 'open', side_effect=AssertionError('disco')):
                self.assertEqual(distro.detectar_distribucion(contenido=texto),
                    dict(estado='soportado', id=ident, version_id=version,
                         version_codename=codename, origen='contenido', motivo=None))

    def test_no_infiere_derivados_ni_versiones(self):
        for texto in ('ID=ubuntu\nVERSION_ID=24.04\nID_LIKE=debian',
                      'ID=desconocida\nID_LIKE=fedora', 'ID=debian\nVERSION_ID=12',
                      'ID=debian\nVERSION_ID=14', 'ID=debian', 'ID=fedora'):
            with self.subTest(texto=texto):
                self.assertEqual(distro.detectar_distribucion(contenido=texto)['estado'], 'no_soportado')

    def test_datos_invalidos(self):
        for texto in ('', 'ID_LIKE=debian', 'ID="debian', 'ID=debian\nID=fedora',
                      'ID=debian extra', 'export ID=debian', 'ID=Debian',
                      'ID=debian\nVERSION_ID="$(echo 13)"', 'ID=debian\x00',
                      'ID=debian\nVERSION_ID=13\nNAME="a""b"', 'x' * 65537):
            with self.subTest(texto=texto[:60]):
                datos = distro.detectar_distribucion(contenido=texto)
                self.assertEqual(datos['estado'], 'no_soportado')
                self.assertEqual(datos['motivo'], 'datos_invalidos')

    def test_precedencia_y_fallback_solo_si_ausente(self):
        with tempfile.TemporaryDirectory() as temporal:
            etc, usr = [Path(temporal) / n for n in ('etc-release', 'usr-release')]
            usr.write_text('ID=debian\nVERSION_ID=13', encoding='utf-8')
            rutas = (etc, usr)
            self.assertEqual(distro.detectar_distribucion(rutas=rutas)['origen'], str(usr))
            etc.write_text('ID=fedora\nVERSION_ID=44', encoding='utf-8')
            self.assertEqual(distro.detectar_distribucion(rutas=rutas)['id'], 'fedora')
            for texto in ('invalido', 'ID=otra\nVERSION_ID=1'):
                etc.write_text(texto, encoding='utf-8')
                datos = distro.detectar_distribucion(rutas=rutas)
                self.assertEqual(datos['origen'], str(etc))
                self.assertEqual(datos['estado'], 'no_soportado')

    def test_ausentes_y_lectura_denegada(self):
        consultadas = []
        def ausente(ruta, *args, **kwargs):
            consultadas.append(str(ruta))
            raise FileNotFoundError()
        with patch.object(Path, 'open', autospec=True, side_effect=ausente):
            datos = distro.detectar_distribucion()
            self.assertEqual(datos['motivo'], 'archivos_ausentes')
            self.assertEqual(consultadas, ['/etc/os-release', '/usr/lib/os-release'])
        for error in (PermissionError(), UnicodeError()):
            with self.subTest(error=error), patch.object(Path, 'open', side_effect=error) as abrir:
                self.assertEqual(distro.detectar_distribucion()['motivo'], 'lectura_no_disponible')
                self.assertEqual(abrir.call_count, 1)

    def test_no_ejecuta_expansiones(self):
        datos = distro.detectar_distribucion(contenido='ID=debian\nVERSION_ID=13\nNAME="$(touch /tmp/no-ejecutar)"')
        self.assertEqual(datos['estado'], 'soportado')

    def test_entradas_excluyentes(self):
        with self.assertRaises(ValueError):
            distro.detectar_distribucion(contenido='ID=fedora', rutas=())
