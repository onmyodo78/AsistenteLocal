"""Despliegue sintético sin root, APT ni acceso a destinos del sistema."""
import hashlib
import os
from pathlib import Path
import tempfile
import subprocess
import sys
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import despliegue_helper_apt as d


class Antecesores(unittest.TestCase):
    def info(self, modo=0o755, uid=0, gid=0, tipo=stat.S_IFDIR):
        return SimpleNamespace(st_mode=tipo | modo, st_uid=uid, st_gid=gid)

    def recorrer(self, infos):
        with patch.object(d.os, 'open', side_effect=range(10, 20)) as abrir, \
                patch.object(d.os, 'fstat', side_effect=infos), \
                patch.object(d.os, 'close') as cerrar:
            d.verificar_antecesores('/usr/local/lib')
            self.assertEqual(cerrar.call_count, 4)
            self.assertTrue(all(c.args[1] & os.O_NOFOLLOW for c in abrir.call_args_list))
            self.assertTrue(all(c.args[1] & os.O_DIRECTORY for c in abrir.call_args_list))

    def test_raiz_0555_y_antecesores_protegidos_sin_modo_exacto(self):
        self.recorrer([self.info(m) for m in (0o555, 0o755, 0o711, 0o555)])

    def test_rechaza_propiedad_tipo_escritura_bits_y_falta_recorrido(self):
        casos = [self.info(uid=1000), self.info(gid=1000),
                 self.info(tipo=stat.S_IFREG), self.info(tipo=stat.S_IFLNK)]
        casos += [self.info(m) for m in (0o775, 0o757, 0o1777, 0o2755, 0o4755, 0o644)]
        for info in casos:
            for posicion in range(4):
                with self.subTest(info=info, posicion=posicion):
                    with self.assertRaises(ValueError):
                        self.recorrer([self.info()] * posicion + [info])

    def test_rutas_relativas_y_padre_ambiguo_no_se_abren(self):
        for ruta in ('usr/local/lib', '/usr/../lib'):
            with self.subTest(ruta=ruta), patch.object(d.os, 'open') as abrir:
                with self.assertRaises(ValueError):
                    d.verificar_antecesores(ruta)
                abrir.assert_not_called()

    def test_enlace_real_no_se_sigue_y_cierra_descriptor(self):
        with tempfile.TemporaryDirectory() as temporal:
            enlace = Path(temporal) / 'enlace'
            enlace.symlink_to('/usr', target_is_directory=True)
            # Simular solo metadatos para alcanzar el enlace bajo /tmp inseguro.
            with patch.object(d.os, 'fstat', return_value=self.info()):
                with self.assertRaises(OSError):
                    d.verificar_antecesores(enlace)

    def test_error_de_inspeccion_cierra_descriptor(self):
        with patch.object(d.os, 'open', return_value=42), \
                patch.object(d.os, 'fstat', side_effect=OSError('sin metadatos')), \
                patch.object(d.os, 'close') as cerrar:
            with self.assertRaises(OSError):
                d.verificar_antecesores('/')
            cerrar.assert_called_once_with(42)

    def test_directorio_publicado_conserva_modo_y_propietarios_exactos(self):
        for info in (self.info(0o555), self.info(uid=1000), self.info(gid=1000)):
            with self.subTest(info=info), patch.object(d.os, 'lstat', return_value=info):
                with self.assertRaises(ValueError):
                    d.verificar_directorio('/destino')


class Despliegue(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.base.chmod(0o755)
        self.fuente = self.base / 'fuente'
        self.fuente.mkdir()
        self.destino = self.base / 'instalado'
        self.manifiesto = self.base / 'manifiesto'
        lineas = []
        for nombre in d.MODULOS:
            datos = ('# ' + nombre + '\n').encode()
            (self.fuente / nombre).write_bytes(datos)
            lineas.append(hashlib.sha256(datos).hexdigest() + '  ' + nombre + '\n')
        self.manifiesto.write_text(''.join(lineas))
        self.digest = hashlib.sha256(self.manifiesto.read_bytes()).hexdigest()

    def ejecutar(self):
        return d.desplegar(self.fuente, self.manifiesto, self.digest,
                          self.destino, os.getuid())

    def test_publicacion_completa_y_verificacion_posterior(self):
        real = d.publicar_sin_reemplazar
        def publicar(origen, destino):
            self.assertFalse(destino.exists())
            self.assertEqual(origen.parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual((origen.parent / 'manifiesto.sha256').stat().st_mode & 0o777, 0o600)
            d.verificar_contenido(origen, d.interpretar_manifiesto(
                self.manifiesto.read_bytes(), self.digest), os.getuid())
            real(origen, destino)
        with patch.object(d, 'publicar_sin_reemplazar', side_effect=publicar):
            hashes = self.ejecutar()
        d.verificar_contenido(self.destino, hashes, os.getuid())
        self.assertEqual(list(self.base.glob('.asistentelocal-*')), [])

    def test_sustitucion_de_fuente_y_manifiesto_no_publica(self):
        for entrada in (self.fuente / d.MODULOS[0], self.manifiesto):
            with self.subTest(entrada=entrada):
                original = entrada.read_bytes()
                entrada.write_bytes(original + b'# cambio\n')
                with self.assertRaises(ValueError):
                    self.ejecutar()
                self.assertFalse(self.destino.exists())
                entrada.write_bytes(original)

    def test_ausente_enlace_y_bits_especiales_se_rechazan(self):
        archivo = self.fuente / d.MODULOS[0]
        original = archivo.read_bytes()
        for caso in ('ausente', 'enlace', 'permisos'):
            with self.subTest(caso=caso):
                archivo.unlink()
                if caso == 'enlace':
                    archivo.symlink_to(self.manifiesto)
                elif caso == 'permisos':
                    archivo.write_bytes(original)
                    archivo.chmod(0o4644)
                with self.assertRaises((OSError, ValueError)):
                    self.ejecutar()
                self.assertFalse(self.destino.exists())
                if os.path.lexists(archivo):
                    archivo.unlink()
                archivo.write_bytes(original)

    def test_fallo_copia_y_fallo_verificacion_no_publican(self):
        for funcion in ('leer_regular', 'verificar_contenido'):
            with self.subTest(funcion=funcion):
                with patch.object(d, funcion, side_effect=OSError('fallo simulado')):
                    with self.assertRaises(OSError):
                        self.ejecutar()
                self.assertFalse(self.destino.exists())
                self.assertEqual(list(self.base.glob('.asistentelocal-*')), [])

    def test_destino_concurrente_no_se_reemplaza(self):
        real = d.publicar_sin_reemplazar
        def competir(origen, destino):
            destino.mkdir()
            real(origen, destino)
        with patch.object(d, 'publicar_sin_reemplazar', side_effect=competir):
            with self.assertRaises(FileExistsError):
                self.ejecutar()
        self.assertEqual(list(self.destino.iterdir()), [])

    def test_manifiesto_duplicado_ajeno_o_incompleto_rechazado(self):
        original = self.manifiesto.read_bytes()
        for datos in (original + original.splitlines(keepends=True)[0],
                      original.replace(b'ejecutor_apt.py', b'../ejecutor_apt.py'),
                      b'\n'.join(original.splitlines()[1:])):
            with self.subTest(datos=datos):
                with self.assertRaises(ValueError):
                    d.interpretar_manifiesto(datos, hashlib.sha256(datos).hexdigest())

    def test_arranque_documentado_verifica_bytes_y_rechaza_enlaces(self):
        documento = (Path(d.__file__).parent / 'EJECUCION_APT.md').read_text()
        inicio = documento.index("sudo /usr/bin/python3 -I -S -B -c '\n")
        codigo = documento[inicio:].split("-c '\n", 1)[1].split("\n' ", 1)[0]
        script = self.base / 'prueba.py'
        script.write_text('print("ARRANQUE_VERIFICADO")\n')
        digest = hashlib.sha256(script.read_bytes()).hexdigest()
        def arrancar(ruta, esperado):
            return subprocess.run([sys.executable, '-I', '-S', '-B', '-c',
                                   codigo, str(ruta), esperado],
                                  capture_output=True, text=True, timeout=5)
        self.assertEqual(arrancar(script, digest).stdout.strip(), 'ARRANQUE_VERIFICADO')
        script.write_text('raise RuntimeError("NO EJECUTAR")\n')
        rechazo = arrancar(script, digest)
        self.assertNotEqual(rechazo.returncode, 0)
        self.assertNotIn('RuntimeError', rechazo.stderr)
        enlace = self.base / 'enlace'
        enlace.symlink_to(self.base, target_is_directory=True)
        self.assertNotEqual(arrancar(enlace / script.name, digest).returncode, 0)

    def test_error_posterior_no_declara_exito_ni_borra_publicacion(self):
        real = d.verificar_contenido
        def verificar(ruta, hashes, uid):
            if ruta == self.destino:
                raise ValueError('fallo posterior')
            real(ruta, hashes, uid)
        with patch.object(d, 'verificar_contenido', side_effect=verificar):
            with self.assertRaises(ValueError) as capturada:
                self.ejecutar()
            self.assertIn('Evidencia privada conservada', '\n'.join(capturada.exception.__notes__))
        self.assertEqual(set(os.listdir(self.destino)), set(d.MODULOS))

    def test_limpieza_fallida_no_oculta_error_original(self):
        original = ValueError('error primario de copia')
        real = d.abrir_directorio
        def abrir_fuente(ruta):
            if ruta == self.fuente:
                raise original
            return real(ruta)
        with patch.object(d, 'abrir_directorio', side_effect=abrir_fuente):
            with patch.object(d.shutil, 'rmtree', side_effect=OSError('limpieza fallida')):
                with self.assertRaises(ValueError) as capturada:
                    self.ejecutar()
        self.assertIs(capturada.exception, original)
        notas = '\n'.join(original.__notes__)
        self.assertIn('limpieza fallida', notas)
        self.assertIn(str(self.destino), notas)
        self.assertFalse(self.destino.exists())

    def test_error_posterior_conserva_manifiesto_y_no_intenta_limpiar(self):
        original = ValueError('verificación final fallida')
        real = d.verificar_contenido
        def verificar(ruta, hashes, uid):
            if ruta == self.destino:
                raise original
            return real(ruta, hashes, uid)
        with patch.object(d, 'verificar_contenido', side_effect=verificar), patch.object(d.shutil, 'rmtree') as limpiar:
            with self.assertRaises(ValueError) as capturada:
                self.ejecutar()
            limpiar.assert_not_called()
        self.assertIs(capturada.exception, original)
        temporal, = self.base.glob('.asistentelocal-despliegue-*')
        self.assertEqual((temporal / 'manifiesto.sha256').read_bytes(), self.manifiesto.read_bytes())
        self.assertIn(str(temporal), '\n'.join(original.__notes__))
        d.verificar_contenido(self.destino, d.interpretar_manifiesto(
            self.manifiesto.read_bytes(), self.digest), os.getuid())

    def test_limpieza_fallida_tras_exito_informa_sin_borrar_destino(self):
        with patch.object(d.shutil, 'rmtree', side_effect=OSError('limpieza fallida')):
            with self.assertRaises(OSError) as capturada:
                self.ejecutar()
        self.assertIn('publicado y verificado', '\n'.join(capturada.exception.__notes__))
        d.verificar_contenido(self.destino, d.interpretar_manifiesto(
            self.manifiesto.read_bytes(), self.digest), os.getuid())

    def test_interrupcion_inmediatamente_despues_de_rename_conserva_evidencia(self):
        real = d.publicar_sin_reemplazar
        def interrumpir(origen, destino):
            real(origen, destino)
            raise KeyboardInterrupt('interrupción tras rename')
        with patch.object(d, 'publicar_sin_reemplazar', side_effect=interrumpir), patch.object(d.shutil, 'rmtree') as limpiar:
            with self.assertRaises(KeyboardInterrupt) as capturada:
                self.ejecutar()
            limpiar.assert_not_called()
        self.assertIn('resultado incierto', '\n'.join(capturada.exception.__notes__))
        self.assertEqual(set(os.listdir(self.destino)), set(d.MODULOS))
        temporal, = self.base.glob('.asistentelocal-despliegue-*')
        self.assertTrue((temporal / 'manifiesto.sha256').is_file())


if __name__ == '__main__':
    unittest.main()
