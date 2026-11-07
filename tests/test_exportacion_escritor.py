"""Escrituras únicamente dentro de TemporaryDirectory; sin adquisiciones."""
import builtins
from pathlib import Path
import os
import stat
import tempfile
import unittest
from unittest.mock import patch

import exportacion_escritor as e
import exportacion_controlador as c
from exportacion_generadores import generar_csv, generar_markdown
from test_informe_exportacion import informe


class Escritor(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.raiz = Path(self.tmp.name)
        self.ahora = 100.
        self.control = c.ControladorExportacion(reloj=lambda: self.ahora)
        self.control.activar()
        self.addCleanup(self.control.desactivar)

    def preparar(self, formato='md', nombre=None):
        ruta = self.raiz/(nombre or 'informe.'+formato)
        ident = self.control.preparar(informe(), formato=formato, destino=str(ruta))
        token = self.control.confirmar(ident, self.control.vista_previa(ident), confirmacion=True)
        return ruta, ident, token

    def test_md_y_csv_bytes_exactos_y_permisos(self):
        for formato, generador in (('md', generar_markdown), ('csv', generar_csv)):
            ruta, ident, token = self.preparar(formato)
            resultado = e.publicar(self.control, ident, token)
            self.assertEqual(ruta.read_bytes(), generador(informe()))
            self.assertEqual(stat.S_IMODE(ruta.stat().st_mode), 0o600)
            self.assertEqual(resultado['bytes'], ruta.stat().st_size)
            self.assertTrue(resultado['contenido_verificado'])
        self.assertEqual(sorted(p.name for p in self.raiz.iterdir()), ['informe.csv', 'informe.md'])

    def test_existente_no_sobrescrito(self):
        ruta, ident, token = self.preparar()
        ruta.write_bytes(b'original')
        with self.assertRaisesRegex(e.ErrorEscritura, '^destino_existente$'):
            e.publicar(self.control, ident, token)
        self.assertEqual(ruta.read_bytes(), b'original')
        self.assertEqual(len(list(self.raiz.iterdir())), 1)

    def test_symlink_destino_no_se_sigue(self):
        otro = self.raiz/'otro'
        otro.write_bytes(b'original')
        ruta, ident, token = self.preparar()
        ruta.symlink_to(otro)
        with self.assertRaises(e.ErrorEscritura):
            e.publicar(self.control, ident, token)
        self.assertEqual(otro.read_bytes(), b'original')
        self.assertTrue(ruta.is_symlink())

    def test_symlink_directorio_y_ausente_rechazados_sin_crear(self):
        real = self.raiz/'real'
        real.mkdir()
        enlace = self.raiz/'enlace'
        enlace.symlink_to(real, target_is_directory=True)
        for padre in (enlace, self.raiz/'ausente'):
            ident = self.control.preparar(informe(), formato='md', destino=str(padre/'informe.md'))
            token = self.control.confirmar(ident, self.control.vista_previa(ident), confirmacion=True)
            with self.assertRaises(e.ErrorEscritura):
                e.publicar(self.control, ident, token)
        self.assertEqual(list(real.iterdir()), [])
        self.assertFalse((self.raiz/'ausente').exists())

    def test_json_relativos_extensiones_y_entrega_directa_rechazados(self):
        for formato, ruta in (('json', self.raiz/'informe.json'), ('md', self.raiz/'informe.csv'),
                               ('md', Path('informe.md')), ('md', self.raiz/'..'/'informe.md')):
            with self.assertRaises(c.ErrorExportacion):
                self.control.preparar(informe(), formato=formato, destino=str(ruta))
        entrega = c.EntregaExportacion('md', str(self.raiz/'informe.md'), b'privado')
        with self.assertRaises(e.ErrorEscritura):
            e.publicar(entrega, 'id', object())
        self.assertEqual(list(self.raiz.iterdir()), [])

    def test_caducada_cancelada_revocada_no_crean(self):
        ruta, ident, token = self.preparar()
        self.ahora = 400.
        with self.assertRaises(e.ErrorEscritura):
            e.publicar(self.control, ident, token)
        self.ahora = 100.
        ruta, ident, token = self.preparar()
        self.control.cancelar(ident)
        with self.assertRaises(e.ErrorEscritura):
            e.publicar(self.control, ident, token)
        ruta, ident, token = self.preparar()
        self.control.reemplazar(ident, informe(), formato='csv', destino=str(self.raiz/'otro.csv'))
        with self.assertRaises(e.ErrorEscritura):
            e.publicar(self.control, ident, token)
        self.assertEqual(list(self.raiz.iterdir()), [])

    def test_consumida_y_doble_publicacion(self):
        ruta, ident, token = self.preparar()
        e.publicar(self.control, ident, token)
        antes = ruta.read_bytes()
        with self.assertRaises(e.ErrorEscritura):
            e.publicar(self.control, ident, token)
        self.assertEqual(ruta.read_bytes(), antes)
        ruta2, ident2, token2 = self.preparar(nombre='otro.md')
        self.control.consumir(ident2, token2)
        with self.assertRaises(e.ErrorEscritura):
            e.publicar(self.control, ident2, token2)
        self.assertFalse(ruta2.exists())

    def test_sustitucion_interna_contenido_o_destino_invalida(self):
        for campo, valor in (('contenido', b'contenido alterado'),
                             ('destino', str(self.raiz/'otro.md')), ('formato', 'csv')):
            ruta, ident, token = self.preparar()
            self.control._preparadas[ident][campo] = valor
            with self.assertRaises(e.ErrorEscritura):
                e.publicar(self.control, ident, token)
        self.assertEqual(list(self.raiz.iterdir()), [])

    def test_fallo_escritura_limpia_sin_informe_parcial(self):
        ruta, ident, token = self.preparar()
        original = e.os.write
        llamadas = []
        def escribir(fd, bloque):
            if llamadas:
                raise OSError('/privado error sensible')
            llamadas.append(1)
            return original(fd, bloque[:10])
        with patch.object(e.os, 'write', side_effect=escribir):
            with self.assertRaisesRegex(e.ErrorEscritura, '^escritura_fallida$'):
                e.publicar(self.control, ident, token)
        self.assertFalse(ruta.exists())
        self.assertEqual(list(self.raiz.iterdir()), [])
        with self.assertRaises(e.ErrorEscritura):
            e.publicar(self.control, ident, token)

    def test_verificacion_contenido_detecta_corrupcion(self):
        ruta, ident, token = self.preparar()
        with patch.object(e.os, 'read', return_value=b'corrupcion'):
            with self.assertRaisesRegex(e.ErrorEscritura, '^verificacion_fallida$'):
                e.publicar(self.control, ident, token)
        self.assertEqual(list(self.raiz.iterdir()), [])

    def test_carrera_destino_creado_antes_link_no_reemplaza(self):
        ruta, ident, token = self.preparar()
        original = e.os.link
        def enlazar(*args, **kw):
            ruta.write_bytes(b'ganador carrera')
            return original(*args, **kw)
        with patch.object(e, '_plataforma'), patch.object(e.os, 'link', side_effect=enlazar):
            with self.assertRaisesRegex(e.ErrorEscritura, '^destino_existente$'):
                e.publicar(self.control, ident, token)
        self.assertEqual(ruta.read_bytes(), b'ganador carrera')
        self.assertEqual(len(list(self.raiz.iterdir())), 1)

    def test_carrera_directorio_sustituido_antes_publicar(self):
        padre = self.raiz/'padre'
        padre.mkdir(mode=0o700)
        ruta = padre/'informe.md'
        ident = self.control.preparar(informe(), formato='md', destino=str(ruta))
        token = self.control.confirmar(ident, self.control.vista_previa(ident), confirmacion=True)
        verificar = e._verificar
        def sustituir(fd, contenido):
            verificar(fd, contenido)
            padre.rename(self.raiz/'movido')
            padre.mkdir(mode=0o700)
        with patch.object(e, '_verificar', side_effect=sustituir):
            with self.assertRaisesRegex(e.ErrorEscritura, '^directorio_sustituido$'):
                e.publicar(self.control, ident, token)
        self.assertEqual(list(padre.iterdir()), [])
        self.assertEqual(list((self.raiz/'movido').iterdir()), [])

    def test_sistema_sin_link_seguro_rechaza_sin_fallback(self):
        ruta, ident, token = self.preparar()
        with patch.object(e, '_plataforma'), patch.object(e.os, 'link', side_effect=OSError('no soportado')):
            with self.assertRaises(e.ErrorEscritura):
                e.publicar(self.control, ident, token)
        self.assertEqual(list(self.raiz.iterdir()), [])

    def test_limite_y_expiracion_durante_escritura(self):
        ruta, ident, token = self.preparar()
        with patch.object(e, 'MAX_REPRESENTACION_BYTES', 1):
            with self.assertRaises(e.ErrorEscritura):
                e.publicar(self.control, ident, token)
        self.assertEqual(list(self.raiz.iterdir()), [])
        ruta, ident, token = self.preparar()
        verificar = e._verificar
        def caducar(fd, contenido):
            verificar(fd, contenido)
            self.ahora = 400.
        with patch.object(e, '_verificar', side_effect=caducar):
            with self.assertRaisesRegex(e.ErrorEscritura, '^autorizacion_no_vigente$'):
                e.publicar(self.control, ident, token)
        self.assertEqual(list(self.raiz.iterdir()), [])

    def test_permisos_con_umask_restrictiva(self):
        ruta, ident, token = self.preparar()
        anterior = os.umask(0o777)
        try:
            e.publicar(self.control, ident, token)
        finally:
            os.umask(anterior)
        self.assertEqual(stat.S_IMODE(ruta.stat().st_mode), 0o600)

    def test_fallo_fsync_antes_y_despues_publicacion(self):
        ruta, ident, token = self.preparar()
        with patch.object(e.os, 'fsync', side_effect=OSError('privado')):
            with self.assertRaises(e.ErrorEscritura):
                e.publicar(self.control, ident, token)
        self.assertEqual(list(self.raiz.iterdir()), [])
        ruta, ident, token = self.preparar()
        original = e.os.fsync
        def sincronizar(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError('privado')
            original(fd)
        with patch.object(e.os, 'fsync', side_effect=sincronizar):
            with self.assertRaisesRegex(e.ErrorEscritura, '^publicado_finalizacion_no_confirmada$'):
                e.publicar(self.control, ident, token)
        self.assertEqual(ruta.read_bytes(), generar_markdown(informe()))
        with self.assertRaises(e.ErrorEscritura):
            e.publicar(self.control, ident, token)

    def test_sin_sqlite_ni_adquisiciones(self):
        ruta, ident, token = self.preparar()
        importar = builtins.__import__
        def comprobar(nombre, *a, **kw):
            if 'sqlite' in nombre or nombre in ('historial_persistente', 'historial_controlador'):
                raise AssertionError('sqlite')
            return importar(nombre, *a, **kw)
        with patch('builtins.__import__', side_effect=comprobar), \
             patch('subprocess.Popen', side_effect=AssertionError('adquisicion')):
            e.publicar(self.control, ident, token)
        self.assertTrue(ruta.exists())
