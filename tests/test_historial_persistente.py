"""Todos los archivos de prueba están dentro de TemporaryDirectory."""
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
import unittest
from unittest.mock import patch

import historial_controlador as c
import historial_persistente as p
from historial_sqlite import HistorialMemoria, ErrorHistorial
from test_historial_sqlite import auditoria, resultado


class PersistenciaLocal(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)/'datos'
        self.destino = p.HistorialPersistente(base_datos=self.base)
        self.control = c.ControladorHistorial(self.destino, reloj=lambda: self.ahora)
        self.ahora = 100.
        self.control.activar()
        self.addCleanup(self.control.cerrar)
        self.archivo = self.base/'AsistenteLocal'/p.NOMBRE

    def preparar(self):
        ident = self.control.preparar(auditoria(), [resultado()])
        return ident, self.control.confirmar(ident, self.control.vista_previa(ident), confirmacion=True)

    def guardar(self):
        ident, token = self.preparar()
        return self.control.guardar(ident, token)

    def test_constructor_disponibilidad_vista_sin_crear(self):
        self.assertFalse(self.destino.disponible())
        self.assertEqual(self.destino.listar_auditorias(), [])
        ident, _ = self.preparar()
        self.assertTrue(self.control.vista_previa(ident)['persistencia_disco'])
        self.assertFalse(self.base.exists())

    def test_guardado_lectura_y_permisos(self):
        aid = self.guardar()
        self.assertEqual(stat.S_IMODE(self.archivo.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.archivo.parent.stat().st_mode), 0o700)
        self.assertTrue(self.destino.disponible())
        self.assertEqual(self.destino.consultar_resultados(aid)[0]['registro'], resultado())
        self.assertEqual(len(self.destino.listar_auditorias()), 1)
        self.assertEqual(self.destino.consultar_eventos(aid), [])
        self.assertEqual(sorted(x.name for x in self.archivo.parent.iterdir()), ['.historial.lock', p.NOMBRE])

    def test_formato_sqlite_y_integridad(self):
        self.guardar()
        con = sqlite3.connect(self.archivo)
        try:
            self.assertEqual(con.execute('PRAGMA integrity_check').fetchall(), [('ok',)])
            self.assertEqual(con.execute('PRAGMA user_version').fetchone()[0], 1)
            self.assertEqual(con.execute('PRAGMA foreign_key_check').fetchall(), [])
        finally:
            con.close()

    def test_segundo_controlador_carga_base_y_agrega(self):
        self.guardar()
        control = c.ControladorHistorial(p.HistorialPersistente(base_datos=self.base))
        control.activar()
        try:
            a = auditoria()
            a['fin_utc'] = '2026-11-05T12:02:00Z'
            ident = control.preparar(a, [resultado()])
            token = control.confirmar(ident, control.vista_previa(ident), confirmacion=True)
            control.guardar(ident, token)
        finally:
            control.cerrar()
        self.assertEqual(len(self.destino.listar_auditorias()), 2)

    def test_llamada_directa_sin_permiso_no_crea(self):
        for f in (lambda: self.destino.guardar_auditoria(auditoria(), [resultado()]),
                  lambda: self.destino._guardar_autorizado(object()),
                  lambda: self.destino._guardar_autorizado('manual')):
            with self.assertRaises((ErrorHistorial, c.ErrorControlador)):
                f()
        self.assertFalse(self.base.exists())

    def test_caducada_cancelada_revocada_consumida(self):
        ident, token = self.preparar()
        self.ahora = 500
        with self.assertRaises(c.ErrorControlador):
            self.control.guardar(ident, token)
        self.assertFalse(self.base.exists())
        self.ahora = 100
        ident, token = self.preparar()
        self.control.cancelar(ident)
        with self.assertRaises(c.ErrorControlador):
            self.control.guardar(ident, token)
        ident, token = self.preparar()
        self.control.reemplazar(ident, auditoria(), [resultado()])
        with self.assertRaises(c.ErrorControlador):
            self.control.guardar(ident, token)
        self.assertFalse(self.base.exists())
        aid = self.guardar()
        antes = self.archivo.read_bytes()
        with self.assertRaises(c.ErrorControlador):
            self.control.guardar(ident, token)
        self.assertEqual(self.archivo.read_bytes(), antes)
        self.assertEqual(len(self.destino.consultar_resultados(aid)), 1)

    def test_xdg_y_fallback_no_crean(self):
        with patch.dict(os.environ, XDG_DATA_HOME=str(self.base)):
            destino = p.HistorialPersistente()
            self.assertEqual(destino._ruta, self.base/'AsistenteLocal')
        with patch.dict(os.environ, XDG_DATA_HOME='relativo'), patch.object(p.Path, 'home', return_value=Path(self.tmp.name)):
            destino = p.HistorialPersistente()
            self.assertEqual(destino._ruta, Path(self.tmp.name)/'.local/share/AsistenteLocal')
        self.assertEqual(list(Path(self.tmp.name).iterdir()), [])
        for base in ('relativo', '/', self.base/'..'/'otra'):
            with self.assertRaises(ErrorHistorial):
                p.HistorialPersistente(base_datos=base)

    def test_enlace_directorio_rechazado(self):
        otro = Path(self.tmp.name)/'otro'
        otro.mkdir(mode=0o700)
        self.base.symlink_to(otro, target_is_directory=True)
        with self.assertRaises(c.ErrorControlador):
            self.guardar()
        self.assertEqual(list(otro.iterdir()), [])

    def test_enlace_base_y_hardlink_rechazados(self):
        self.archivo.parent.mkdir(parents=True, mode=0o700)
        otro = Path(self.tmp.name)/'otro'
        otro.write_bytes(b'original')
        self.archivo.symlink_to(otro)
        with self.assertRaises(c.ErrorControlador):
            self.guardar()
        self.assertEqual(otro.read_bytes(), b'original')
        self.archivo.unlink()
        os.link(otro, self.archivo)
        otro.chmod(0o600)
        with self.assertRaises(c.ErrorControlador):
            self.guardar()
        self.assertEqual(otro.read_bytes(), b'original')

    def test_permisos_existentes_no_se_corrigen(self):
        self.archivo.parent.mkdir(parents=True, mode=0o755)
        self.archivo.parent.chmod(0o755)
        with self.assertRaises(c.ErrorControlador):
            self.guardar()
        self.assertEqual(stat.S_IMODE(self.archivo.parent.stat().st_mode), 0o755)
        self.assertFalse(self.archivo.exists())

    def test_bases_corruptas_futuras_y_esquema_ajeno_no_se_sobrescriben(self):
        self.archivo.parent.mkdir(parents=True, mode=0o700)
        for version in (None, 0, 2):
            if version is None:
                contenido = b'base corrupta'
            else:
                with HistorialMemoria() as motor:
                    motor._conexion.execute('PRAGMA user_version='+str(version))
                    contenido = motor._conexion.serialize()
            self.archivo.write_bytes(contenido)
            self.archivo.chmod(0o600)
            with self.assertRaises(c.ErrorControlador):
                self.guardar()
            self.assertEqual(self.archivo.read_bytes(), contenido)
        with HistorialMemoria() as motor:
            motor._conexion.execute('CREATE TABLE ajena(dato TEXT)')
            contenido = motor._conexion.serialize()
        self.archivo.write_bytes(contenido)
        with self.assertRaises(c.ErrorControlador):
            self.guardar()
        self.assertEqual(self.archivo.read_bytes(), contenido)

    def test_fallo_publicacion_conserva_base_y_limpia_temporal(self):
        self.guardar()
        antes = self.archivo.read_bytes()
        a = auditoria()
        a['fin_utc'] = '2026-11-05T12:03:00Z'
        ident = self.control.preparar(a, [resultado()])
        token = self.control.confirmar(ident, self.control.vista_previa(ident), confirmacion=True)
        with patch.object(p.os, 'replace', side_effect=PermissionError('privado')):
            with self.assertRaises(c.ErrorControlador):
                self.control.guardar(ident, token)
        self.assertEqual(self.archivo.read_bytes(), antes)
        self.assertFalse(list(self.archivo.parent.glob('*.tmp')))
        self.assertEqual(len(self.destino.listar_auditorias()), 1)

    def test_error_acceso_sin_crear(self):
        with patch.object(p.os, 'open', side_effect=PermissionError('privado')):
            with self.assertRaisesRegex(c.ErrorControlador, '^guardado_fallido$'):
                self.guardar()
        self.assertFalse(self.base.exists())

    def test_sustitucion_entrada_detectada(self):
        self.guardar()
        a = auditoria()
        a['fin_utc'] = '2026-11-05T12:04:00Z'
        ident = self.control.preparar(a, [resultado()])
        token = self.control.confirmar(ident, self.control.vista_previa(ident), confirmacion=True)
        original = p.os.fsync
        def sustituir(fd):
            original(fd)
            self.archivo.unlink()
            self.archivo.symlink_to('/no-se-abre')
        with patch.object(p.os, 'fsync', side_effect=sustituir):
            with self.assertRaises(c.ErrorControlador):
                self.control.guardar(ident, token)
        self.assertTrue(self.archivo.is_symlink())

    def test_consultas_no_cambian_bytes_ni_crean_auxiliares(self):
        aid = self.guardar()
        antes = self.archivo.read_bytes()
        entradas = sorted(x.name for x in self.archivo.parent.iterdir())
        self.destino.listar_auditorias()
        self.destino.consultar_resultados(aid)
        self.destino.consultar_eventos(aid)
        self.destino.disponible()
        self.assertEqual(self.archivo.read_bytes(), antes)
        self.assertEqual(sorted(x.name for x in self.archivo.parent.iterdir()), entradas)

    def test_token_consumido_y_cambio_destino_no_escriben(self):
        ident, token = self.preparar()
        self.control.guardar(ident, token)
        antes = self.archivo.read_bytes()
        with self.assertRaises(c.ErrorControlador):
            self.control.guardar(ident, token)
        self.assertEqual(self.archivo.read_bytes(), antes)
        a = auditoria()
        a['fin_utc'] = '2026-11-05T12:05:00Z'
        ident = self.control.preparar(a, [resultado()])
        token = self.control.confirmar(ident, self.control.vista_previa(ident), confirmacion=True)
        self.destino._ruta = Path(self.tmp.name)/'distinto'
        with self.assertRaises(c.ErrorControlador):
            self.control.guardar(ident, token)
        self.assertFalse(self.destino._ruta.exists())

    def test_fallo_escritura_no_publica_base(self):
        with patch.object(p.os, 'write', side_effect=OSError('privado')):
            with self.assertRaises(c.ErrorControlador):
                self.guardar()
        self.assertFalse(self.archivo.exists())
        self.assertFalse(list(self.archivo.parent.glob('*.tmp')))

    def test_fsync_directorio_incierto_no_permite_repetir(self):
        ident, token = self.preparar()
        original = p.os.fsync
        def sincronizar(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError('privado')
            return original(fd)
        with patch.object(p.os, 'fsync', side_effect=sincronizar):
            with self.assertRaisesRegex(c.ErrorControlador, '^publicado_durabilidad_no_confirmada$'):
                self.control.guardar(ident, token)
        self.assertTrue(self.archivo.exists())
        with self.assertRaises(c.ErrorControlador):
            self.control.guardar(ident, token)
        with self.assertRaises(c.ErrorControlador):
            self.preparar()

    def test_archivo_permisivo_rechazado_sin_chmod(self):
        self.guardar()
        antes = self.archivo.read_bytes()
        self.archivo.chmod(0o644)
        a = auditoria()
        a['fin_utc'] = '2026-11-05T12:06:00Z'
        ident = self.control.preparar(a, [resultado()])
        token = self.control.confirmar(ident, self.control.vista_previa(ident), confirmacion=True)
        with self.assertRaises(c.ErrorControlador):
            self.control.guardar(ident, token)
        self.assertEqual(stat.S_IMODE(self.archivo.stat().st_mode), 0o644)
        self.assertEqual(self.archivo.read_bytes(), antes)

    def test_contenido_preexistente_invalido_no_se_publica(self):
        self.guardar()
        con = sqlite3.connect(self.archivo)
        con.execute("UPDATE auditorias SET guardado_utc='usuario-privado'")
        con.commit()
        con.close()
        antes = self.archivo.read_bytes()
        with self.assertRaises(ErrorHistorial):
            self.destino.listar_auditorias()
        a = auditoria()
        a['fin_utc'] = '2026-11-05T12:07:00Z'
        ident = self.control.preparar(a, [resultado()])
        token = self.control.confirmar(ident, self.control.vista_previa(ident), confirmacion=True)
        with self.assertRaises(c.ErrorControlador):
            self.control.guardar(ident, token)
        self.assertEqual(self.archivo.read_bytes(), antes)
