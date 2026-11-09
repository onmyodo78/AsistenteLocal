"""Programación e interfaz APT: solo trazas y transacciones simuladas."""
import copy
import contextlib
import fcntl
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import auditoria_basica
import auditoria_semanal as semanal
import cli
import mantenimiento_apt
from test_auditoria_basica import Herramientas, Reloj, distro
from test_ejecucion_apt import plan


class Programacion(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.raiz = Path(self.tmp.name) / 'informes'
        self.h = Herramientas()
        self.traza = auditoria_basica.Coordinador(herramientas=self.h, detectar=distro, reloj=Reloj()).ejecutar()
        self.pila = contextlib.ExitStack(); self.addCleanup(self.pila.close)
        self.pila.enter_context(patch('os.geteuid', return_value=1000))
        # El sandbox puede mapear propietarios de / y /tmp a nobody. Simular
        # ancestros del sistema root, sin modificar el sistema ni rebajar producción.
        lstat = Path.lstat
        def propietario_sistema(path, *a, **kw):
            st = lstat(path, *a, **kw)
            if path in (Path('/'), Path('/tmp')):
                valores = list(st); valores[4] = 0
                return os.stat_result(valores)
            return st
        self.pila.enter_context(patch.object(Path, 'lstat', propietario_sistema))
        self.auditar = self.pila.enter_context(patch('auditoria_basica.auditar', return_value=self.traza))
        self.pila.enter_context(patch('subprocess.Popen', side_effect=AssertionError('Proceso real prohibido')))

    def test_guarda_traza_original_y_texto_en_privado_sin_repetir(self):
        original = copy.deepcopy(self.traza)
        r = semanal.ejecutar(self.raiz)
        d = Path(r['directorio'])
        self.assertEqual(r['estado'], self.traza[-1]['estado'])
        self.assertEqual(json.loads((d/'traza.json').read_text()), original)
        self.assertEqual(self.traza, original)
        self.assertIn('P3', (d/'informe.txt').read_text())
        self.assertEqual(d.stat().st_mode & 0o777, 0o700)
        self.assertEqual((d/'traza.json').stat().st_mode & 0o777, 0o600)
        self.assertFalse(list(self.raiz.glob('.en-curso-*')))
        self.auditar.assert_called_once_with()

    def test_concurrencia_no_adquiere_ni_borra_el_bloqueo(self):
        semanal.directorio_privado(self.raiz)
        lock = self.raiz/'.auditoria.lock'
        fd = os.open(lock, os.O_CREAT|os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX|fcntl.LOCK_NB)
            r = semanal.ejecutar(self.raiz)
            self.assertEqual(r['motivo'], 'ejecucion_en_curso')
            self.auditar.assert_not_called()
        finally:
            os.close(fd)
        self.assertTrue(lock.exists())

    def test_parcial_conserva_desconocidos_y_codigo_cli(self):
        h = Herramientas(); h.ausentes.add('memoria')
        self.traza = auditoria_basica.Coordinador(herramientas=h, detectar=distro, reloj=Reloj()).ejecutar()
        self.auditar.return_value = self.traza
        with contextlib.redirect_stdout(io.StringIO()) as out:
            code = cli.main(['--formato','json','auditoria-semanal','--directorio',str(self.raiz)])
        r = json.loads(out.getvalue())
        self.assertEqual(code, 3)
        self.assertEqual(json.loads((Path(r['directorio'])/'traza.json').read_text()), self.traza)

    def test_contrato_invalido_o_error_no_publica_informe_correcto(self):
        for value in ([], [dict(tipo='cierre', estado='completo')]):
            self.auditar.return_value = value
            with self.assertRaises((ValueError, KeyError)):
                semanal.ejecutar(self.raiz)
            self.assertEqual([p.name for p in self.raiz.iterdir()], ['.auditoria.lock'])
        self.auditar.side_effect = RuntimeError('fallo simulado')
        with self.assertRaises(RuntimeError):semanal.ejecutar(self.raiz)

    def test_fallo_publicacion_no_deja_temporales_y_no_toca_informe_previo(self):
        previo = Path(semanal.ejecutar(self.raiz)['directorio'])
        contenido = (previo/'traza.json').read_bytes()
        with patch.object(semanal.os, 'rename', side_effect=OSError('simulado')):
            with self.assertRaises(OSError):semanal.ejecutar(self.raiz)
        self.assertEqual((previo/'traza.json').read_bytes(), contenido)
        self.assertFalse(list(self.raiz.glob('.en-curso-*')))

    def test_rechaza_permisos_y_enlaces_antes_de_adquirir(self):
        self.raiz.mkdir(mode=0o755)
        with self.assertRaises(ValueError):semanal.ejecutar(self.raiz)
        self.raiz.chmod(0o700)
        (self.raiz/'.auditoria.lock').symlink_to(Path(self.tmp.name)/'otro')
        with self.assertRaises(OSError):semanal.ejecutar(self.raiz)
        self.auditar.assert_not_called()
        abierto=Path(self.tmp.name)/'abierto'; abierto.mkdir(); abierto.chmod(0o777)
        with self.assertRaises(ValueError):semanal.ejecutar(abierto/'informes')
        enlace=Path(self.tmp.name)/'enlace'; enlace.symlink_to(self.raiz, target_is_directory=True)
        with self.assertRaises(ValueError):semanal.ejecutar(enlace)

    def test_dos_ejecuciones_conservan_ambos_informes(self):
        a = semanal.ejecutar(self.raiz); b = semanal.ejecutar(self.raiz)
        self.assertNotEqual(a['directorio'], b['directorio'])
        self.assertTrue(Path(a['directorio']).is_dir())
        self.assertTrue(Path(b['directorio']).is_dir())

    def test_unidades_sin_instalar_activar_ni_privilegios(self):
        r = semanal.unidades('/tmp/prueba con % y $/informes')
        servicio = r['asistentelocal-auditoria.service']
        self.assertIn('%%', servicio); self.assertIn('$$', servicio)
        self.assertIn('NoNewPrivileges=true', servicio)
        self.assertNotIn('sudo', servicio)
        self.assertNotIn('WantedBy', servicio)
        self.assertIn('OnCalendar=weekly', r['asistentelocal-auditoria.timer'])
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(cli.main(['--formato','json','unidades-auditoria-semanal','--directorio','/tmp/prueba con % y $/informes']),0)
        self.assertEqual(json.loads(out.getvalue()),r)
        self.auditar.assert_not_called()
        with self.assertRaises(ValueError):semanal.unidades('relativa')
        with self.assertRaises(ValueError):semanal.unidades('/tmp/invalida\nExecStart=otro')


class EntradaAPT(unittest.TestCase):
    def test_lectura_delega_sin_terminal_ni_importar_modelo(self):
        with patch('cli.main', return_value=3) as main, patch.object(mantenimiento_apt.os,'open',side_effect=AssertionError('TTY inesperado')):
            self.assertEqual(mantenimiento_apt.main(['--formato','json','plan']), 3)
            main.assert_called_once_with(['--formato','json','plan'])

    def test_administracion_sin_terminal_no_invoca_cliente(self):
        for op in ('descargar-apt','actualizar-apt','historial-apt'):
            with patch.object(mantenimiento_apt.os,'open',side_effect=OSError('sin tty')), patch('cli.main') as main, contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(mantenimiento_apt.main([op]),1)
                main.assert_not_called()

    def test_plan_y_respuesta_del_helper_se_conservan_sin_reintento(self):
        for estado,error in [('completo',None),('cancelado','confirmacion_rechazada'),('cancelado','plan_modificado'),('resultado_desconocido','ejecucion_fallida')]:
            p=plan(); resultado=dict(version=1,estado=estado,error=error)
            with patch('os.geteuid',return_value=1000), patch.object(mantenimiento_apt.os,'open',return_value=123), patch.object(mantenimiento_apt.os,'isatty',return_value=True), patch.object(mantenimiento_apt.os,'close'), patch('cli.consultar',return_value=p) as consultar, patch('cliente_ejecucion_apt.actualizar',return_value=resultado) as actualizar, contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()):
                code=mantenimiento_apt.main(['--formato','json','actualizar-apt'])
            self.assertEqual(code,0 if estado=='completo' else 1)
            self.assertEqual(json.loads(out.getvalue()),resultado)
            consultar.assert_called_once_with('plan'); actualizar.assert_called_once_with(p)

    def test_comandos_libres_rechazados(self):
        with patch('cli.main') as main, contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):mantenimiento_apt.main(['apt-get upgrade'])
            main.assert_not_called()
