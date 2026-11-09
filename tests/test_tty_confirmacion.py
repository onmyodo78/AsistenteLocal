"""Confirmación en TTY real, sin sudo ni operaciones administrativas."""
import contextlib
import io
import json
import os
from pathlib import Path
import pty
import select
import subprocess
import sys
import termios
import time
import unittest
from unittest.mock import patch

import autorizacion_apt as aut
import ejecutor_apt as helper

RAIZ = str(Path(__file__).resolve().parents[1])


class ConfirmacionTTY(unittest.TestCase):
    def ejecutar_pty(self, backend, respuesta='exacta', fallo=None):
        codigo = '''import os,fcntl,termios,sys,json,io
os.setsid()
fcntl.ioctl(0,termios.TIOCSCTTY,0)
sys.path.insert(0,sys.argv[1])
import autorizacion_apt as aut
import mantenimiento_dnf5 as fedora
import ejecutor_apt as apt
from unittest.mock import patch
p={'digest':'a'*64,'operacion':aut.OPERACION,'plan':{'huella':'b'*64,'simulacion':{'actualizaciones':[]}}}
modulo=apt if sys.argv[2]=='apt' else fedora
if sys.argv[2]=='dnf5':
 fedora.informe=lambda plan:'Consulta informativa de prueba'
frase=aut.frase(p) if sys.argv[2]=='apt' else fedora.frase(p)
fallo=sys.argv[3]
original=io.TextIOWrapper
class Fallo(original):
 def write(self,texto):
  if fallo=='escritura':raise OSError('DETALLE_PRIVADO_ESCRITURA')
  return super().write(texto)
 def readline(self,*args):
  if fallo=='lectura':raise OSError('DETALLE_PRIVADO_LECTURA')
  return super().readline(*args)
try:
 with patch.object(io,'TextIOWrapper',Fallo):
  resultado=modulo.confirmar_tty(p)
 print('RESULTADO='+json.dumps({'aceptado':resultado}),flush=True)
except ValueError as e:
 print('RESULTADO='+json.dumps({'error':str(e)}),flush=True)
'''
        maestro, esclavo = pty.openpty()
        atributos = termios.tcgetattr(esclavo)
        atributos[3] &= ~termios.ECHO
        termios.tcsetattr(esclavo, termios.TCSANOW, atributos)
        try:
            proceso = subprocess.Popen([sys.executable, '-I', '-S', '-B', '-c',
                                        codigo, RAIZ, backend, fallo or ''],
                                       stdin=esclavo, stdout=esclavo, stderr=esclavo)
        finally:
            os.close(esclavo)
        datos = b''
        enviado = False
        limite = time.monotonic() + 10
        try:
            while time.monotonic() < limite:
                if select.select([maestro], [], [], 0.1)[0]:
                    try:
                        bloque = os.read(maestro, 65536)
                    except OSError:
                        break
                    if not bloque:
                        break
                    datos += bloque
                    if b'> ' in datos and not enviado and fallo != 'lectura':
                        frase = ('AUTORIZAR APT ' if backend == 'apt' else 'ABRIR DNF5 INTERACTIVO ') + 'a'*64
                        texto = frase if respuesta == 'exacta' else 'no'
                        os.write(maestro, (texto+'\n').encode())
                        enviado = True
                if proceso.poll() is not None:
                    # Drenar la PTY hasta EOF/EIO antes de interpretar el resultado.
                    if not select.select([maestro], [], [], 0)[0]:
                        break
            proceso.wait(timeout=2)
            self.assertEqual(proceso.returncode, 0, datos.decode(errors='replace'))
            lineas = [x.split('RESULTADO=',1)[1] for x in datos.decode().splitlines()
                      if 'RESULTADO=' in x]
            self.assertEqual(len(lineas), 1, datos.decode())
            self.assertNotIn('DETALLE_PRIVADO', datos.decode())
            return json.loads(lineas[0])
        finally:
            if proceso.poll() is None:
                proceso.kill()
            proceso.wait()
            os.close(maestro)

    def test_aceptacion_exacta_en_pty_apt_y_fedora(self):
        for backend in ('apt', 'dnf5'):
            with self.subTest(backend=backend):
                self.assertEqual(self.ejecutar_pty(backend), {'aceptado':True})

    def test_rechazo_en_pty_apt_y_fedora(self):
        for backend in ('apt', 'dnf5'):
            with self.subTest(backend=backend):
                self.assertEqual(self.ejecutar_pty(backend,'no'), {'aceptado':False})

    def test_fallos_lectura_y_escritura_con_pty_real(self):
        for backend in ('apt', 'dnf5'):
            for fallo in ('lectura', 'escritura'):
                with self.subTest(backend=backend,fallo=fallo):
                    self.assertEqual(self.ejecutar_pty(backend,fallo=fallo),
                                     {'error':'terminal_io_error'})

    def test_sin_terminal_controladora_rechaza_sin_leer_stdin(self):
        codigo = """import sys
sys.path.insert(0,sys.argv[1])
from autorizacion_apt import abrir_tty_confirmacion
try:
 with abrir_tty_confirmacion():raise AssertionError('No debe aceptar stdin')
except ValueError as e:
 print(str(e))
"""
        r=subprocess.run([sys.executable,'-I','-S','-B','-c',codigo,RAIZ],
                         input=b'AUTORIZAR APT '+b'a'*64+b'\n',capture_output=True,
                         start_new_session=True,timeout=5)
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(r.stdout.strip(),b'terminal_requerida')

    def test_archivo_regular_no_es_terminal(self):
        with patch('builtins.open',side_effect=lambda *a,**k:open_real(os.devnull,*a[1:],**k)):
            with self.assertRaisesRegex(ValueError,'terminal_requerida'):
                with aut.abrir_tty_confirmacion():self.fail('Aceptó archivo sin TTY')

    def test_helper_clasifica_errores_tty_sin_detalles_ni_diario(self):
        import mantenimiento_dnf5 as perfil
        for error in ('terminal_requerida','terminal_io_error'):
            with self.subTest(error=error), patch.object(helper,'verificar_instalacion'), \
                    patch.object(helper.sys,'flags',type('Flags',(),{'isolated':True,'no_site':True})()), \
                    patch.object(helper.sys,'path',[]), \
                    patch.object(perfil,'main_helper',side_effect=ValueError(error)), \
                    contextlib.redirect_stdout(io.StringIO()) as salida:
                self.assertEqual(helper.main_dnf5(['ejecutar']),1)
                self.assertEqual(json.loads(salida.getvalue()),
                                 {'version':1,'estado':'cancelado','error':error})


open_real = open

if __name__ == '__main__':
    unittest.main()
