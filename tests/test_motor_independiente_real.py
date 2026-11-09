"""Pruebas optativas locales. Sin red, privilegios ni modificaciones de paquetes.

ASISTENTE_MANTENIMIENTO_REAL=1 habilita APT real y aislamiento de scratch.
No activa las integraciones antiguas con LM Studio ni DNF del anfitrión.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

RAIZ = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.environ.get('ASISTENTE_MANTENIMIENTO_REAL') == '1' and os.geteuid() != 0,
                     'Pruebas locales optativas desactivadas o usuario root')
class Local(unittest.TestCase):
    def test_importacion_sin_conversacion_ni_lmstudio(self):
        codigo = ('import sys,socket; sys.path.insert(0,sys.argv[1]); '
                  'socket.create_connection=lambda *a,**k: (_ for _ in ()).throw(AssertionError("Red")); '
                  'import cli; '
                  'assert not any(n in sys.modules for n in ("AsistenteLocal","lmstudio_http","lmstudio_metrics")); '
                  'sys.exit(cli.main(["--formato","json","capacidades"]))')
        p = subprocess.run([sys.executable,'-I','-B','-c',codigo,str(RAIZ)],
                           capture_output=True,text=True,timeout=40)
        self.assertIn(p.returncode,(0,1))
        self.assertEqual(json.loads(p.stdout)['version'],1)

    def test_plan_debian_y_estado_sistema_sin_cambios(self):
        from distribucion_linux import detectar_distribucion
        if detectar_distribucion()['id'] != 'debian':
            self.skipTest('Prueba nativa específica Debian')
        estado = Path('/var/lib/dpkg/status')
        indices = Path('/var/lib/apt/lists')
        def instantanea():
            return (hashlib.sha256(estado.read_bytes()).hexdigest(),
                sorted((p.name,p.stat().st_size,p.stat().st_mtime_ns) for p in indices.iterdir()))
        antes = instantanea()
        p = subprocess.run([sys.executable,'-B',str(RAIZ/'cli.py'),'--formato','json','plan'],
                           capture_output=True,text=True,timeout=125)
        self.assertEqual(antes,instantanea())
        self.assertIn(p.returncode,(0,3,1))
        d = json.loads(p.stdout)
        from contratos_mantenimiento import validar
        validar(d)
        self.assertFalse(d['ejecucion_habilitada'])
        # No aceptar una falsa simulación correcta ante fallos reales del entorno.
        if d['simulacion']['estado'] != 'completo':
            self.assertTrue(d['simulacion']['errores'])
        print('APT local:',d['estado'],'candidatas=',len(d['candidatas']['paquetes']),
              'simulacion=',d['simulacion']['estado'],'errores=',d['simulacion']['errores'],
              'previstas=',len(d['simulacion']['actualizaciones']))

    def test_auditoria_debian_sin_lmstudio(self):
        from distribucion_linux import detectar_distribucion
        if detectar_distribucion()['id'] != 'debian':
            self.skipTest('Prueba nativa específica Debian')
        status=Path('/var/lib/dpkg/status')
        antes=hashlib.sha256(status.read_bytes()).hexdigest()
        p=subprocess.run([sys.executable,'-B',str(RAIZ/'cli.py'),'--formato','json','auditoria'],
                         capture_output=True,text=True,timeout=125)
        self.assertEqual(antes,hashlib.sha256(status.read_bytes()).hexdigest())
        self.assertIn(p.returncode,(0,3,1))
        d=json.loads(p.stdout)
        self.assertEqual(d['backend'],'debian')
        self.assertIn(d['estado_inventario'],('completo','parcial','error'))
        print('Auditoría local:',d['estado_adquisicion'],'paquetes=',d['total_instalados'])

    def test_aislamiento_scratch_sin_escritura_exterior_ni_red(self):
        codigo = '''import os,sys,socket
sys.path.insert(0,sys.argv[1])
from auditoria_aislamiento import restringir
fd=os.open(sys.argv[2],os.O_RDONLY|os.O_DIRECTORY)
restringir(temporal_fd=fd)
os.close(fd)
with open(sys.argv[2]+'/permitido','w') as f: f.write('temporal')
try:
    open(sys.argv[3]+'/prohibido','w')
except PermissionError:
    pass
else:
    raise AssertionError('Escritura exterior permitida')
try:
    socket.socket()
except PermissionError:
    pass
else:
    raise AssertionError('Red permitida')
'''
        with tempfile.TemporaryDirectory(prefix='asistentelocal-plan-',dir='/tmp') as t, \
             tempfile.TemporaryDirectory(prefix='asistentelocal-test-',dir='/tmp') as exterior:
            p = subprocess.run([sys.executable,'-I','-B','-c',codigo,str(RAIZ),t,exterior],
                               capture_output=True,text=True,timeout=10)
            self.assertEqual(p.returncode,0,p.stderr)
            self.assertFalse(Path(exterior,'prohibido').exists())
            self.assertEqual(Path(t,'permitido').read_text(),'temporal')
