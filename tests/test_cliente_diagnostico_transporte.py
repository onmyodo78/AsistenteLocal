"""Diagnóstico del protocolo y expiración sudo simulada; nunca ejecutar sudo real."""
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
from unittest.mock import Mock, patch
import cliente_ejecucion_apt as c


class Diagnostico(unittest.TestCase):
    def invocar(self,salida,codigo=0,peticion=None,backend='dnf5'):
        proceso=Mock(returncode=codigo)
        proceso.communicate.return_value=(salida,None)
        with patch.object(c.Path,'is_file',return_value=True), \
                patch.object(c,'comprobar_proteccion',return_value=True), \
                patch.object(c.subprocess,'Popen',return_value=proceso) as popen, \
                patch.object(c.time,'monotonic',side_effect=[10.,310.]):
            r=c.invocar('ejecutar',peticion,backend=backend)
        self.assertIsNone(popen.call_args.kwargs['stderr'])
        self.assertNotIn('timeout',proceso.communicate.call_args.kwargs)
        self.assertEqual(proceso.communicate.call_count,1)
        return r

    def test_motivos_estables_para_ambos_backends(self):
        casos=[('tamano_excesivo',b'x'*1048577,0),
               ('json_invalido',b'',1),('json_invalido',b'{',0),
               ('json_invalido',b'\xff',0),('estructura_incorrecta',b'[]',0),
               ('version_invalida',b'{"version":true,"estado":"completo"}',0),
               ('version_invalida',b'{"version":2,"estado":"completo"}',0),
               ('estado_invalido',b'{"version":1}',0),
               ('estado_invalido',b'{"version":1,"estado":[]}',0),
               ('estado_invalido',b'{"version":1,"estado":"inventado"}',0),
               ('identificador_discordante',b'{"version":1,"estado":"completo","id":"otro"}',0),
               ('codigo_salida_incompatible',b'{"version":1,"estado":"completo","id":"esperado"}',1)]
        for backend in ('apt','dnf5'):
            for motivo,salida,codigo in casos:
                with self.subTest(backend=backend,motivo=motivo,salida=salida[:60]):
                    r=self.invocar(salida,codigo,{'id':'esperado'},backend)
                    self.assertEqual(r,dict(version=1,estado='resultado_desconocido',
                        error='respuesta_ejecutor_no_confirmada',diagnostico_transporte=dict(
                            motivo=motivo,codigo_salida=codigo,duracion_s=300.,bytes_recibidos=len(salida))))

    def test_expiracion_simulada_no_se_afirma_como_causa(self):
        r=self.invocar(b'',1)
        self.assertEqual(r['diagnostico_transporte']['motivo'],'json_invalido')
        self.assertNotIn('sudo_timeout',json.dumps(r))

    def test_sin_datos_crudos_ni_mensajes_de_error(self):
        r=self.invocar(b'SECRETO_PRUEBA: error de autenticacion',1)
        self.assertNotIn('SECRETO_PRUEBA',json.dumps(r))
        self.assertEqual(set(r['diagnostico_transporte']),
                         {'motivo','codigo_salida','duracion_s','bytes_recibidos'})

    def test_respuestas_validas_se_conservan_sin_anadir_datos(self):
        for estado in ('preparado','completo','cancelado','fallido','incompleto','resultado_desconocido'):
            original={'version':1,'estado':estado,'id':'esperado'}
            with self.subTest(estado=estado):
                self.assertEqual(self.invocar(json.dumps(original).encode(),
                    0 if estado in ('preparado','completo') else 1,{'id':'esperado'}),original)

    def test_prompt_visible_y_expiracion_simulada_en_pty_real(self):
        # El sustituto simula el prompt/expiración; no importa sudo ni lee contraseñas.
        raiz=str(Path(__file__).resolve().parents[1])
        codigo='''import os,fcntl,termios,sys,json,subprocess
os.setsid();fcntl.ioctl(0,termios.TIOCSCTTY,0)
sys.path.insert(0,sys.argv[1])
import cliente_ejecucion_apt as c
from unittest.mock import patch
real=subprocess.Popen
fake="import os,time;os.write(2,b'PROMPT_SUDO_SIMULADO_VISIBLE\\\\n');time.sleep(0.1);raise SystemExit(1)"
llamadas=[]
def crear(comando,**kw):
 assert comando[:3]==['/usr/bin/sudo','-k','--']
 assert kw['stderr'] is None
 llamadas.append(1)
 return real([sys.executable,'-I','-S','-B','-c',fake],**kw)
with patch.object(c.Path,'is_file',return_value=True),patch.object(c,'comprobar_proteccion',return_value=True),patch.object(c.subprocess,'Popen',side_effect=crear):
 r=c.invocar('historial',backend='dnf5')
assert len(llamadas)==1
print('RESULTADO='+json.dumps(r),flush=True)
'''
        maestro,esclavo=pty.openpty()
        try:
            proceso=subprocess.Popen([sys.executable,'-I','-S','-B','-c',codigo,raiz],
                                     stdin=esclavo,stdout=esclavo,stderr=esclavo)
        finally:os.close(esclavo)
        datos=b'';limite=time.monotonic()+5
        try:
            while time.monotonic()<limite:
                if select.select([maestro],[],[],0.1)[0]:
                    try:bloque=os.read(maestro,65536)
                    except OSError:break
                    if not bloque:break
                    datos+=bloque
            proceso.wait(timeout=2)
            self.assertEqual(proceso.returncode,0,datos.decode(errors='replace'))
            self.assertIn(b'PROMPT_SUDO_SIMULADO_VISIBLE',datos)
            linea=[x.split('RESULTADO=',1)[1] for x in datos.decode().splitlines() if 'RESULTADO=' in x][0]
            r=json.loads(linea)
            self.assertEqual(r['diagnostico_transporte']['codigo_salida'],1)
            self.assertEqual(r['diagnostico_transporte']['bytes_recibidos'],0)
            self.assertNotIn('PROMPT',json.dumps(r))
        finally:
            if proceso.poll() is None:proceso.kill()
            proceso.wait();os.close(maestro)

if __name__=='__main__':unittest.main()
