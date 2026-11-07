"""Fixtures y adquisición simulada: sin dpkg real ni acceso a red."""
import contextlib
import io
import json
import sys
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import AsistenteLocal as app
import auditoria_debian as deb
import auditoria_aislamiento as aislamiento
import backend_seguridad as backend
from distribucion_linux import detectar_distribucion
from evidencia_local import comprobar
from test_p0 import respuesta, llamada


def fila(nombre='ejemplo', arch='amd64', version='2:1.0~rc1-3+deb13u1',
         estado='install ok installed', fuente='fuente-ejemplo', version_fuente='2:1.0-3'):
    return '\t'.join((nombre, arch, version, estado, fuente, version_fuente))+'\n'


class Selector:
    def __init__(self, timeout=False):
        self.claves = {}
        self.timeout = timeout
    def __enter__(self):
        return self
    def __exit__(self, *args):
        pass
    def register(self, archivo, eventos, data):
        self.claves[archivo] = SimpleNamespace(fd=archivo if isinstance(archivo, int) else archivo.fileno(),
                                             fileobj=archivo, data=data)
    def unregister(self, archivo):
        del self.claves[archivo]
    def get_map(self):
        return self.claves
    def select(self, espera):
        return [] if self.timeout else [(k, 1) for k in list(self.claves.values())]


class InventarioDebian(unittest.TestCase):
    def adquirir(self, texto=None, codigo=0, stderr=b'', timeout=False, wait_timeout=False):
        proceso = Mock()
        proceso.stdout.fileno.return_value = 1
        proceso.stderr.fileno.return_value = 2
        proceso.__enter__ = Mock(return_value=proceso)
        proceso.__exit__ = Mock(return_value=False)
        proceso.wait.return_value = codigo
        if wait_timeout:
            proceso.wait.side_effect = [deb.subprocess.TimeoutExpired('simulado', 15), -9]
        proceso.poll.return_value = None
        bloques = {1: [(fila() if texto is None else texto).encode(), b''], 2: [stderr, b'']}
        with patch.object(deb.subprocess, 'Popen', return_value=proceso) as lanzar, \
             patch.object(deb.selectors, 'DefaultSelector', return_value=Selector(timeout)), \
             patch.object(deb.os, 'read', side_effect=lambda fd,n: bloques[fd].pop(0)):
            datos = deb.consultar_inventario(120)
        lanzar.assert_called_once_with(deb.comando_aislado(), stdout=deb.subprocess.PIPE,
            stderr=deb.subprocess.PIPE, stdin=deb.subprocess.DEVNULL)
        self.assertLessEqual(datos['fuente']['duracion_s'], 15)
        return datos

    def test_instalados_multiarch_y_versiones(self):
        datos = self.adquirir(fila()+fila(arch='i386'))
        self.assertEqual(datos['total_instalados'], 2)
        self.assertEqual(datos['estado_adquisicion'], 'completo')
        paquete = datos['inventario_dpkg'][0]
        self.assertEqual(paquete, dict(nombre_binario='ejemplo', arquitectura='amd64',
            version='2:1.0~rc1-3+deb13u1', estado_instalacion='install ok installed',
            categoria='instalado', nombre_fuente='fuente-ejemplo', version_fuente='2:1.0-3'))
        self.assertEqual(deb.parsear_fila(fila(fuente='', version_fuente='').rstrip('\n'))['nombre_fuente'], None)

    def test_estados_incompletos_residuales_y_hold(self):
        estados = [('hold ok installed', 'instalado'), ('deinstall ok config-files', 'residual'),
            ('install reinstreq installed', 'incompleto'), ('install ok unpacked', 'incompleto'),
            ('install ok half-installed', 'incompleto'), ('install ok half-configured', 'incompleto'),
            ('install ok triggers-pending', 'incompleto'), ('install ok triggers-awaited', 'incompleto'),
            ('unknown ok not-installed', 'no_instalado')]
        texto = ''.join(fila(nombre='pkg'+str(i), estado=estado) for i,(estado,_) in enumerate(estados))
        datos = self.adquirir(texto)
        self.assertEqual([p['categoria'] for p in datos['inventario_dpkg']], [c for _,c in estados])
        self.assertEqual(datos['total_instalados'], 1)
        self.assertEqual(datos['recuentos_recogidos']['residual'], 1)

    def test_malformados_y_prefijo_valido(self):
        for texto in ('invalida\n', fila(estado='install ok falso'), fila(nombre='../pkg'),
                      fila(version='sin-version'), fila().replace('\n','\tmas\n')):
            datos = self.adquirir(fila()+texto)
            self.assertEqual(datos['estado_adquisicion'], 'parcial')
            self.assertIsNone(datos['total_instalados'])
            self.assertEqual(len(datos['inventario_dpkg']), 1)
            self.assertEqual(datos['fuente']['motivo'], 'formato_invalido')
        self.assertEqual(self.adquirir(fila()+fila())['fuente']['motivo'], 'registro_duplicado')
        self.assertEqual(self.adquirir(fila()+'prefijo')['fuente']['motivo'], 'fila_incompleta')
        acumulador = deb.Acumulador()
        acumulador.recibir('stdout', b'\xff\n')
        self.assertEqual(acumulador.motivo, 'formato_invalido')

    def test_limites_y_fragmentacion(self):
        self.assertEqual((deb.MAX_BYTES, deb.MAX_REGISTROS, deb.MAX_LINEA, deb.MAX_STDERR,
                          deb.MAX_SEGUNDOS, deb.MAX_RESUMEN), (4194304,25000,2048,8192,15,5000))
        a = deb.Acumulador()
        for byte in fila().encode():
            a.recibir('stdout', bytes([byte]))
        self.assertEqual(len(a.registros), 1)
        for limite, canal, bloques, motivo in [
            ('MAX_BYTES', 'stdout', [b'x'*9], 'limite_bytes'),
            ('MAX_LINEA', 'stdout', [b'x'*9], 'limite_linea'),
            ('MAX_STDERR', 'stderr', [b'x'*9], 'limite_stderr')]:
            with self.subTest(limite=limite), patch.object(deb, limite, 8):
                a = deb.Acumulador()
                for bloque in bloques:
                    a.recibir(canal,bloque)
                self.assertEqual(a.motivo,motivo)
        with patch.object(deb, 'MAX_REGISTROS', 1):
            datos = self.adquirir(fila()+fila(nombre='otro'))
            self.assertEqual(datos['fuente']['motivo'], 'limite_registros')
            self.assertEqual(len(datos['inventario_dpkg']), 1)
            self.assertIsNone(datos['total_instalados'])

    def test_fallos_adquisicion_y_no_fallback(self):
        for codigo, motivo in ((78,'aislamiento_no_disponible'), (69,'ejecutable_ausente'), (1,'error_comando')):
            datos = self.adquirir(texto='', codigo=codigo)
            self.assertEqual(datos['estado_adquisicion'], 'error')
            self.assertEqual(datos['fuente']['motivo'], motivo)
        self.assertEqual(self.adquirir(stderr=b'aviso')['fuente']['motivo'], 'avisos_no_interpretados')
        self.assertEqual(self.adquirir(timeout=True)['fuente']['motivo'], 'tiempo_agotado')
        for error, motivo in ((FileNotFoundError(), 'ejecutable_ausente'),
                              (PermissionError(), 'permiso_denegado'), (OSError(), 'error_sistema')):
            with patch.object(deb.subprocess, 'Popen', side_effect=error) as lanzar:
                datos = deb.consultar_inventario(1)
                self.assertEqual(datos['fuente']['motivo'], motivo)
                self.assertEqual(lanzar.call_count,1)
        with patch.object(deb.subprocess, 'Popen') as lanzar:
            self.assertEqual(deb.consultar_inventario(0)['fuente']['motivo'], 'tiempo_agotado')
            lanzar.assert_not_called()

    def test_timeout_y_error_conservan_registros_sin_total(self):
        for kwargs, motivo in (({'wait_timeout': True}, 'tiempo_agotado'),
                               ({'codigo': 1}, 'error_comando')):
            with self.subTest(kwargs=kwargs):
                datos = self.adquirir(**kwargs)
                self.assertEqual(datos['estado_adquisicion'], 'parcial')
                self.assertEqual(datos['fuente']['motivo'], motivo)
                self.assertEqual(len(datos['inventario_dpkg']), 1)
                self.assertIsNone(datos['total_instalados'])
                self.assertFalse(datos['inventario_completo'])

    def test_dependencia_dpkg_ausente_y_correlacion_sin_consultas(self):
        seleccion = detectar_distribucion(contenido='ID=debian\nVERSION_ID=13')
        with patch.object(backend, 'detectar_distribucion', return_value=seleccion), \
             patch.object(app.shutil, 'which', return_value=None), \
             patch.object(app.os.path, 'isfile', return_value=False), \
             patch.object(app, 'inventario_debian') as adquirir, \
             patch.object(app.subprocess, 'Popen', side_effect=AssertionError('Proceso real')), \
             patch.object(app, 'abrir_http_local', side_effect=AssertionError('HTTP real')), \
             patch.object(app, 'ALLOW_EXTERNAL', True):
            entorno = app.entorno_ejecucion()
            self.assertEqual(entorno['dependencias']['auditoria_seguridad']['dpkg-query']['estado'], 'ausente')
            self.assertEqual(json.loads(app.ejecutar_consulta('correlacion_seguridad'))['estado'], 'no_implementado')
            adquirir.assert_not_called()

    def test_modo_fijo_y_fallo_aislamiento(self):
        self.assertEqual(deb.COMANDO, ('dpkg-query','--admindir=/var/lib/dpkg','--show',
            '--showformat=${Package}\t${Architecture}\t${Version}\t${Status}\t${source:Package}\t${source:Version}\n'))
        for args, restringe, esperado in ((['dpkg'], True,69), (['dpkg'],False,78), (['dpkg','extra'],True,78)):
            orden = []
            def restringir():
                orden.append('aislamiento')
                if not restringe:
                    raise OSError()
            def ejecutar(*args):
                orden.append('exec')
                raise FileNotFoundError()
            with patch.object(sys,'argv',['helper']+args), \
                 patch.object(aislamiento,'restringir',side_effect=restringir), \
                 patch.object(aislamiento.os,'execvpe',side_effect=ejecutar) as execvpe:
                self.assertEqual(aislamiento.main(),esperado)
                if esperado == 69:
                    self.assertEqual(orden,['aislamiento','exec'])
                    self.assertEqual(execvpe.call_args.args[:2], ('dpkg-query',list(deb.COMANDO)))
                else:
                    execvpe.assert_not_called()

    def test_resumen_privado_acotado_y_validacion(self):
        datos = self.adquirir()
        resultado = deb.ResultadoDebian(datos,18000)
        self.assertNotIn('ejemplo',str(resultado))
        self.assertNotIn('inventario_dpkg',json.loads(resultado))
        self.assertNotIn('inventario_rpm',resultado.datos)
        self.assertEqual(json.loads(resultado)['estado_seguridad'],'no_evaluada')
        comprobar('auditoria_seguridad',resultado,nivel_debian='contrato')
        copia = resultado.datos
        copia['inventario_dpkg'].clear()
        self.assertEqual(len(resultado.datos['inventario_dpkg']),1)
        for limite in (0,20,200,1000,5000):
            texto = resultado.ajustar(limite)
            self.assertLessEqual(len(texto),limite)
            if texto:
                json.loads(texto)
        parcial = self.adquirir(fila()+'invalida\n')
        self.assertIn('Contrato dpkg verificado',comprobar('auditoria_seguridad',
            deb.ResultadoDebian(parcial,5000),nivel_debian='contrato'))

    def test_seleccion_dependencias_y_modelo_sin_inventario(self):
        datos = self.adquirir()
        seleccion = detectar_distribucion(contenido='ID=debian\nVERSION_ID=13')
        with patch.object(backend,'detectar_distribucion',return_value=seleccion), \
             patch.object(app,'inventario_debian',return_value=datos) as adquirir, \
             patch.object(app,'consultar_auditoria_seguridad',side_effect=AssertionError('Fedora')), \
             patch.object(app,'consultar_correlacion',side_effect=AssertionError('Fedora')), \
             patch.object(app.shutil,'which',return_value='/bin/simulado'), \
             patch.object(app,'consultar_modelo',side_effect=[respuesta([llamada('auditoria_seguridad')]),respuesta(content='Fin')]) as modelo, \
             contextlib.redirect_stdout(io.StringIO()):
            entorno = app.entorno_ejecucion()
            self.assertEqual(set(entorno['dependencias']['auditoria_seguridad']),{'dpkg-query', 'python:apt_pkg'})
            self.assertEqual(entorno['dependencias']['correlacion_seguridad'],{})
            corr = json.loads(app.ejecutar_consulta('correlacion_seguridad'))
            self.assertEqual(corr['estado'],'no_implementado')
            app.preguntar('inventario')
            adquirir.assert_called_once()
            self.assertTrue(0 < adquirir.call_args.args[0] <= 120)
            mensajes = [m['content'] for m in modelo.call_args.args[0] if m['role']=='tool']
            self.assertEqual(len(mensajes),1)
            self.assertNotIn('ejemplo',mensajes[0])
            self.assertNotIn('inventario_dpkg',json.loads(mensajes[0]))
