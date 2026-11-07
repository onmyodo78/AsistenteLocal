"""APT íntegramente simulado: sin importar apt_pkg real ni abrir su caché."""
import contextlib
import copy
import io
import json
from pathlib import Path
import sys
import time
from types import SimpleNamespace as NS
import unittest
from unittest.mock import Mock, patch

import apt_debian as apt
import auditoria_debian as deb
import auditoria_aislamiento as aislamiento
import AsistenteLocal as app
import backend_seguridad as backend
from distribucion_linux import detectar_distribucion
from evidencia_local import comprobar
from test_auditoria_debian import Selector, fila


def indices(**cambios):
    dato = dict(configurados=1, presentes=1, ausentes=0, edad_max_s=100,
        potencialmente_desactualizados=False, frescura='no_verificada', umbral_aviso_s=604800)
    dato.update(cambios)
    return dato


def registro(**cambios):
    dato = dict(nombre_binario='ejemplo', arquitectura='amd64', instalada='1:1.0-1',
        candidata='1:2.0-1', prioridad=990, retenido=False, superior=True,
        posible_actualizacion=True, instalable_garantizada=False, origenes=[])
    dato.update(cambios)
    return dato


def salida(registros=None, meta=None, fin=True):
    registros = [registro()] if registros is None else registros
    datos = [dict(tipo='indices', datos=indices() if meta is None else meta)]
    datos += [dict(tipo='paquete', datos=r) for r in registros]
    if fin:
        datos.append(dict(tipo='fin', registros=len(registros)))
    return ''.join(json.dumps(d)+'\n' for d in datos)


def api_simulada(held=False, candidata='1:2.0-1', orden=1, prioridad=990):
    archivo = NS(origin='Debian', archive='trixie', component='main', site='deb.example', filename='/indice')
    indice = NS(has_packages=True, exists=True, is_trusted=True)
    instalada = NS(ver_str='1:1.0-1', arch='amd64')
    version = NS(ver_str=candidata, arch='amd64', file_list=[(archivo,0)]) if candidata else None
    paquete = NS(name='ejemplo', current_ver=instalada, current_state=6,
                 inst_state=0, selected_state=2 if held else 1)
    cache = NS(packages=[paquete], file_list=[archivo])
    policy = Mock()
    policy.get_candidate_ver.return_value = version
    policy.get_priority.return_value = prioridad
    policy.read_pinfile.return_value = policy.read_pindir.return_value = True
    sources = Mock()
    sources.list = [NS(index_files=[indice])]
    sources.find_index.return_value = indice
    sources.read_main_list.return_value = True
    config = Mock()
    config.find.return_value = ''
    config.find_file.return_value = '/etc/apt/preferences'
    config.find_dir.return_value = '/etc/apt/preferences.d/'
    api = Mock(CURSTATE_INSTALLED=6, INSTSTATE_OK=0, INSTSTATE_HOLD=1, SELSTATE_HOLD=2)
    api.Cache.return_value = cache
    api.Policy.return_value = policy
    api.SourceList.return_value = sources
    api.config = config
    api.version_compare.return_value = orden
    return api, cache, policy, sources


class AptLocal(unittest.TestCase):
    def adquirir(self, texto=None, codigo=0, stderr=b'', timeout=False):
        proceso = Mock()
        proceso.stdout.fileno.return_value = 1
        proceso.stderr.fileno.return_value = 2
        proceso.__enter__ = Mock(return_value=proceso)
        proceso.__exit__ = Mock(return_value=False)
        proceso.wait.return_value = codigo
        proceso.poll.return_value = None
        bloques = {1:[(salida() if texto is None else texto).encode(), b''], 2:[stderr,b'']}
        with patch.object(apt.subprocess,'Popen',return_value=proceso) as lanzar, \
             patch.object(apt.selectors,'DefaultSelector',return_value=Selector(timeout)), \
             patch.object(apt.os,'read',side_effect=lambda fd,n: bloques[fd].pop(0)):
            datos = apt.consultar_actualizaciones(120)
        lanzar.assert_called_once_with(apt.comando_aislado(),stdout=apt.subprocess.PIPE,
            stderr=apt.subprocess.PIPE,stdin=apt.subprocess.DEVNULL)
        return datos

    def test_versiones_prioridades_y_retenciones(self):
        for candidata, orden in [('1:2.0-1',1), ('1:1.0-1',0), ('1:0.9~rc1-1',-1), (None,0)]:
            for held in (False, True):
                with self.subTest(candidata=candidata, held=held):
                    api, cache, policy, sources = api_simulada(held,candidata,orden,1001)
                    dato = list(apt._registros(cache,policy,sources,api))[0]
                    self.assertEqual(dato['candidata'],candidata)
                    self.assertEqual(dato['superior'],candidata is not None and orden > 0)
                    self.assertEqual(dato['posible_actualizacion'],candidata is not None and orden > 0 and not held)
                    self.assertFalse(dato['instalable_garantizada'])
                    self.assertEqual(dato['prioridad'],1001 if candidata else None)
                    if candidata:
                        api.version_compare.assert_called_once_with(candidata,'1:1.0-1')
                    policy.get_candidate_ver.assert_called_once_with(cache.packages[0])
        # La selección se delega a Policy, sin elegir a mano la mayor versión.
        api, cache, policy, sources = api_simulada(candidata='1:0.9-1',orden=-1,prioridad=1001)
        cache.packages[0].version_list = [NS(ver_str='9:99.0-1')]
        self.assertEqual(list(apt._registros(cache,policy,sources,api))[0]['candidata'],'1:0.9-1')

    def test_multiarch_procedencia_y_estados(self):
        api, cache, policy, sources = api_simulada(held=True)
        otro = copy.copy(cache.packages[0])
        otro.current_ver = NS(ver_str='1:1.0-1',arch='i386')
        otro.inst_state = api.INSTSTATE_HOLD
        cache.packages += [otro, NS(current_ver=None)]
        filas = list(apt._registros(cache,policy,sources,api))
        self.assertEqual([r['arquitectura'] for r in filas],['amd64','i386'])
        self.assertTrue(all(r['retenido'] and not r['posible_actualizacion'] for r in filas))
        self.assertEqual(filas[0]['origenes'][0],dict(origen='Debian',archivo='trixie',
            componente='main',sitio='deb.example',confiable_segun_apt=True))
        sources.find_index.return_value = None
        self.assertEqual(list(apt._registros(cache,policy,sources,api))[0]['origenes'],[])
        cache.packages = [NS(current_ver=NS(),current_state=1)]
        self.assertEqual(list(apt._registros(cache,policy,sources,api)),[])

    def test_indices_ausentes_viejos_y_reloj(self):
        api, cache, policy, sources = api_simulada()
        for mtime, aviso in ((999900,False), (0,True), (1000001,True)):
            with patch.object(apt.os,'stat',return_value=NS(st_mtime=mtime)):
                meta = apt._indices(cache,sources,1000000)
                self.assertEqual(meta['potencialmente_desactualizados'],aviso)
                self.assertEqual(meta['frescura'],'no_verificada')
        sources.list[0].index_files[0].exists = False
        self.assertEqual(apt._indices(NS(file_list=[]),sources,1000000)['ausentes'],1)
        datos = self.adquirir(salida([],indices(presentes=0,ausentes=1),fin=False),codigo=67)
        self.assertEqual(datos['motivo'],'indices_ausentes')
        self.assertIsNone(datos['total_posibles'])
        datos = self.adquirir(salida(meta=indices(configurados=2,ausentes=1)))
        self.assertEqual(datos['estado_adquisicion'],'parcial')
        self.assertEqual(datos['motivo'],'indices_parciales')

    def test_lectura_completa_y_contrato(self):
        datos = self.adquirir(salida([registro(),registro(arquitectura='i386',retenido=True,posible_actualizacion=False)]))
        self.assertEqual(datos['estado_adquisicion'],'completo')
        self.assertEqual(datos['total_posibles'],1)
        self.assertEqual(datos['recuentos_recogidos'],dict(registros=2,superiores=2,retenidos=1,posibles=1))
        self.assertEqual(datos['instalabilidad'],'no_comprobada')
        self.assertEqual(datos['seguridad'],'no_evaluada')

    def test_parciales_malformados_y_fin_obligatorio(self):
        for texto in (salida(fin=False), salida(fin=False)+'invalido\n',
                      salida()+json.dumps(dict(tipo='fin',registros=1))+'\n',
                      salida([registro(),registro()])):
            with self.subTest(texto=texto[-60:]):
                datos = self.adquirir(texto)
                self.assertEqual(datos['estado_adquisicion'],'parcial')
                self.assertIsNone(datos['total_posibles'])
                self.assertEqual(len(datos['candidatos']),1)
        for campo,valor in [('retenido',1),('instalable_garantizada',True),('instalada','mal'),
                            ('prioridad','500'),('posible_actualizacion',False)]:
            with self.subTest(campo=campo), self.assertRaises(ValueError):
                apt.validar_registro(registro(**{campo:valor}))

    def test_limites_y_fragmentacion(self):
        self.assertEqual((apt.MAX_BYTES,apt.MAX_REGISTROS,apt.MAX_LINEA,apt.MAX_STDERR,
                          apt.MAX_SEGUNDOS),(4194304,25000,16384,8192,15))
        a = apt.Acumulador()
        for byte in salida().encode():
            a.recibir('stdout',bytes([byte]))
        self.assertTrue(a.fin)
        for limite,canal,motivo in [('MAX_BYTES','stdout','limite_bytes'),
            ('MAX_LINEA','stdout','limite_linea'),('MAX_STDERR','stderr','limite_stderr')]:
            with patch.object(apt,limite,8):
                a = apt.Acumulador()
                a.recibir(canal,b'x'*9)
                self.assertEqual(a.motivo,motivo)
        with patch.object(apt,'MAX_REGISTROS',1):
            self.assertEqual(self.adquirir(salida([registro(),registro(arquitectura='i386')]))['estado_adquisicion'],'parcial')

    def test_fallos_sin_reintentos(self):
        for codigo,motivo in [(78,'aislamiento_no_disponible'),(70,'python3_apt_no_disponible'),
            (71,'configuracion_apt_no_disponible'),(72,'consulta_apt_fallida'),(73,'limite_registros')]:
            self.assertEqual(self.adquirir('',codigo)['motivo'],motivo)
        self.assertEqual(self.adquirir(timeout=True)['motivo'],'tiempo_agotado')
        self.assertEqual(self.adquirir(stderr=b'aviso')['motivo'],'avisos_no_interpretados')
        for error,motivo in [(FileNotFoundError(),'ejecutable_ausente'),(PermissionError(),'permiso_denegado')]:
            with patch.object(apt.subprocess,'Popen',side_effect=error) as lanzar:
                self.assertEqual(apt.consultar_actualizaciones(1)['motivo'],motivo)
                self.assertEqual(lanzar.call_count,1)

    def test_modo_fijo_y_orden_aislamiento(self):
        self.assertEqual(apt.comando_aislado(),[sys.executable,'-B',
            str(Path(apt.__file__).with_name('auditoria_aislamiento.py').resolve()),'apt-local'])
        for args,fallo in [(['apt-local'],False),(['apt-local'],True),(['apt-local','extra'],False)]:
            orden = []
            def restringir():
                orden.append('aislamiento')
                if fallo:
                    raise OSError()
            def emitir():
                orden.append('apt')
                return 0
            with patch.object(sys,'argv',['helper']+args), patch.object(aislamiento,'restringir',side_effect=restringir), \
                 patch.object(apt,'emitir_local',side_effect=emitir), \
                 patch.object(aislamiento.os,'execvpe',side_effect=AssertionError('exec')):
                codigo = aislamiento.main()
                self.assertEqual(codigo,0 if len(args)==1 and not fallo else 78)
                self.assertEqual('apt' in orden,codigo==0)
                if codigo==0:
                    self.assertEqual(orden,['aislamiento','apt'])

    def test_worker_solo_cache_politica_y_sin_persistencia(self):
        api,cache,policy,sources = api_simulada()
        with patch.dict(sys.modules,{'apt_pkg':api}), \
             patch.dict(apt.os.environ, {'APT_CONFIG': '/config-no-autorizada'}), \
             patch.object(Path,'exists',return_value=True), \
             patch.object(apt.os,'stat',return_value=NS(st_mtime=time.time())), \
             patch.object(apt.subprocess,'Popen',side_effect=AssertionError('subproceso')), \
             contextlib.redirect_stdout(io.StringIO()) as salida_worker:
            self.assertEqual(apt.emitir_local(),0)
            self.assertNotIn('APT_CONFIG', apt.os.environ)
        a = apt.Acumulador()
        a.recibir('stdout',salida_worker.getvalue().encode())
        self.assertTrue(a.fin)
        api.Cache.assert_called_once_with(None)
        policy.read_pinfile.assert_called_once_with('/etc/apt/preferences')
        policy.read_pindir.assert_called_once_with('/etc/apt/preferences.d/')
        api.config.set.assert_any_call('Dir::Cache::pkgcache','')
        api.config.set.assert_any_call('Dir::Cache::srcpkgcache','')
        api.config.set.assert_any_call('Debug::NoLocking','true')
        for prohibido in ('Acquire','DepCache','PackageManager'):
            getattr(api,prohibido).assert_not_called()
        with patch.dict(sys.modules,{'apt_pkg':None}):
            self.assertEqual(apt.emitir_local(),70)
        api.config.find.return_value = '/otra-raiz'
        with patch.dict(sys.modules,{'apt_pkg':api}):
            self.assertEqual(apt.emitir_local(),71)

    def test_combinacion_privacidad_y_estados_independientes(self):
        # Inventario sintético completo con versión coincidente.
        inventario = dict(version=1,backend='debian',herramienta='auditoria_seguridad',
            alcance='inventario_local_dpkg',estado_seguridad='no_evaluada',estado_adquisicion='completo',
            inventario_completo=True,inventario_dpkg=[deb.parsear_fila(fila(version='1:1.0-1').rstrip('\n'))],
            fuente=dict(nombre='dpkg-query',codigo=0,motivo=None,stderr_bytes=0),recuentos_recogidos=dict(instalado=1,incompleto=0,residual=0,no_instalado=0),
            total_instalados=1,actualizaciones='no_implementado',cve='no_disponible',
            avisos_seguridad='no_disponible',limitaciones=['Solo inventario'])
        actualizaciones = self.adquirir()
        for cambia in (False,True):
            candidato = copy.deepcopy(actualizaciones)
            if cambia:
                candidato['candidatos'][0]['instalada']='1:0.9-1'
            with patch.object(deb,'consultar_inventario',return_value=copy.deepcopy(inventario)), \
                 patch.object(apt,'consultar_actualizaciones',return_value=candidato):
                datos = deb.consultar_auditoria(120)
            self.assertEqual(datos['estado_inventario'],'completo')
            self.assertEqual(datos['estado_adquisicion'],'parcial' if cambia else 'completo')
            if cambia:
                self.assertIsNone(datos['actualizaciones']['total_posibles'])
            resultado = deb.ResultadoDebian(datos,5000)
            self.assertLessEqual(len(resultado),5000)
            self.assertNotIn('ejemplo',str(resultado))
            self.assertNotIn('candidatos',json.loads(resultado)['actualizaciones'])
            self.assertNotIn('inventario_dpkg',json.loads(resultado))
            if not cambia:
                comprobar('auditoria_seguridad',resultado)
            else:
                self.assertIn('cobertura APT no confirmada',
                    comprobar('auditoria_seguridad',resultado,nivel_debian='contrato'))
                with self.assertRaises(AssertionError):
                    comprobar('auditoria_seguridad',resultado)

    def test_dependencia_opcional_sin_consultar_apt(self):
        distribucion=detectar_distribucion(contenido='ID=debian\nVERSION_ID=13')
        with patch.object(backend,'detectar_distribucion',return_value=distribucion), \
             patch.object(app.importlib.util,'find_spec',return_value=None), \
             patch.object(app.shutil,'which',return_value='/bin/simulado'), \
             patch.object(apt,'emitir_local',side_effect=AssertionError('APT real')):
            deps=app.entorno_ejecucion()['dependencias']['auditoria_seguridad']
            self.assertEqual(deps['python:apt_pkg']['estado'],'ausente')
            self.assertEqual(set(deps),{'dpkg-query','python:apt_pkg'})

    def test_worker_indices_ausentes_y_errores_sin_salida_sensible(self):
        api, cache, policy, sources = api_simulada()
        sources.list[0].index_files[0].exists = False
        for fallo, esperado in ((False,67),(True,72)):
            if fallo:
                api.Cache.side_effect = OSError('RUTA_SECRETA')
            with patch.dict(sys.modules,{'apt_pkg':api}), \
                 patch.dict(apt.os.environ), \
                 patch.object(Path,'exists',return_value=True), \
                 contextlib.redirect_stdout(io.StringIO()) as texto, \
                 contextlib.redirect_stderr(io.StringIO()) as diagnostico:
                self.assertEqual(apt.emitir_local(),esperado)
            self.assertNotIn('RUTA_SECRETA',texto.getvalue())
            self.assertNotIn('RUTA_SECRETA',diagnostico.getvalue())

    def test_presupuesto_worker_y_error_parcial_con_prefijo(self):
        api, cache, policy, sources = api_simulada()
        with patch.dict(sys.modules,{'apt_pkg':api}), patch.dict(apt.os.environ), \
             patch.object(Path,'exists',return_value=True), \
             patch.object(apt.os,'stat',return_value=NS(st_mtime=time.time())), \
             patch.object(apt,'MAX_REGISTROS',0), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(apt.emitir_local(),73)
        datos=self.adquirir(salida(fin=False),codigo=72)
        self.assertEqual(datos['estado_adquisicion'],'parcial')
        self.assertEqual(len(datos['candidatos']),1)
        self.assertIsNone(datos['total_posibles'])

    def test_inventario_y_actualizaciones_no_se_confunden(self):
        inventario = dict(version=1,estado_adquisicion='error',inventario_completo=False,
                          inventario_dpkg=[],estado_seguridad='no_evaluada')
        with patch.object(deb,'consultar_inventario',return_value=inventario), \
             patch.object(apt,'consultar_actualizaciones',return_value=self.adquirir()) as adquirir:
            datos=deb.consultar_auditoria(120)
        self.assertEqual(datos['estado_inventario'],'error')
        self.assertEqual(datos['actualizaciones']['estado_adquisicion'],'completo')
        self.assertEqual(datos['estado_adquisicion'],'parcial')
        self.assertIsNone(datos['actualizaciones']['total_posibles'])
        self.assertTrue(0 < adquirir.call_args.args[0] <= 120)
