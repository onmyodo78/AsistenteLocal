"""DNF5 simulado: ninguna prueba ejecuta RPM, sudo, red o una transacción."""
import contextlib
import copy
import io
import json
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

import dnf5_preparacion as d
from adaptadores.fedora import Fedora
from contratos_mantenimiento import paquete, validar
from mantenimiento import consultar


def p(nombre='uno', version='1',repo='@System'):
    return types.SimpleNamespace(get_name=lambda:nombre,get_arch=lambda:'x86_64',
        get_epoch=lambda:'2',get_version=lambda:version,get_release=lambda:'1.fc45',
        get_repo_id=lambda:repo)


class Query(list):
    def filter_installed(self):pass
    def filter_enabled(self,valor):assert valor is True


class Config:
    def __init__(self):self.valores={}
    def __getattr__(self,nombre):
        if not nombre.startswith('get_') or not nombre.endswith('_option'):raise AttributeError(nombre)
        clave=nombre[4:-7]
        return lambda:types.SimpleNamespace(set=lambda v:self.valores.update({clave:v}))


class Nativo:
    def __init__(self):
        self.config=Config();self.repo_config=Config();self.orden=[];self.problemas=0
        self.logs=[];self.grupos=[];self.accion=2;self.error=None
        self.antes=p();self.despues=p(version='2',repo='fedora')
        self.item=types.SimpleNamespace(get_action=lambda:self.accion,get_package=lambda:self.despues,
            get_replaces=lambda:[self.antes],get_reason=lambda:2)
        self.items=[self.item]
        self.trans=types.SimpleNamespace(get_problems=lambda:self.problemas,
            get_resolve_logs=lambda:self.logs,get_transaction_groups=lambda:self.grupos,
            get_transaction_environments=lambda:[],get_transaction_modules=lambda:[],
            get_transaction_packages=lambda:self.items,download=self.prohibido,run=self.prohibido,
            test=self.prohibido,serialize=self.prohibido)
        self.repo=types.SimpleNamespace(get_id=lambda:'fedora',get_config=lambda:self.repo_config)
        self.sack=types.SimpleNamespace(create_repos_from_system_configuration=self.crear,
                                        load_repos=self.cargar)
        self.base=types.SimpleNamespace(get_config=lambda:self.config,load_config=self.leer_config,
            setup=self.setup,get_repo_sack=lambda:self.sack)
        self.goal=types.SimpleNamespace(add_rpm_upgrade=lambda:self.orden.append('upgrade'),resolve=self.resolver)
        self.lib=types.ModuleType('libdnf5');self.lib.__path__=[]
        self.modulos={'libdnf5':self.lib}
        for nombre in ('base','conf','repo','rpm','transaction'):
            modulo=types.ModuleType('libdnf5.'+nombre)
            setattr(self.lib,nombre,modulo);self.modulos['libdnf5.'+nombre]=modulo
        self.lib.base.Base=lambda:self.base
        self.lib.base.Goal=lambda base:self.goal
        self.lib.base.GoalProblem_NO_PROBLEM=0
        self.lib.rpm.PackageQuery=lambda base:Query([self.antes])
        self.lib.repo.RepoQuery=lambda base:Query([self.repo])
        for i,nombre in enumerate(d.ACCIONES,1):
            setattr(self.lib.transaction,'TransactionItemAction_'+nombre,i)

    def prohibido(self,*args):raise AssertionError('Transacción real prohibida')
    def leer_config(self):self.orden.append('config')
    def crear(self):self.orden.append('repos')
    def setup(self):
        assert self.config.valores['cacheonly']=='all'
        assert self.config.valores['plugins'] is False
        assert self.config.valores['build_cache'] is False
        self.orden.append('setup')
    def cargar(self):
        assert self.repo_config.valores['skip_if_unavailable'] is False
        assert self.repo_config.valores['build_cache'] is False
        if self.error:raise self.error
        self.orden.append('load')
    def resolver(self):self.orden.append('resolve');return self.trans
    def recoger(self):
        with patch.dict(sys.modules,self.modulos):return d.recoger('/tmp/privado')


class Dnf5(unittest.TestCase):
    def setUp(self):
        self.n=Nativo();self.a=Fedora();self.a.gestor='dnf5'
        self.pila=contextlib.ExitStack();self.addCleanup(self.pila.close)
        import subprocess, urllib.request
        self.pila.enter_context(patch.object(subprocess,'Popen',side_effect=AssertionError('Proceso real prohibido')))
        self.pila.enter_context(patch.object(urllib.request,'urlopen',side_effect=AssertionError('Red prohibida')))

    def evidencia(self):return self.n.recoger()

    def adaptar(self,evidencia,inventario=None):
        with patch('adaptadores.fedora.importlib.util.find_spec',return_value=object()), patch(
                'adaptadores.fedora.ejecutar',return_value=dict(estado='completo',stdout=json.dumps(evidencia))) as ejecutar:
            r=self.a.preparar(time.monotonic()+20,inventario)
        self.assertEqual(ejecutar.call_args.args[0],'dnf5-preparar')
        return r

    def test_resolver_inspecciona_sin_descargar_ni_ejecutar(self):
        e=self.evidencia();d.validar(e)
        self.assertEqual(e['acciones_estado'],'completo')
        self.assertEqual(e['estado'],'no_verificable');self.assertFalse(e['ejecucion_habilitada'])
        self.assertEqual(e['acciones'][0]['paquete']['evr'],'2:2-1.fc45')
        self.assertEqual(e['acciones'][0]['reemplaza'][0]['evr'],'2:1-1.fc45')
        self.assertEqual(self.n.orden,['config','setup','repos','load','upgrade','resolve'])
        self.assertEqual(self.n.config.valores['persistdir'],'/tmp/privado')
        self.assertEqual(self.n.config.valores['logdir'],'/tmp/privado')
        self.assertEqual(self.adaptar(e),e)

    def test_binding_ausente_no_lanza_sondeo_de_aborto(self):
        with patch.dict(sys.modules,{'libdnf5':None}):
            self.assertEqual(d.recoger('/tmp/privado')['errores'],['binding_no_disponible'])
        with patch('adaptadores.fedora.importlib.util.find_spec',return_value=None), patch(
                'adaptadores.fedora.ejecutar',side_effect=AssertionError('No sondear')):
            self.assertEqual(self.a.preparar(time.monotonic()+10)['errores'],['binding_no_disponible'])

    def test_api_incompatible_y_permisos_repositorios(self):
        del self.n.lib.base.Goal
        self.assertEqual(self.evidencia()['errores'],['api_dnf5_no_admitida'])
        self.n=Nativo()
        for exc,motivo in ((PermissionError('secreto'), 'permisos_insuficientes'),
                (RuntimeError('https://usuario:clave@repositorio'), 'resolucion_dnf5_fallida')):
            with self.subTest(motivo=motivo):
                self.n.error=exc;e=self.evidencia()
                self.assertEqual(e['errores'],[motivo]);self.assertEqual(e['acciones'],[])
                self.assertNotIn('secreto',json.dumps(e));self.assertNotIn('clave',json.dumps(e))

    def test_repositorio_ausente_o_cambiado(self):
        self.n.lib.repo.RepoQuery=lambda base:Query([])
        self.assertEqual(self.evidencia()['errores'],['repositorios_no_verificados'])
        self.n=Nativo();e=self.evidencia();nuevo=copy.deepcopy(e)
        nuevo['repositorios']=['fedora','nuevo'];nuevo['huella']=d.huella(nuevo)
        with self.assertRaisesRegex(ValueError,'transaccion_nativa_diferente'):
            d.comprobar_identidad(e,nuevo)

    def test_conflictos_sin_excepcion_y_logs_no_se_ignoran(self):
        for problemas,logs in ((1,[]),(0,['mensaje no interpretado'])):
            self.n.problemas=problemas;self.n.logs=logs
            e=self.evidencia();self.assertEqual(e['errores'],['conflictos_dnf5'])
            self.assertEqual(e['acciones'],[])

    def test_accion_desconocida_y_grupos_no_se_ocultan(self):
        self.n.accion=999
        e=self.evidencia()
        self.assertEqual(e['errores'],['acciones_dnf5_no_admitidas'])
        self.assertEqual(e['diagnostico'],[d.detalle_rechazo('accion_rpm_desconocida',codigos=[999])])
        self.n.accion=2;self.n.grupos=['grupo']
        self.assertEqual(self.evidencia()['errores'],['acciones_dnf5_no_admitidas'])

    def test_grupo_entorno_modulo_se_distinguen_sin_representarlos(self):
        for motivo,metodo in (('grupo','get_transaction_groups'),('entorno','get_transaction_environments'),
                               ('modulo','get_transaction_modules')):
            with self.subTest(motivo=motivo):
                self.n=Nativo()
                setattr(self.n.trans,metodo,lambda:[types.SimpleNamespace(get_action=lambda:2)])
                e=self.evidencia()
                self.assertEqual(e['diagnostico'],[d.detalle_rechazo(motivo,codigos=[2])])
                self.assertEqual(e['errores'],['acciones_dnf5_no_admitidas'])
                self.assertEqual(e['estado'],'no_verificable');self.assertEqual(e['acciones'],[])
                with self.assertRaisesRegex(ValueError,'plan_no_verificable'):d.comprobar_ejecutable(e)
                self.assertEqual(self.adaptar(e),e)

    def test_varias_operaciones_rechazadas_no_se_ocultan(self):
        for metodo in ('get_transaction_groups','get_transaction_environments','get_transaction_modules'):
            setattr(self.n.trans,metodo,lambda:[types.SimpleNamespace(get_action=lambda:5)]*2)
        e=self.evidencia()
        self.assertEqual([r['motivo'] for r in e['diagnostico']],['grupo','entorno','modulo'])
        self.assertTrue(all(r['cantidad']==2 and r['codigos']==[5] for r in e['diagnostico']))

    def test_motivo_rpm_no_representable_se_distingue(self):
        self.n.item.get_reason=lambda:101
        e=self.evidencia()
        self.assertEqual(e['diagnostico'],[d.detalle_rechazo('motivo_rpm_no_representable',codigos=[101])])
        self.assertEqual(e['acciones_estado'],'no_comprobada');self.assertFalse(e['ejecucion_habilitada'])

    def test_otra_operacion_no_representable_no_inventa_un_tipo(self):
        self.n.error=ValueError('acciones_dnf5_no_admitidas')
        self.assertEqual(self.evidencia()['diagnostico'],[d.detalle_rechazo('operacion_no_representable')])

    def test_vector_vacio_con_booleano_verdadero_sigue_rechazado_y_diagnosticado(self):
        class Vector:
            def __iter__(self):return iter(())
        self.n.trans.get_transaction_groups=lambda:Vector()
        e=self.evidencia()
        self.assertEqual(e['diagnostico'],[d.detalle_rechazo('grupo',cantidad=0)])
        self.assertEqual(e['estado'],'no_verificable');self.assertEqual(e['errores'],['acciones_dnf5_no_admitidas'])

    def test_vector_opaco_no_oculta_rechazo_con_error_generico_de_api(self):
        class VectorOpaco:
            def __repr__(self):raise AssertionError('No mostrar punteros nativos')
        self.n.trans.get_transaction_modules=lambda:VectorOpaco()
        e=self.evidencia()
        self.assertEqual(e['diagnostico'],[d.detalle_rechazo('modulo',cantidad=None,representacion='no_iterable')])
        self.assertEqual(e['errores'],['acciones_dnf5_no_admitidas'])
        self.assertEqual(d.leer(json.dumps(e)),e)
        self.assertEqual(e['estado'],'no_verificable')

    def test_fallo_durante_iteracion_no_declara_lista_vacia(self):
        class VectorIncompleto:
            def __iter__(self):
                yield types.SimpleNamespace(get_action=lambda:2)
                raise RuntimeError('secreto nativo')
        self.n.trans.get_transaction_environments=lambda:VectorIncompleto()
        e=self.evidencia()
        self.assertEqual(e['diagnostico'],[d.detalle_rechazo('entorno',cantidad=None,representacion='lectura_no_disponible')])
        self.assertEqual(e['errores'],['acciones_dnf5_no_admitidas'])
        self.assertNotIn('secreto',json.dumps(e))

    def test_diagnostico_acotado_sin_nombres_repr_o_mensajes_nativos(self):
        class Secreto:
            def __repr__(self):raise AssertionError('No representar datos nativos')
            def __str__(self):raise AssertionError('No convertir datos nativos')
        self.n.grupos=[types.SimpleNamespace(get_action=lambda:Secreto(),nombre='secreto')]
        e=self.evidencia()
        self.assertEqual(e['diagnostico'][0]['codigos'],[None])
        self.assertNotIn('secreto',json.dumps(e))
        self.n.grupos=[types.SimpleNamespace(get_action=lambda n=n:n) for n in range(4)]
        with patch.object(d,'MAX_FILAS',3),patch.object(d,'MAX_CODIGOS',2):
            e=self.evidencia()
        detalle=e['diagnostico'][0]
        self.assertEqual(detalle['cantidad'],3);self.assertEqual(detalle['codigos'],[0,1])
        self.assertTrue(detalle['truncado']);self.assertTrue(detalle['codigos_truncados'])

    def test_contrato_v2_cierra_diagnostico_y_preserva_lectura_v1(self):
        e=self.evidencia();self.assertEqual(e['version'],2);self.assertEqual(e['diagnostico'],[])
        viejo=copy.deepcopy(e);viejo['version']=1;del viejo['diagnostico'];viejo['huella']=d.huella(viejo)
        self.assertEqual(d.leer(json.dumps(viejo)),viejo)
        with self.assertRaisesRegex(ValueError,'plan_no_verificable'):d.comprobar_ejecutable(viejo)
        self.n.accion=999
        e=self.evidencia()
        for clave,valor in (('motivo','arbitrario'),('cantidad',True),('cantidad',d.MAX_FILAS+1),
                ('codigos',['https://usuario:clave@servidor']),('codigos',[True]),
                ('codigos',[2**40]),('codigos',[1,1]),('truncado','false')):
            with self.subTest(clave=clave,valor=valor):
                nuevo=copy.deepcopy(e);nuevo['diagnostico'][0][clave]=valor;nuevo['huella']=d.huella(nuevo)
                with self.assertRaises(ValueError):d.leer(json.dumps(nuevo))
        nuevo=copy.deepcopy(e);nuevo['diagnostico']*=9;nuevo['huella']=d.huella(nuevo)
        with self.assertRaises(ValueError):d.validar(nuevo)
        nuevo=copy.deepcopy(e);nuevo['diagnostico']=[];nuevo['huella']=d.huella(nuevo)
        with self.assertRaises(ValueError):d.validar(nuevo)

    def test_validador_identifica_accion_rpm_inyectada_desconocida(self):
        e=self.evidencia();e['acciones'][0]['accion']='comando';e['huella']=d.huella(e)
        with self.assertRaises(d.OperacionNoRepresentable) as error:d.validar(e)
        self.assertEqual(error.exception.diagnostico[0]['motivo'],'accion_rpm_desconocida')

    def test_eliminacion_e_instalacion_se_informan_y_no_son_ejecutables(self):
        for accion in ('REMOVE','INSTALL','DOWNGRADE','REINSTALL','REASON_CHANGE'):
            self.n.accion=getattr(self.n.lib.transaction,'TransactionItemAction_'+accion)
            if accion in ('REMOVE','REASON_CHANGE'):self.n.despues=self.n.antes
            else:self.n.despues=p(version='2',repo='fedora')
            e=self.evidencia()
            self.assertEqual(e['acciones'][0]['accion'],accion)
            with self.assertRaisesRegex(ValueError,'plan_no_verificable'):d.comprobar_ejecutable(e)

    def test_installonly_multiversion_conserva_identidades(self):
        viejo=p(nombre='kernel-core');otro=p(nombre='kernel-core',version='0')
        self.n.lib.rpm.PackageQuery=lambda base:Query([viejo,otro])
        self.n.despues=p(nombre='kernel-core',version='2',repo='fedora')
        self.n.item.get_replaces=lambda:[];self.n.accion=1
        e=self.evidencia()
        self.assertEqual(e['acciones_estado'],'completo')
        self.assertEqual(len(e['inventario']),2)
        self.assertEqual(e['acciones'][0]['reemplaza'],[])

    def test_inventario_externo_o_reemplazo_incoherente_bloquea(self):
        e=self.evidencia()
        self.assertEqual(self.adaptar(e,[])['errores'],['inventario_no_coincidente'])
        self.n.item.get_replaces=lambda:[p(nombre='desconocido')]
        self.assertEqual(self.evidencia()['errores'],['inventario_no_coincidente'])

    def test_aborto_textual_con_binding_tampoco_es_evidencia(self):
        with patch('adaptadores.fedora.importlib.util.find_spec',return_value=object()), patch(
                'adaptadores.fedora.ejecutar',return_value=dict(estado='completo',stdout='Transaction aborted.')) as ejecutar:
            e=self.a.simular(time.monotonic()+10,[])
        self.assertEqual(e['estado'],'no_verificable')
        self.assertEqual(e['errores'],['evidencia_dnf5_invalida'])
        self.assertEqual(ejecutar.call_args.args[0],'dnf5-preparar')

    def test_native_no_contiene_puntos_de_ejecucion(self):
        import ast
        from pathlib import Path
        arbol=ast.parse(Path(d.__file__).read_text())
        prohibidos={'run','download','test','serialize','system','Popen','execve','execvpe'}
        for nodo in ast.walk(arbol):
            if isinstance(nodo,ast.Call) and isinstance(nodo.func,ast.Attribute):
                self.assertNotIn(nodo.func.attr,prohibidos)

    def test_worker_fallo_de_aislamiento_no_importa_resolvedor(self):
        import mantenimiento_worker as w
        with tempfile.TemporaryDirectory(prefix='asistentelocal-plan-') as temporal, patch.object(
                w.sys,'argv',['worker','dnf5-preparar']), patch.object(w.os,'geteuid',return_value=__import__('os').getuid()), patch.dict(
                w.os.environ,{'ASISTENTE_TEMPORAL':temporal}), patch('auditoria_aislamiento.restringir',side_effect=OSError('no disponible')), patch.object(
                d,'recoger') as recoger:
            self.assertEqual(w.main(),78);recoger.assert_not_called()

    def test_cambios_paquetes_instalaciones_eliminaciones_y_versiones(self):
        e=self.evidencia()
        self.assertTrue(d.comprobar_identidad(e,copy.deepcopy(e)))
        for campo in ('acciones','inventario'):
            nuevo=copy.deepcopy(e)
            if campo=='acciones':nuevo[campo]=[]
            else:nuevo[campo].append(dict(nombre='extra',arquitectura='noarch',evr='0:1-1'))
            nuevo['huella']=d.huella(nuevo)
            with self.assertRaisesRegex(ValueError,'transaccion_nativa_diferente'):
                d.comprobar_identidad(e,nuevo)
        nuevo=copy.deepcopy(e);nuevo['acciones'][0]['paquete']['evr']='2:3-1.fc45'
        nuevo['huella']=d.huella(nuevo)
        with self.assertRaisesRegex(ValueError,'transaccion_nativa_diferente'):d.comprobar_identidad(e,nuevo)

    def test_vigencia_y_huella_no_son_autorizacion(self):
        e=self.evidencia()
        for ahora in (e['creado']-1,e['creado']+301):
            with self.assertRaisesRegex(ValueError,'autorizacion_caducada'):d.comprobar_identidad(e,e,ahora=ahora)
        with self.assertRaisesRegex(ValueError,'plan_no_verificable'):d.comprobar_ejecutable(e)
        e['ejecucion_habilitada']=True;e['huella']=d.huella(e)
        with self.assertRaises(ValueError):d.validar(e)

    def test_json_estricto_sin_claves_duplicadas_tablas_o_datos_extra(self):
        for texto in ('Transaction aborted.', '{"version":1,"version":1}', '{}', 'NaN'):
            with self.assertRaises((ValueError,TypeError)):d.leer(texto)
        e=self.evidencia();e['extra']='comando'
        with self.assertRaises(ValueError):d.validar(e)
        e=self.evidencia();e['acciones'].append(copy.deepcopy(e['acciones'][0]));e['huella']=d.huella(e)
        with self.assertRaises(ValueError):d.validar(e)

    def test_error_transporte_nunca_acepta_stdout_parcial(self):
        for error in ('permisos_insuficientes','aislamiento_no_disponible','tiempo_agotado',
                'limite_salida','avisos_no_verificados','error_gestor'):
            with patch('adaptadores.fedora.importlib.util.find_spec',return_value=object()), patch(
                    'adaptadores.fedora.ejecutar',return_value=dict(estado='error',error=error,stdout=json.dumps(self.evidencia()))):
                e=self.a.preparar(time.monotonic()+10)
            self.assertEqual(e['errores'],[error]);self.assertEqual(e['acciones'],[])

    def test_deadline_vencido_no_adquiere_y_cancelacion_se_propaga(self):
        with patch('adaptadores.fedora.ejecutar',side_effect=AssertionError('Plazo agotado')):
            self.assertEqual(self.a.preparar(time.monotonic()-1)['errores'],['tiempo_agotado'])
        with patch('adaptadores.fedora.importlib.util.find_spec',return_value=object()), patch(
                'adaptadores.fedora.ejecutar',side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):self.a.preparar(time.monotonic()+10)

    def test_motor_conserva_contrato_apt_y_bloquea_fedora(self):
        from autorizacion_apt import comprobar_plan
        e=self.evidencia();inventario=[paquete('uno','x86_64','2:1-1.fc45',None)]
        with patch.object(self.a,'capacidades',return_value=dict(consulta=True,simulacion=False,ejecucion=False,solo_cache=True,sin_red=True)), patch.object(
                self.a,'consultar',return_value=(dict(estado='completo',paquetes=[],errores=[]),inventario)), patch.object(
                self.a,'preparar',return_value=e):
            plan=consultar('plan',distribucion=dict(estado='soportado',id='fedora',version_id='45'),adaptador=self.a)
        validar(plan)
        self.assertEqual(plan['estado'],'parcial')
        self.assertEqual(plan['simulacion']['estado'],'no_verificable')
        self.assertEqual(plan['simulacion']['actualizaciones'],[paquete('uno','x86_64','2:1-1.fc45','2:2-1.fc45')])
        self.assertFalse(plan['ejecucion_habilitada'])
        with self.assertRaisesRegex(ValueError,'plan_no_ejecutable'):comprobar_plan(plan)

    def test_worker_solo_recoge_despues_de_aislar_y_rechaza_root(self):
        import mantenimiento_worker as w
        import auditoria_aislamiento as aislamiento
        evidencia=self.evidencia()
        with tempfile.TemporaryDirectory(prefix='asistentelocal-plan-') as temporal, patch.object(
                w.sys,'argv',['worker','dnf5-preparar']), patch.object(w.os,'geteuid',return_value=__import__('os').getuid()), patch.dict(
                w.os.environ,{'ASISTENTE_TEMPORAL':temporal}), patch.object(aislamiento,'restringir') as aislar, patch.object(
                d,'recoger',return_value=evidencia) as recoger, contextlib.redirect_stdout(io.StringIO()) as salida:
            def adquirir(t):
                aislar.assert_called_once();self.assertEqual(t,temporal)
                return evidencia
            recoger.side_effect=adquirir
            self.assertEqual(w.main(),0);d.leer(salida.getvalue())
        with patch.object(w.sys,'argv',['worker','dnf5-preparar']), patch.object(w.os,'geteuid',return_value=0), patch.object(d,'recoger') as recoger:
            self.assertEqual(w.main(),78);recoger.assert_not_called()

    def test_cli_detalle_y_cancelacion_sin_cliente_administrativo(self):
        import cli
        with patch('distribucion_linux.detectar_distribucion',return_value=dict(estado='soportado',id='fedora')), patch.object(
                cli.os,'geteuid',return_value=1000), patch.object(Fedora,'preparar',return_value=self.evidencia()), patch(
                'cliente_ejecucion_apt.invocar',side_effect=AssertionError('No escalar')), contextlib.redirect_stdout(io.StringIO()) as salida:
            self.assertEqual(cli.main(['--formato','json','preparar-dnf5']),3)
            self.assertEqual(d.leer(salida.getvalue())['acciones_estado'],'completo')
        with patch('distribucion_linux.detectar_distribucion',return_value=dict(estado='soportado',id='fedora')), patch.object(
                cli.os,'geteuid',return_value=1000), patch.object(Fedora,'preparar',side_effect=KeyboardInterrupt), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(['preparar-dnf5']),130)


if __name__=='__main__':unittest.main()
