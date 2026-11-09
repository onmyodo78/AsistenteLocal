"""Mantenimiento Fedora simulado: ninguna llamada real a sudo, DNF5 o RPM."""
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import Mock,patch

import mantenimiento_dnf5 as perfil
import dnf5_interactivo as nativo
import ejecucion_apt as coordinador
import cliente_ejecucion_apt as cliente
import ejecutor_apt as helper
import despliegue_helper_apt as despliegue
from contratos_mantenimiento import base,finalizar,paquete
from registro_mantenimiento import Registro,historial


FEDORA={'estado':'soportado','id':'fedora','version_id':'45'}


def consulta(estado='completo'):
    d=base('fedora','dnf5','actualizaciones')
    d['estado']=estado
    d['candidatas'].update(estado=estado,paquetes=[paquete('uno','x86_64','0:1-1.fc45','0:2-1.fc45')])
    return finalizar(d)


class BackendSimulado:
    def __init__(self,codigo=0,cambios=2,verificado=True):
        self.codigo=codigo;self.cambios=cambios;self.verificado=verificado;self.llamadas=[]
        self.verificacion={}
    @contextlib.contextmanager
    def bloqueo(self):yield
    def comprobar_sistema(self):self.llamadas.append('sistema')
    def preparar_archivos(self):self.llamadas.append('inventario_antes')
    def instalar(self):self.llamadas.append('dnf5');return self.codigo==0,{'codigo_dnf5':self.codigo}
    def verificar(self,plan):
        self.llamadas.append('inventario_despues_y_check')
        self.verificacion={'cambios_total':self.cambios,'estado':'comprobado' if self.verificado else 'no_verificable'}
        return self.verificado


class Dnf5Interactivo(unittest.TestCase):
    def setUp(self):
        self.pila=contextlib.ExitStack();self.addCleanup(self.pila.close)
        self.pila.enter_context(patch.object(perfil,'detectar_distribucion',return_value=FEDORA))
        self.pila.enter_context(patch.object(nativo.subprocess,'Popen',side_effect=AssertionError('Proceso real prohibido')))
        self.pila.enter_context(patch.object(nativo.subprocess,'run',side_effect=AssertionError('Consulta real prohibida')))
        self.temporal=tempfile.TemporaryDirectory();self.addCleanup(self.temporal.cleanup)
        self.registro=Path(self.temporal.name)/'diario'
        self.p=perfil.crear_peticion(consulta(),1000)

    def ejecutar(self,n=None,confirmar=True,p=None):
        n=BackendSimulado() if n is None else n
        with Registro(self.registro,uid=os.getuid()) as diario:
            return coordinador.ejecutar(self.p if p is None else p,1000,n,diario,lambda p:confirmar,estrategia=perfil)

    def test_solo_fedora45_no_derivados_ni_debian(self):
        for d in ({'estado':'soportado','id':'debian','version_id':'13'},
                  {'estado':'soportado','id':'fedora','version_id':'44'},
                  {'estado':'no_soportado','id':'fedora','version_id':'45'}):
            with self.assertRaisesRegex(ValueError,'fedora45_requerido'):perfil.exigir_fedora45(d)
        perfil.exigir_fedora45(FEDORA)

    def test_consulta_parcial_no_se_presenta_como_transaccion(self):
        d=consulta('parcial');texto=perfil.informe(d)
        self.assertIn('Lista incompleta',texto);self.assertIn('0:2-1.fc45',texto)
        p=perfil.crear_peticion(d,1000);perfil.validar_peticion(p,1000)
        self.assertFalse(p['politica']['plan_previo_vinculante'])
        self.assertIn('No es la transacción definitiva',texto)

    def test_no_confunde_preparador_estricto_con_sesion_interactiva(self):
        d=consulta();d['operacion']='plan';d['estado']='parcial';finalizar(d)
        with self.assertRaisesRegex(ValueError,'consulta_dnf5_requerida'):perfil.crear_peticion(d,1000)
        import dnf5_preparacion as estricto
        with self.assertRaisesRegex(ValueError,'plan_no_verificable'):estricto.comprobar_ejecutable(estricto.resultado('acciones_dnf5_no_admitidas'))

    def test_sobre_compartido_rechaza_alteraciones_uid_tiempo_y_comandos(self):
        for cambiar in ('digest','uid','creado','politica','comando'):
            p=copy.deepcopy(self.p)
            if cambiar=='comando':p['comando']='sudo cualquier_cosa'
            elif cambiar=='politica':p['politica']['confirmacion_nativa']=False
            elif cambiar=='creado':p['creado']-=301
            elif cambiar=='uid':p['uid']=2000
            else:p['digest']='0'*64
            with self.subTest(cambiar=cambiar),self.assertRaises(ValueError):perfil.validar_peticion(p,1000)

    def test_confirmacion_tty_no_acepta_yes_generico(self):
        class Terminal(io.StringIO):
            def readline(self,*args):return 'yes\n'
            def __exit__(self,*args):pass
        terminal=Terminal()
        with patch.object(perfil,'abrir_tty_confirmacion',return_value=terminal):self.assertFalse(perfil.confirmar_tty(self.p))
        texto=terminal.getvalue()
        self.assertIn('NO congela',texto);self.assertIn('DNF5 resolverá',texto)
        self.assertIn(perfil.frase(self.p),texto)

    def test_frase_exacta_solo_autoriza_inicio(self):
        class Terminal(io.StringIO):
            def readline(t,*args):return perfil.frase(self.p)+'\n'
        with patch.object(perfil,'abrir_tty_confirmacion',return_value=Terminal()):self.assertTrue(perfil.confirmar_tty(self.p))

    def test_cancelacion_humana_no_invoca_backend_ni_registra_autorizacion(self):
        n=BackendSimulado();r=self.ejecutar(n,False)
        self.assertEqual(r['estado'],'cancelado');self.assertEqual(n.llamadas,[])
        self.assertEqual(historial(self.registro,uid=os.getuid()),[])

    def test_exito_diario_y_comprobacion_posterior(self):
        n=BackendSimulado();r=self.ejecutar(n)
        self.assertEqual(r['estado'],'completo')
        self.assertEqual(n.llamadas,['sistema','inventario_antes','dnf5','inventario_despues_y_check'])
        self.assertEqual(r['resultado']['equivalencia_con_plan_previo'],'no_afirmada')
        self.assertEqual(r['resultado']['progreso']['codigo_dnf5'],0)
        self.assertEqual(historial(self.registro,uid=os.getuid())[0]['estado'],'completo')

    def test_dnf5_error_sin_cambios_no_inventa_cancelacion(self):
        r=self.ejecutar(BackendSimulado(codigo=1,cambios=0))
        self.assertEqual(r['estado'],'fallido');self.assertEqual(r['error'],'dnf5_no_completo_o_cancelado')

    def test_dnf5_error_tras_cambios_es_incompleto(self):
        self.assertEqual(self.ejecutar(BackendSimulado(codigo=1))['estado'],'incompleto')

    def test_interrupcion_nativa_sin_cambios_es_cancelacion(self):
        self.assertEqual(self.ejecutar(BackendSimulado(codigo=130,cambios=0))['estado'],'cancelado')

    def test_salida_cero_sin_cambios_no_afirma_paquetes_actualizados(self):
        r=self.ejecutar(BackendSimulado(codigo=0,cambios=0))
        self.assertEqual(r['estado'],'completo');self.assertEqual(r['resultado']['verificacion']['cambios_total'],0)
        self.assertNotIn('actualizaciones_instaladas',r['resultado'])

    def test_fallo_verificacion_no_se_declara_exito_y_bloquea_reintento(self):
        r=self.ejecutar(BackendSimulado(verificado=False))
        self.assertEqual(r['estado'],'resultado_desconocido')
        p=perfil.crear_peticion(consulta(),1000);n=BackendSimulado()
        r=self.ejecutar(n,p=p)
        self.assertEqual(r['error'],'operacion_pendiente_revision');self.assertEqual(n.llamadas,[])

    def test_uid_ajeno_rechazado_antes_de_tocar_diario(self):
        p=copy.deepcopy(self.p);p['uid']=1234
        with self.assertRaises(ValueError):self.ejecutar(p=p)

    def test_permisos_insuficientes_antes_de_dnf5(self):
        n=BackendSimulado();n.comprobar_sistema=Mock(side_effect=ValueError('permisos_insuficientes'))
        r=self.ejecutar(n);self.assertEqual(r['estado'],'cancelado')
        self.assertEqual(r['error'],'permisos_insuficientes');self.assertNotIn('dnf5',n.llamadas)

    def test_inventario_previo_fallido_no_arranca_transaccion(self):
        n=BackendSimulado();n.preparar_archivos=Mock(side_effect=ValueError('inventario_rpm_no_verificado'))
        r=self.ejecutar(n);self.assertEqual(r['estado'],'cancelado');self.assertNotIn('dnf5',n.llamadas)

    def test_diario_fallido_antes_de_ejecutar_no_invoca_dnf5(self):
        n=BackendSimulado()
        with Registro(self.registro,uid=os.getuid()) as diario,patch.object(diario,'iniciar',side_effect=OSError('sin espacio')):
            r=coordinador.ejecutar(self.p,1000,n,diario,lambda p:True,estrategia=perfil)
        self.assertEqual(n.llamadas,[]);self.assertEqual(r['estado'],'cancelado')

    def test_error_posterior_conserva_codigo_observado_y_no_guarda_salida_cruda(self):
        n=BackendSimulado();n.verificar=Mock(side_effect=OSError('fallo nativo'))
        n.ultima_salida='dato sensible de terminal'
        r=self.ejecutar(n)
        self.assertEqual(r['estado'],'resultado_desconocido')
        self.assertEqual(r['resultado']['progreso']['codigo_dnf5'],0)
        self.assertNotIn('sensible',json.dumps(r))

    def test_caducidad_durante_confirmacion_impide_arranque(self):
        n=BackendSimulado()
        with Registro(self.registro,uid=os.getuid()) as diario:
            def confirmar(p):p['creado']-=301;return True
            r=coordinador.ejecutar(self.p,1000,n,diario,confirmar,estrategia=perfil)
        self.assertEqual(r['error'],'autorizacion_caducada');self.assertNotIn('dnf5',n.llamadas)

    def test_helper_dnf5_exige_python_aislado_y_rechaza_descarga(self):
        with contextlib.redirect_stdout(io.StringIO()) as salida:
            self.assertEqual(helper.main_dnf5(['descargar']),1)
        self.assertEqual(json.loads(salida.getvalue())['error'],'operacion_no_autorizada')
        with patch.object(helper.sys,'flags',Mock(isolated=False,no_site=False)),contextlib.redirect_stdout(io.StringIO()) as salida:
            self.assertEqual(helper.main_dnf5(['ejecutar']),1)
        self.assertEqual(json.loads(salida.getvalue())['error'],'python_no_aislado')

    def test_fallo_exterior_al_coordinador_no_afirma_cancelacion_tras_posible_ejecucion(self):
        import sqlite3
        with patch.object(helper.sys,'flags',Mock(isolated=True,no_site=True)),patch.object(helper.sys,'path',['/usr/lib']),patch.object(
                helper,'verificar_instalacion'),patch.object(helper.Path,'lstat',return_value=Mock(st_mode=0o40755,st_uid=0)),patch.object(
                perfil,'main_helper',side_effect=sqlite3.OperationalError('dato privado')),contextlib.redirect_stdout(io.StringIO()) as salida:
            self.assertEqual(helper.main_dnf5(['ejecutar']),1)
        r=json.loads(salida.getvalue())
        self.assertEqual(r['estado'],'resultado_desconocido');self.assertNotIn('privado',salida.getvalue())

    def test_permisos_subproceso_se_registran_sin_reintento(self):
        tty=Mock();tty.__enter__=Mock(return_value=tty);tty.__exit__=Mock(return_value=False)
        with patch('builtins.open',return_value=tty),patch.object(nativo.os,'isatty',return_value=True),patch.object(nativo.subprocess,'Popen',side_effect=PermissionError) as popen:
            correcto,progreso=nativo.Dnf5Interactivo().instalar()
        self.assertFalse(correcto);self.assertIsNone(progreso['codigo_dnf5'])
        self.assertEqual(progreso['error'],'permisos_insuficientes');popen.assert_called_once()

    def test_autorizacion_repetida_no_se_ejecuta(self):
        self.ejecutar();n=BackendSimulado();r=self.ejecutar(n)
        self.assertEqual(r['error'],'autorizacion_consumida');self.assertEqual(n.llamadas,[])

    def test_dnf5_recibe_tty_real_sin_pipes_ni_respuestas_automaticas(self):
        tty=Mock();tty.__enter__=Mock(return_value=tty);tty.__exit__=Mock(return_value=False);tty.fileno.return_value=9
        proceso=Mock();proceso.wait.return_value=0
        with patch('builtins.open',return_value=tty),patch.object(nativo.os,'isatty',return_value=True),patch.object(
                nativo.subprocess,'Popen',return_value=proceso) as popen:
            self.assertEqual(nativo.Dnf5Interactivo().instalar(),(True,{'codigo_dnf5':0}))
        args,kwargs=popen.call_args
        self.assertEqual(args[0],nativo.COMANDO)
        self.assertIs(kwargs['stdin'],tty);self.assertIs(kwargs['stdout'],tty);self.assertIs(kwargs['stderr'],tty)
        self.assertNotIn('shell',kwargs);self.assertNotIn('-y',args[0]);self.assertNotIn('--assumeyes',args[0])
        self.assertIn('--setopt=assumeyes=False',args[0]);self.assertIn('--setopt=defaultyes=False',args[0])
        self.assertEqual(kwargs['env']['DNF5_PLUGINS_DIR'],'')

    def test_no_terminal_no_proceso(self):
        tty=Mock();tty.__enter__=Mock(return_value=tty);tty.__exit__=Mock(return_value=False)
        with patch('builtins.open',return_value=tty),patch.object(nativo.os,'isatty',return_value=False),self.assertRaisesRegex(ValueError,'terminal_requerida'):
            nativo.Dnf5Interactivo().instalar()

    def test_ctrl_c_no_mata_ni_repite_dnf5(self):
        tty=Mock();tty.__enter__=Mock(return_value=tty);tty.__exit__=Mock(return_value=False)
        proceso=Mock();proceso.wait.side_effect=[KeyboardInterrupt(),130]
        with patch('builtins.open',return_value=tty),patch.object(nativo.os,'isatty',return_value=True),patch.object(
                nativo.subprocess,'Popen',return_value=proceso) as popen:
            self.assertEqual(nativo.Dnf5Interactivo().instalar()[1]['codigo_dnf5'],130)
        popen.assert_called_once();proceso.kill.assert_not_called();proceso.terminate.assert_not_called()

    def test_inventario_multiversion_y_errores_de_consulta(self):
        limpio=b'kernel-core\tx86_64\t0:1-1.fc45\nkernel-core\tx86_64\t0:2-1.fc45\n'
        with patch.object(nativo,'lectura',return_value=Mock(stdout=limpio,stderr=b'',returncode=0)):
            self.assertEqual(len(nativo.inventario()),2)
        for stdout,stderr,codigo in ((b'tabla humana',b'',0),(b'',b'permiso',1),(limpio,b'aviso',0)):
            with patch.object(nativo,'lectura',return_value=Mock(stdout=stdout,stderr=stderr,returncode=codigo)),self.assertRaises(ValueError):nativo.inventario()

    def test_post_check_fallido_o_aviso_no_se_oculta(self):
        n=nativo.Dnf5Interactivo();n.antes=[paquete('uno','x86_64','0:1-1',None)]
        for codigo,stdout,stderr in ((1,b'conflicto',b''),(0,b'',b'aviso')):
            with patch.object(nativo,'inventario',return_value=n.antes),patch.object(nativo,'lectura',return_value=Mock(returncode=codigo,stdout=stdout,stderr=stderr)):
                self.assertFalse(n.verificar(consulta()))
                self.assertEqual(n.verificacion['codigo_check'],codigo)
                self.assertNotIn('conflicto',json.dumps(n.verificacion))

    def test_post_inventario_inaccesible_resulta_no_verificable(self):
        n=nativo.Dnf5Interactivo()
        with patch.object(nativo,'inventario',side_effect=PermissionError):self.assertFalse(n.verificar(consulta()))
        self.assertIsNone(n.verificacion['cambios_total'])

    def test_comando_no_utiliza_downloadonly_como_opcion_configuracion(self):
        # DNF5 5.4.7 rechaza este setopt antes de resolver una transacción.
        self.assertNotIn('--setopt=downloadonly=False',nativo.COMANDO)
        self.assertFalse(any(x.startswith('--setopt=downloadonly=') for x in nativo.COMANDO))
        self.assertNotIn('--downloadonly',nativo.COMANDO)
        for opcion in ('--setopt=assumeyes=False','--setopt=assumeno=False',
                       '--setopt=defaultyes=False','--no-allow-downgrade'):
            self.assertIn(opcion,nativo.COMANDO)

    def test_aislamiento_conserva_plugins_aplicacion_y_biblioteca_desactivados(self):
        self.assertIn('--no-plugins',nativo.COMANDO)
        self.assertIn('--no-plugins',nativo.CHECK)
        self.assertEqual(nativo.ENTORNO['DNF5_PLUGINS_DIR'],'')

    def test_aviso_alias_con_codigo_cero_no_se_silencia_ni_declara_verificado(self):
        n=nativo.Dnf5Interactivo();n.antes=[paquete('paquete','noarch','0:1-1',None)]
        warning=b'Attached command "builddep" not found: compatibility alias\n'
        with patch.object(nativo,'inventario',return_value=n.antes),patch.object(
                nativo,'lectura',return_value=Mock(returncode=0,stdout=b'',stderr=warning)):
            self.assertFalse(n.verificar({}))
        self.assertEqual(n.verificacion['estado'],'no_verificable')
        self.assertEqual(n.verificacion['stderr_check_bytes'],len(warning))
        self.assertEqual(n.verificacion['cambios_total'],0)
        self.assertNotIn('Attached',json.dumps(n.verificacion))

    def test_diferencias_post_se_limitan_sin_afirmar_lista_completa(self):
        filas=[paquete('p'+str(i),'noarch','0:1-1',None) for i in range(5)]
        with patch.object(nativo,'MAX_CAMBIOS',2):r=nativo.resumen(filas,[])
        self.assertEqual(r['cambios_total'],5);self.assertEqual(len(r['versiones_que_salen']),2)
        self.assertFalse(r['lista_cambios_completa'])

    def test_cliente_reutiliza_sudo_normal_y_helper_dnf5_protegido(self):
        proceso=Mock();proceso.returncode=0
        proceso.communicate.return_value=(json.dumps({'version':1,'estado':'completo','id':self.p['id']}).encode(),None)
        with patch.object(Path,'is_file',return_value=True),patch.object(cliente,'comprobar_proteccion',return_value=True),patch.object(cliente.subprocess,'Popen',return_value=proceso) as popen:
            cliente.invocar('ejecutar',self.p,backend='dnf5')
        self.assertEqual(popen.call_args.args[0],['/usr/bin/sudo','-k','--','/usr/bin/python3','-I','-S','-B',str(cliente.HELPER_DNF5),'ejecutar'])
        self.assertNotIn('-S',popen.call_args.args[0][:3])

    def test_helper_ausente_o_no_protegido_no_invoca_sudo(self):
        with patch.object(Path,'is_file',return_value=False):self.assertEqual(cliente.invocar('ejecutar',self.p,backend='dnf5')['error'],'ejecutor_no_instalado')
        with patch.object(Path,'is_file',return_value=True),patch.object(cliente,'comprobar_proteccion',return_value=False):
            self.assertEqual(cliente.invocar('ejecutar',self.p,backend='dnf5')['error'],'instalacion_no_protegida')
        with self.assertRaises(ValueError):cliente.invocar('descargar',self.p,backend='dnf5')

    def test_cli_generico_detecta_fedora_y_no_confunde_consulta_con_permiso(self):
        import cli
        with patch('distribucion_linux.detectar_distribucion',return_value=FEDORA),patch.object(cli.os,'geteuid',return_value=1000),patch.object(
                cli,'consultar',return_value=consulta('parcial')),patch.object(perfil,'actualizar',return_value={'version':1,'estado':'cancelado'}) as actualizar,contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(['actualizar-dnf5']),1);actualizar.assert_called_once()
        with patch('distribucion_linux.detectar_distribucion',return_value=FEDORA),patch.object(cli.os,'geteuid',return_value=1000),patch.object(
                cli,'consultar',return_value=consulta('parcial')),patch.object(perfil,'actualizar') as actualizar,contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(cli.main(['mantenimiento']),3);actualizar.assert_not_called();self.assertIn('Lista incompleta',out.getvalue())

    def test_cli_dnf5_rechaza_debian_antes_de_escalar(self):
        import cli
        with patch('distribucion_linux.detectar_distribucion',return_value={'estado':'soportado','id':'debian','version_id':'13'}),patch.object(cli.os,'geteuid',return_value=1000),patch.object(perfil,'actualizar') as actualizar,contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(['actualizar-dnf5']),1);actualizar.assert_not_called()

    def test_despliegue_cerrado_fedora_reutiliza_instalador_sin_tocar_apt(self):
        self.assertEqual(set(despliegue.MODULOS_DNF5),set(helper.ARCHIVOS_DNF5))
        origen=Path(self.temporal.name)/'fuente';origen.mkdir()
        for n in despliegue.MODULOS_DNF5:(origen/n).write_text('# prueba inerte\n')
        contenido=''.join(hashlib.sha256((origen/n).read_bytes()).hexdigest()+'  '+n+'\n' for n in despliegue.MODULOS_DNF5)
        manifiesto=origen/'manifest';manifiesto.write_text(contenido)
        padre=Path(self.temporal.name)/'instalacion';padre.mkdir();padre.chmod(0o755)
        destino=padre/'protegido'
        hashes=despliegue.desplegar(origen,manifiesto,hashlib.sha256(contenido.encode()).hexdigest(),destino,os.getuid(),modulos=despliegue.MODULOS_DNF5)
        self.assertEqual(set(hashes),set(despliegue.MODULOS_DNF5))
        with self.assertRaises(ValueError):despliegue.desplegar(origen,manifiesto,hashlib.sha256(contenido.encode()).hexdigest(),destino,os.getuid(),modulos=despliegue.MODULOS_DNF5)

    def test_cli_despliegue_selecciona_destino_y_manifiesto_fijos_dnf5(self):
        hashes={n:'0'*64 for n in despliegue.MODULOS_DNF5}
        argumentos=['despliegue','--origen','/fuente','--manifiesto','/manifest','--sha256-manifiesto','0'*64,'--backend','dnf5']
        with patch.object(despliegue.sys,'argv',argumentos),patch.object(despliegue.sys,'flags',Mock(isolated=True,no_site=True)),patch.object(
                despliegue.os,'geteuid',return_value=0),patch.object(despliegue.os,'umask'),patch.object(despliegue,'verificar_antecesores'),patch.object(
                despliegue,'desplegar',return_value=hashes) as desplegar,contextlib.redirect_stdout(io.StringIO()) as salida:
            despliegue.main()
        self.assertEqual(desplegar.call_args.args[3],despliegue.DESTINO_DNF5)
        self.assertEqual(desplegar.call_args.kwargs['modulos'],despliegue.MODULOS_DNF5)
        self.assertEqual(len(salida.getvalue().splitlines()),1+len(despliegue.MODULOS_DNF5))


if __name__=='__main__':unittest.main()
