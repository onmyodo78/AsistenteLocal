"""Ejecución APT exclusivamente simulada. Ninguna prueba instancia un PM real."""
import contextlib
import copy
import io
import json
import hashlib
import sys
import types
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import Mock,patch

import autorizacion_apt as aut
import ejecucion_apt as motor
import apt_ejecucion_nativa as nativo
import cliente_ejecucion_apt as cliente
import ejecutor_apt as helper
import cli
from contratos_mantenimiento import base,finalizar,paquete
from registro_mantenimiento import Registro,historial

INSTALAR_NATIVO=nativo.AptNativo.instalar


def plan():
    p=base('debian13','apt','plan')
    p['estado']='completo'
    p['capacidades']=dict(consulta=True,simulacion=True,ejecucion=False,solo_cache=True,sin_red=True)
    p['candidatas'].update(estado='completo',paquetes=[paquete('ejemplo','amd64','1','2')])
    p['simulacion'].update(estado='completo',retenciones_estado='completo',no_actualizados_total=0,
                           actualizaciones=[paquete('ejemplo','amd64','1','2')])
    p['comparacion']['estado']='completa'
    return finalizar(p)


class SinEjecucion(unittest.TestCase):
    def setUp(self):
        for objeto,nombre in ((nativo.subprocess,'Popen'),(nativo.AptNativo,'instalar')):
            p=patch.object(objeto,nombre,side_effect=AssertionError('Ejecución real prohibida'))
            p.start();self.addCleanup(p.stop)


class Autorizacion(SinEjecucion):
    def test_contrato_vigencia_identidad_y_hash(self):
        p=aut.crear_peticion(plan(),1000)
        self.assertEqual(aut.validar_peticion(p,1000),p)
        self.assertIn(p['digest'],aut.frase(p))
        for mutacion in ('uid','digest','plan','creado','politica'):
            q=copy.deepcopy(p)
            if mutacion=='uid':q['uid']=1001
            elif mutacion=='digest':q['digest']='0'*64
            elif mutacion=='plan':q['plan']['simulacion']['actualizaciones'][0]['propuesta']='9'
            elif mutacion=='creado':q['creado']-=aut.VIGENCIA+1
            else:q['politica']['solo_cache']=False
            with self.subTest(mutacion=mutacion),self.assertRaises(ValueError):aut.validar_peticion(q,1000)

    def test_rechaza_ampliar_alcance_y_backend(self):
        for cambio in ('fedora','eliminar','instalar','vacio','retenido'):
            d=plan()
            if cambio=='fedora':d['distribucion']='fedora';d['gestor']='dnf'
            elif cambio=='eliminar':d['simulacion']['eliminaciones']=[paquete('otro','amd64','1',None)]
            elif cambio=='instalar':d['simulacion']['instalaciones']=[paquete('otro','amd64',None,'1')]
            elif cambio=='vacio':d['simulacion']['actualizaciones']=[]
            else:d['simulacion']['retenciones']=[paquete('ejemplo','amd64','1',None)]
            finalizar(d)
            with self.assertRaises(ValueError):aut.crear_peticion(d,1000)

    def test_claves_duplicadas_y_sin_confirmacion_en_contrato(self):
        with self.assertRaises(ValueError):aut.leer_json('{"uid":1,"uid":2}')
        p=aut.crear_peticion(plan(),1000)
        p['confirmado']=True
        with self.assertRaises(ValueError):aut.validar_peticion(p,1000)


class Flujo(SinEjecucion):
    def setUp(self):
        super().setUp()
        self.temporal=tempfile.TemporaryDirectory()
        self.addCleanup(self.temporal.cleanup)
        self.registro=Registro(self.temporal.name,uid=os.getuid()).__enter__()
        self.addCleanup(self.registro.__exit__,None,None,None)
        self.p=aut.crear_peticion(plan(),1000)
        self.native=Mock()
        self.native.bloqueo.return_value=contextlib.nullcontext()
        self.native.simular.return_value=dict(simulacion=copy.deepcopy(self.p['plan']['simulacion']),
                                               candidatas=copy.deepcopy(self.p['plan']['candidatas']['paquetes']))
        self.native.instalar.return_value=(True,{'codigo':0})
        self.native.verificar.return_value=True

    def ejecutar(self,confirmacion=True):
        return motor.ejecutar(self.p,1000,self.native,self.registro,lambda p:confirmacion)

    def test_exito_orden_revalidacion_y_sqlite(self):
        r=self.ejecutar()
        self.assertEqual(r['estado'],'completo')
        nombres=[c[0] for c in self.native.mock_calls]
        self.assertLess(nombres.index('simular'),nombres.index('instalar'))
        self.assertLess(nombres.index('marcar_y_comprobar'),nombres.index('instalar'))
        self.assertLess(nombres.index('preparar_archivos'),nombres.index('instalar'))
        fila=self.registro.db.execute('SELECT plan_json,estado,resultado_json FROM operaciones').fetchone()
        self.assertEqual(json.loads(fila[0]),self.p['plan'])
        self.assertEqual(fila[1],'completo')
        self.assertTrue(json.loads(fila[2])['verificacion'])
        self.native.instalar.assert_called_once()

    def test_sin_confirmacion_no_hay_instalacion_ni_registro(self):
        self.assertEqual(self.ejecutar(False)['error'],'confirmacion_rechazada')
        self.native.bloqueo.assert_not_called()
        self.assertEqual(self.registro.db.execute('SELECT COUNT(*) FROM operaciones').fetchone()[0],0)

    def test_plan_cambiado_cancela_sin_ejecutar(self):
        self.native.simular.return_value['simulacion']['actualizaciones'][0]['propuesta']='3'
        self.assertEqual(self.ejecutar()['error'],'plan_modificado')
        self.native.instalar.assert_not_called()
        self.assertEqual(self.registro.db.execute('SELECT estado FROM operaciones').fetchone()[0],'cancelado')

    def test_candidatas_cambiadas_cancelan(self):
        self.native.simular.return_value['candidatas']=[]
        self.assertEqual(self.ejecutar()['error'],'candidatas_modificadas')
        self.native.instalar.assert_not_called()

    def test_bloqueos_nativos_se_notifican(self):
        self.native.bloqueo.side_effect=BlockingIOError()
        self.assertEqual(self.ejecutar()['error'],'gestor_bloqueado')
        self.native.instalar.assert_not_called()

    def test_dpkg_incompleto_no_se_repara(self):
        self.native.comprobar_sistema.side_effect=ValueError('dpkg_incompleto')
        self.assertEqual(self.ejecutar()['error'],'dpkg_incompleto')
        self.native.instalar.assert_not_called()
        self.native.simular.assert_not_called()

    def test_caches_incompletas_no_descargan(self):
        self.native.preparar_archivos.side_effect=ValueError('paquetes_no_cacheados')
        self.assertEqual(self.ejecutar()['error'],'paquetes_no_cacheados')
        self.native.instalar.assert_not_called()

    def test_transaccion_seleccionada_diferente_cancela(self):
        self.native.marcar_y_comprobar.side_effect=ValueError('transaccion_nativa_diferente')
        self.assertEqual(self.ejecutar()['error'],'transaccion_nativa_diferente')
        self.native.instalar.assert_not_called()

    def test_una_sola_ejecucion_por_identificador(self):
        self.ejecutar()
        self.assertEqual(self.ejecutar()['error'],'autorizacion_consumida')
        self.native.instalar.assert_called_once()

    def test_transaccion_incompleta_impide_reintento_automatico(self):
        self.native.instalar.return_value=(False,{'codigo':1})
        self.assertEqual(self.ejecutar()['estado'],'incompleto')
        self.p=aut.crear_peticion(plan(),1000)
        self.assertEqual(self.ejecutar()['error'],'operacion_pendiente_revision')
        self.native.instalar.assert_called_once()

    def test_version_final_no_coincidente_no_es_exito(self):
        self.native.verificar.return_value=False
        self.assertEqual(self.ejecutar()['estado'],'incompleto')

    def test_interrupcion_despues_de_empezar_es_desconocida(self):
        self.native.instalar.side_effect=KeyboardInterrupt()
        self.assertEqual(self.ejecutar()['estado'],'resultado_desconocido')
        self.native.instalar.assert_called_once()

    def test_error_registro_inicial_impide_tocar_apt(self):
        with patch.object(self.registro,'iniciar',side_effect=sqlite3.OperationalError('lleno')):
            self.assertEqual(self.ejecutar()['estado'],'cancelado')
        self.native.bloqueo.assert_not_called()

    def test_error_registro_antes_de_instalar_impide_modificaciones(self):
        fase=self.registro.fase
        def fallo(ident,estado,detalle=None):
            if estado=='ejecutando':raise sqlite3.OperationalError('lleno')
            fase(ident,estado,detalle)
        with patch.object(self.registro,'fase',side_effect=fallo):self.ejecutar()
        self.native.instalar.assert_not_called()

    def test_fallo_registro_final_no_declara_exito(self):
        with patch.object(self.registro,'finalizar',side_effect=sqlite3.OperationalError('lleno')):
            r=self.ejecutar()
        self.assertEqual(r['estado'],'resultado_desconocido')
        self.assertEqual(r['error'],'registro_final_no_confirmado')

    def test_historial_solo_lectura(self):
        self.ejecutar()
        filas=historial(Path(self.temporal.name),uid=os.getuid())
        self.assertEqual(filas[0]['estado'],'completo')
        self.assertEqual(filas[0]['id'],self.p['id'])


class Frontera(SinEjecucion):
    def test_checkout_no_puede_ser_ejecutor_privilegiado(self):
        with self.assertRaises(PermissionError):helper.verificar_instalacion()
        with contextlib.redirect_stdout(io.StringIO()) as s:
            self.assertEqual(helper.main(['ejecutar']),1)
        self.assertEqual(json.loads(s.getvalue())['error'],'instalacion_no_protegida')

    def test_no_admite_argv_libres(self):
        with contextlib.redirect_stdout(io.StringIO()) as s:
            self.assertEqual(helper.main(['ejecutar','--yes']),1)
        self.assertEqual(json.loads(s.getvalue())['error'],'operacion_no_autorizada')

    def test_confirmacion_es_terminal_no_stdin_json(self):
        p=aut.crear_peticion(plan(),1000)
        tty=Mock()
        tty.__enter__=Mock(return_value=tty);tty.__exit__=Mock()
        tty.readline.return_value='si\n'
        with patch.object(aut,'abrir_tty_confirmacion',return_value=tty) as abrir:
            self.assertFalse(helper.confirmar_tty(p))
        abrir.assert_called_once_with()
        tty.readline.return_value=aut.frase(p)+'\n'
        with patch.object(aut,'abrir_tty_confirmacion',return_value=tty):self.assertTrue(helper.confirmar_tty(p))

    def test_cliente_no_invoca_sudo_si_helper_no_instalado(self):
        with patch.object(cliente.HELPER.__class__,'is_file',return_value=False):
            self.assertEqual(cliente.invocar('comprobar')['error'],'ejecutor_no_instalado')

    def test_cliente_catalogo_fijo_y_sin_password_por_stdin(self):
        p=aut.crear_peticion(plan(),1000)
        proceso=Mock(returncode=0)
        proceso.communicate.return_value=(json.dumps(dict(version=1,id=p['id'],estado='completo')).encode(),None)
        with patch.object(cliente.HELPER.__class__,'is_file',return_value=True), \
             patch.object(cliente,'comprobar_proteccion',return_value=True), \
             patch.object(cliente.subprocess,'Popen',return_value=proceso) as crear:
            self.assertEqual(cliente.invocar('ejecutar',p)['estado'],'completo')
        comando=crear.call_args.args[0]
        self.assertEqual(comando,['/usr/bin/sudo','-k','--','/usr/bin/python3','-I','-S','-B',str(cliente.HELPER),'ejecutar'])
        self.assertNotIn('-S',comando[:comando.index('--')])
        self.assertNotIn('shell',crear.call_args.kwargs)
        self.assertEqual(json.loads(proceso.communicate.call_args.kwargs['input']),p)

    def test_cli_rechaza_fedora_antes_de_sudo(self):
        p=plan();p['distribucion']='fedora';p['gestor']='dnf';finalizar(p)
        with patch.object(cli,'consultar',return_value=p), \
             patch.object(cli.os,'geteuid',return_value=1000), \
             patch.object(cliente,'actualizar') as actualizar,contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(['actualizar-apt']),1)
        actualizar.assert_not_called()

    def test_cli_comprobar_no_instala_ni_actualiza(self):
        with patch.object(cli.os,'geteuid',return_value=1000), \
             patch.object(cliente,'invocar',return_value=dict(version=1,estado='preparado')) as invocar, \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(['comprobar-ejecucion-apt']),0)
        invocar.assert_called_once_with('comprobar')


class NativoSinTransaccion(SinEjecucion):
    def test_operaciones_de_lectura_son_lista_cerrada(self):
        with self.assertRaises(ValueError):nativo.lectura(['/usr/bin/apt-get','upgrade'])

    def test_transaccion_que_intenta_eliminar_es_rechazada(self):
        apt=nativo.AptNativo()
        apt.pkg=Mock();apt.pkg.version_compare.return_value=1
        paquete_nativo=Mock(marked_upgrade=True,marked_delete=True,marked_downgrade=False,marked_reinstall=False)
        apt.cache=Mock();apt.cache.get_changes.return_value=[paquete_nativo]
        with self.assertRaisesRegex(ValueError,'transaccion_nativa_diferente'):apt.marcar_y_comprobar(plan())

    def test_sin_confianza_no_prepara_pm_ni_descarga(self):
        apt=nativo.AptNativo();apt.pkg=Mock()
        apt.versiones=[Mock(origins=[],sha256='f'*64)]
        with self.assertRaisesRegex(ValueError,'archivos_no_verificados'):apt.preparar_archivos()
        apt.pkg.PackageManager.assert_not_called()
        apt.pkg.Acquire.assert_not_called()

    def test_downgrade_se_rechaza(self):
        apt=nativo.AptNativo();apt.pkg=Mock();apt.pkg.version_compare.return_value=-1
        apt.cache=Mock()
        with self.assertRaisesRegex(ValueError,'version_no_superior'):apt.marcar_y_comprobar(plan())
        apt.cache.upgrade.assert_not_called()


class RegistroSeguro(SinEjecucion):
    def test_symlink_no_se_acepta_como_base(self):
        with tempfile.TemporaryDirectory() as tmp:
            origen=Path(tmp,'fuera');origen.write_text('intacto')
            d=Path(tmp,'diario');d.mkdir(mode=0o700)
            Path(d,'mantenimiento.sqlite3').symlink_to(origen)
            with self.assertRaises((PermissionError,OSError)):
                with Registro(d,uid=os.getuid()):pass
            self.assertEqual(origen.read_text(),'intacto')

    def test_otro_proceso_no_toma_el_diario_y_no_se_borran_bloqueos(self):
        with tempfile.TemporaryDirectory() as tmp:
            with Registro(tmp,uid=os.getuid()):
                with self.assertRaises(BlockingIOError):
                    with Registro(tmp,uid=os.getuid()):pass
            self.assertTrue(Path(tmp,'ejecucion.lock').exists())

    def test_diario_sobrevive_a_reapertura(self):
        p=aut.crear_peticion(plan(),1000)
        with tempfile.TemporaryDirectory() as tmp:
            with Registro(tmp,uid=os.getuid()) as r:
                r.iniciar(p);r.finalizar(p['id'],'completo',resultado={'verificacion':True})
            self.assertEqual(historial(Path(tmp),uid=os.getuid())[0]['estado'],'completo')
            self.assertEqual(Path(tmp,'mantenimiento.sqlite3').stat().st_mode&0o777,0o600)


class CasosNativos(SinEjecucion):
    def preparar(self,contenido,hash_correcto=True,completo=True):
        apt=nativo.AptNativo();apt.pkg=Mock();apt.cache=Mock()
        checksum=hashlib.sha256(contenido).hexdigest() if hash_correcto else '0'*64
        apt.versiones=[Mock(origins=[Mock(trusted=True)],sha256=checksum,size=len(contenido))]
        acq=Mock();acq.items=[Mock(complete=completo,is_trusted=True)]
        apt.pkg.Acquire.return_value=acq
        apt.pkg.PackageManager.return_value.get_archives.return_value=True
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp,'ejemplo_2_amd64.deb');p.write_bytes(contenido);p.chmod(0o600)
            acq.items[0].destfile=str(p)
            fstat=os.fstat
            def datos(fd):
                st=fstat(fd)
                return types.SimpleNamespace(st_mode=st.st_mode,st_uid=0,st_nlink=1,st_size=st.st_size)
            path_real=Path
            with patch.object(nativo,'Path',side_effect=lambda v: path_real(tmp) if v=='/var/cache/apt/archives' else path_real(v)),patch.object(nativo.os,'fstat',side_effect=datos):
                apt.preparar_archivos()
        apt.pkg.Acquire.return_value.run.assert_not_called()
        apt.cache.commit.assert_not_called()
        return apt

    def test_archivo_cacheado_verifica_hash_y_no_descarga(self):
        self.preparar(b'archivo sintetico')

    def test_hash_modificado_no_ejecuta(self):
        with self.assertRaisesRegex(ValueError,'paquetes_no_cacheados'):self.preparar(b'archivo sintetico',False)

    def test_adquisicion_incompleta_no_se_ejecuta(self):
        with self.assertRaisesRegex(ValueError,'paquetes_no_cacheados'):self.preparar(b'archivo sintetico',completo=False)

    def test_version_final_cambia_otro_paquete_no_es_exito(self):
        apt=nativo.AptNativo()
        apt.antes=[dict(nombre_binario='ejemplo',arquitectura='amd64',version='1',categoria='instalado')]
        despues=[dict(nombre_binario='ejemplo',arquitectura='amd64',version='2',categoria='instalado'),
                 dict(nombre_binario='extra',arquitectura='amd64',version='1',categoria='instalado')]
        with patch.object(nativo,'lectura',return_value=''),patch.object(nativo,'inventario_local',return_value=despues):
            self.assertFalse(apt.verificar(plan()))

    def test_version_final_exacta(self):
        apt=nativo.AptNativo()
        apt.antes=[dict(nombre_binario='ejemplo',arquitectura='amd64',version='1',categoria='instalado')]
        despues=[dict(nombre_binario='ejemplo',arquitectura='amd64',version='2',categoria='instalado')]
        with patch.object(nativo,'lectura',return_value=''),patch.object(nativo,'inventario_local',return_value=despues):
            self.assertTrue(apt.verificar(plan()))


class Bootstrap(SinEjecucion):
    def test_cliente_no_ejecuta_un_helper_modificable(self):
        with patch.object(cliente.HELPER.__class__,'is_file',return_value=True), \
             patch.object(cliente,'comprobar_proteccion',return_value=False), \
             patch.object(cliente.subprocess,'Popen') as popen:
            self.assertEqual(cliente.invocar('ejecutar')['error'],'instalacion_no_protegida')
        popen.assert_not_called()

    def test_declinar_no_crea_registro_protegido(self):
        apt=types.ModuleType('apt');pkg=types.ModuleType('apt_pkg')
        for n in ('SystemLock','FileLock','PackageManager','pkgsystem_unlock_inner'):setattr(pkg,n,Mock())
        entrada=Mock();entrada.buffer.read.return_value=json.dumps(aut.crear_peticion(plan(),1000)).encode()
        with patch.object(helper,'verificar_instalacion'),patch.object(helper,'preparar_imports'), \
             patch.dict(sys.modules,{'apt':apt,'apt_pkg':pkg}), \
             patch('distribucion_linux.detectar_distribucion',return_value=dict(estado='soportado',id='debian',version_id='13')), \
             patch.dict(os.environ,{'SUDO_UID':'1000'}), \
             patch.object(helper.sys,'path',list(sys.path)),patch.object(helper.sys,'stdin',entrada), \
             patch.object(helper.os,'geteuid',return_value=0),patch.object(helper,'confirmar_tty',return_value=False), \
             patch('registro_mantenimiento.Registro') as registro,contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(helper.main(['ejecutar']),1)
        registro.assert_not_called()

    def test_comprobar_no_necesita_sudo_ni_escribe_diario(self):
        apt=types.ModuleType('apt');pkg=types.ModuleType('apt_pkg')
        for n in ('SystemLock','FileLock','PackageManager','pkgsystem_unlock_inner'):setattr(pkg,n,Mock())
        with patch.object(helper,'verificar_instalacion'),patch.object(helper,'preparar_imports'),patch.dict(sys.modules,{'apt':apt,'apt_pkg':pkg}), \
             patch('distribucion_linux.detectar_distribucion',return_value=dict(estado='soportado',id='debian',version_id='13')), \
             patch.dict(os.environ,{}),patch.object(helper.sys,'path',list(sys.path)), \
             patch('registro_mantenimiento.Registro') as registro,contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(helper.main(['comprobar']),0)
        registro.assert_not_called()


class InstaladorSoloSimulado(SinEjecucion):
    def modulos_apt(self):
        apt=types.ModuleType('apt');apt.__path__=[]
        progreso=types.ModuleType('apt.progress');progreso.__path__=[]
        base=types.ModuleType('apt.progress.base')
        base.InstallProgress=type('InstallProgress',(),{})
        progreso.base=base;apt.progress=progreso
        return {'apt':apt,'apt.progress':progreso,'apt.progress.base':base}

    def test_llama_a_install_archives_una_vez_no_a_commit(self):
        objeto=nativo.AptNativo();objeto.cache=Mock();objeto.pm=Mock(RESULT_COMPLETED=0)
        objeto.cache.install_archives.return_value=0
        with patch.dict(sys.modules,self.modulos_apt()), \
             patch.object(nativo,'capturar_salida',return_value=contextlib.nullcontext(bytearray(b'evidencia'))), \
             patch.object(nativo.signal,'signal') as signal:
            correcto,evidencia=INSTALAR_NATIVO(objeto)
        self.assertTrue(correcto)
        self.assertEqual(evidencia['salida_nativa_no_interpretada'],'evidencia')
        objeto.cache.install_archives.assert_called_once()
        objeto.cache.commit.assert_not_called()
        self.assertEqual(signal.call_count,4)

    def test_error_del_instalador_siempre_restaura_senales(self):
        objeto=nativo.AptNativo();objeto.cache=Mock();objeto.pm=Mock(RESULT_COMPLETED=0)
        objeto.cache.install_archives.side_effect=RuntimeError('simulado')
        with patch.dict(sys.modules,self.modulos_apt()), \
             patch.object(nativo,'capturar_salida',return_value=contextlib.nullcontext(bytearray(b'fallo'))), \
             patch.object(nativo.signal,'signal') as signal:
            with self.assertRaises(RuntimeError):INSTALAR_NATIVO(objeto)
        self.assertEqual(signal.call_count,4)
        self.assertEqual(objeto.ultima_salida,'fallo')

    def test_captura_nativa_acotada_sin_ejecutar_comandos(self):
        with nativo.capturar_salida() as salida:
            os.write(1,b'x'*70000+b'fin')
        self.assertLessEqual(len(salida),65536)
        self.assertTrue(bytes(salida).endswith(b'fin'))


class ComunicacionSegura(SinEjecucion):
    def test_error_cliente_no_afirma_ausencia_de_modificaciones(self):
        with patch.object(cli,'consultar',return_value=plan()),patch.object(cli.os,'geteuid',return_value=1000), \
             patch.object(cliente,'actualizar',side_effect=OSError('conexion perdida')), \
             contextlib.redirect_stdout(io.StringIO()) as salida,contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(['actualizar-apt']),1)
        self.assertEqual(json.loads(salida.getvalue())['estado'],'resultado_desconocido')
        self.assertNotIn('no se modifican paquetes',salida.getvalue())

    def test_cliente_no_mata_el_proceso_ante_ctrl_c(self):
        proceso=Mock(returncode=1)
        proceso.communicate.side_effect=[KeyboardInterrupt(),(b'{"version":1,"estado":"cancelado"}',None)]
        with patch.object(cliente.HELPER.__class__,'is_file',return_value=True), \
             patch.object(cliente,'comprobar_proteccion',return_value=True), \
             patch.object(cliente.subprocess,'Popen',return_value=proceso), \
             contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cliente.invocar('ejecutar',aut.crear_peticion(plan(),1000))['estado'],'cancelado')
        proceso.kill.assert_not_called();proceso.terminate.assert_not_called()


class RevisionFinal(SinEjecucion):
    def test_helper_exige_interprete_aislado_sin_site(self):
        for aislado,site in ((0,0),(1,0),(0,1)):
            with patch.object(helper.sys,'flags',types.SimpleNamespace(isolated=aislado,no_site=site)):
                with self.assertRaisesRegex(PermissionError,'python_no_aislado'):
                    helper.preparar_imports()

    def test_codigo_protegido_rechaza_modulos_y_padres_inseguros(self):
        import stat
        raiz=Path('/usr/local/lib/asistentelocal')
        archivo=raiz/'ejecucion_apt.py'
        for objeto in (archivo,raiz,raiz.parent):
            for defecto in ('usuario','escritura','enlace'):
                def datos(p):
                    directorio=p not in [raiz/n for n in helper.ARCHIVOS]
                    modo=(stat.S_IFDIR|0o755) if directorio else (stat.S_IFREG|0o644)
                    uid=0
                    if p==objeto:
                        if defecto=='usuario':uid=1000
                        elif defecto=='escritura':modo|=0o020
                        else:modo=stat.S_IFLNK|0o777
                    return types.SimpleNamespace(st_mode=modo,st_uid=uid,st_nlink=1)
                with self.subTest(objeto=objeto,defecto=defecto), \
                     patch.object(helper,'__file__',str(raiz/'ejecutor_apt.py')), \
                     patch.object(helper.Path,'lstat',datos), \
                     patch.object(helper.Path,'iterdir',return_value=iter([raiz/n for n in helper.ARCHIVOS])):
                    with self.assertRaisesRegex(PermissionError,'instalacion_no_protegida'):
                        helper.verificar_instalacion()

    def test_hash_valido_en_otro_archivo_no_acredita_destino_apt(self):
        contenido=b'correcto'
        apt=nativo.AptNativo();apt.pkg=Mock();apt.cache=Mock()
        apt.versiones=[Mock(origins=[Mock(trusted=True)],sha256=hashlib.sha256(contenido).hexdigest(),size=len(contenido))]
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp,'otro.deb').write_bytes(contenido)
            destino=Path(tmp,'seleccionado.deb');destino.write_bytes(b'alterado');destino.chmod(0o600)
            apt.pkg.Acquire.return_value.items=[Mock(complete=True,is_trusted=True,destfile=str(destino))]
            apt.pkg.PackageManager.return_value.get_archives.return_value=True
            path_real=Path;fstat=os.fstat
            def datos(fd):
                st=fstat(fd)
                return types.SimpleNamespace(st_mode=st.st_mode,st_uid=0,st_nlink=1,st_size=st.st_size)
            with patch.object(nativo,'Path',side_effect=lambda v:path_real(tmp) if v=='/var/cache/apt/archives' else path_real(v)), \
                 patch.object(nativo.os,'fstat',side_effect=datos):
                with self.assertRaisesRegex(ValueError,'paquetes_no_cacheados'):apt.preparar_archivos()
        apt.pkg.Acquire.return_value.run.assert_not_called()

    def test_caida_con_diario_pendiente_impide_nueva_autorizacion(self):
        with tempfile.TemporaryDirectory() as tmp:
            with Registro(tmp,uid=os.getuid()) as r:
                p=aut.crear_peticion(plan(),1000);r.iniciar(p);r.fase(p['id'],'ejecutando')
            with Registro(tmp,uid=os.getuid()) as r:
                with self.assertRaisesRegex(ValueError,'operacion_pendiente_revision'):
                    r.iniciar(aut.crear_peticion(plan(),1000))

    def test_hijo_muerto_por_senal_no_devuelve_exito(self):
        modulos=InstaladorSoloSimulado().modulos_apt()
        modulos['apt.progress.base'].InstallProgress.wait_child=lambda self:9
        objeto=nativo.AptNativo();objeto.cache=Mock();objeto.pm=Mock(RESULT_COMPLETED=0)
        objeto.cache.install_archives.side_effect=lambda pm,progreso:os.WEXITSTATUS(progreso.wait_child())
        with patch.dict(sys.modules,modulos), \
             patch.object(nativo,'capturar_salida',return_value=contextlib.nullcontext(bytearray())), \
             patch.object(nativo.signal,'signal'):
            with self.assertRaisesRegex(RuntimeError,'instalador_interrumpido'):INSTALAR_NATIVO(objeto)

    @unittest.skipUnless(Path('/usr/lib/python3/dist-packages/apt/cache.py').is_file(),'python3-apt no instalado')
    def test_api_instalada_libera_y_recupera_bloqueo_interior(self):
        # Ejecutar solo este método de la fuente instalada con apt_pkg simulado.
        # No importar/invocar el gestor real ni adquirir bloqueos del sistema.
        import ast
        fuente=ast.parse(Path('/usr/lib/python3/dist-packages/apt/cache.py').read_text())
        clase=next(n for n in fuente.body if isinstance(n,ast.ClassDef) and n.name=='Cache')
        metodo=next(n for n in clase.body if isinstance(n,ast.FunctionDef) and n.name=='install_archives')
        metodo.returns=None
        for argumento in metodo.args.args:argumento.annotation=None
        pkg=Mock();pkg.pkgsystem_is_locked.return_value=True
        eventos=[]
        pkg.pkgsystem_unlock_inner.side_effect=lambda:eventos.append('liberar_interior')
        pkg.pkgsystem_lock_inner.side_effect=lambda:eventos.append('recuperar_interior')
        espacio={'apt_pkg':pkg}
        exec(compile(ast.Module(body=[metodo],type_ignores=[]),'<API instalada>','exec'),espacio)
        progreso=Mock();progreso.run.side_effect=lambda pm:eventos.append('instalar') or 0
        self.assertEqual(espacio['install_archives'](None,Mock(),progreso),0)
        self.assertEqual(eventos,['liberar_interior','instalar','recuperar_interior'])
        progreso.run.side_effect=RuntimeError('fallo simulado')
        eventos.clear()
        with self.assertRaises(RuntimeError):espacio['install_archives'](None,Mock(),progreso)
        self.assertEqual(eventos,['liberar_interior','recuperar_interior'])


    @unittest.skipUnless(Path('/usr/lib/python3/dist-packages/apt').is_dir() and Path('/usr/lib/python'+str(sys.version_info.major)+'.'+str(sys.version_info.minor)).is_dir(),'rutas Python Debian no disponibles')
    def test_imports_descartan_rutas_heredadas_y_verifican_modulos(self):
        import stat
        lstat=Path.lstat
        def confiable(p):
            st=lstat(p)
            return types.SimpleNamespace(st_mode=st.st_mode,st_uid=0,st_nlink=st.st_nlink)
        # El sandbox representa los archivos del sistema con otro UID. Solo se
        # simula esa propiedad; las rutas y tipos se inspeccionan realmente.
        with patch.object(helper.sys,'flags',types.SimpleNamespace(**{**{k:getattr(sys.flags,k) for k in dir(sys.flags) if not k.startswith('_')},'isolated':1,'no_site':1})), \
             patch.object(helper.sys,'path',['','/tmp/ruta-usuario','/proyecto/editable']), \
             patch.object(helper.Path,'lstat',confiable):
            helper.preparar_imports()
            self.assertEqual(sys.path[0],str(helper.INSTALACION))
            self.assertEqual(sys.path[-1],'/usr/lib/python3/dist-packages')
            self.assertNotIn('/tmp/ruta-usuario',sys.path)
            self.assertNotIn('',sys.path)

    def test_lock_apt_enlazado_o_modificable_se_rechaza_antes_de_bloquear(self):
        import stat
        for modo,uid,nlink in ((stat.S_IFLNK|0o777,0,1),
                                (stat.S_IFREG|0o666,0,1),
                                (stat.S_IFREG|0o644,1000,1),
                                (stat.S_IFREG|0o644,0,2)):
            apt=Mock();pkg=Mock()
            with patch.dict(sys.modules,{'apt':apt,'apt_pkg':pkg}), \
                 patch.object(nativo,'verificar_directorio_root'), \
                 patch.object(Path,'lstat',return_value=types.SimpleNamespace(st_mode=modo,st_uid=uid,st_nlink=nlink)):
                with self.assertRaisesRegex(ValueError,'configuracion_no_admitida'):
                    with nativo.AptNativo().bloqueo():pass
            pkg.SystemLock.assert_not_called()


class ArranqueInterprete(unittest.TestCase):
    def test_arranque_rechaza_pythonpath_antes_de_importar_json(self):
        # Solo se inicia Python sin privilegios; nunca APT, sudo ni el instalador.
        import subprocess
        ruta=Path(helper.__file__).absolute()
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp,'json.py').write_text('raise RuntimeError("IMPORTACION_USUARIO")')
            entorno=dict(os.environ,PYTHONPATH=tmp)
            r=subprocess.run(['/usr/bin/python3','-B',str(ruta),'comprobar'],
                             cwd=tmp,env=entorno,capture_output=True,timeout=10)
        self.assertEqual(r.returncode,1)
        self.assertEqual(json.loads(r.stdout)['error'],'python_no_aislado')
        self.assertNotIn(b'IMPORTACION_USUARIO',r.stderr)

    def test_arranque_aislado_rechaza_checkout_sin_importar_apt(self):
        import subprocess
        r=subprocess.run(['/usr/bin/python3','-I','-S','-B',str(Path(helper.__file__).absolute()),'comprobar'],
                         capture_output=True,timeout=10)
        self.assertEqual(r.returncode,1)
        self.assertEqual(json.loads(r.stdout)['error'],'instalacion_no_protegida')
