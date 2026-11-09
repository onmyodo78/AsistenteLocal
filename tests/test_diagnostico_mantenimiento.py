"""Diagnóstico y descarga simulados; ninguna adquisición real ni sudo."""
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import Mock,patch
import archivos_apt as archivos
import apt_ejecucion_nativa as nativo
import autorizacion_apt as aut
import cli
import diagnostico_mantenimiento as diag
import ejecucion_apt as motor
import ejecutor_apt as helper
from registro_mantenimiento import Registro
from test_ejecucion_apt import plan


def fila():
    return dict(nombre='ejemplo',arquitectura='amd64',version='2',archivo='ejemplo_2_amd64.deb',
                bytes=8,sha256=hashlib.sha256(b'correcto').hexdigest(),bytes_instalados=16,
                origenes=[dict(origen='Debian',archivo='trixie',sitio='deb.debian.org',confiable=True)])


def nativo_observado(estado='ausente'):
    return dict(version=1,entorno_ejecucion='protegido',python_apt='3.0.4',roto=False,acciones=plan()['simulacion']['actualizaciones'],
                archivos=[dict(fila(),comprobacion=dict(estado=estado))],
                indices=dict(archivos_observados=1,edad_maxima_mtime_segundos=42,frescura_verificada=False,firmas_revalidadas=False))


class SinCambios(unittest.TestCase):
    def setUp(self):
        p=patch.object(nativo.subprocess,'Popen',side_effect=AssertionError('Proceso real prohibido'))
        p.start();self.addCleanup(p.stop)
        p=patch.object(nativo.AptNativo,'instalar',side_effect=AssertionError('Instalación prohibida'))
        p.start();self.addCleanup(p.stop)


class Diagnostico(SinCambios):
    def recoger(self,observado=None,**cambios):
        n=nativo_observado() if observado is None else observado
        self.sondeo=Mock(side_effect=lambda modo,fin:dict(estado='completo',stdout='' if modo=='apt-dpkg-audit' else json.dumps(n)))
        parametros=dict(plan=plan(),sondeo=self.sondeo,
            ejecutor=lambda:dict(estado='cancelado',error='ejecutor_no_instalado'),
            concurrencia=lambda:dict(estado='observado',locks=[],procesos=[],garantia=False),
            diario=lambda:dict(estado='sin_operaciones_observadas'),
            medir=lambda filas:dict(estado='suficiente',descarga_bytes=8))
        parametros.update(cambios)
        return diag.diagnosticar(**parametros)

    def test_faltantes_no_autorizan_y_plan_no_es_instalacion(self):
        d=self.recoger()
        self.assertEqual(d['evaluacion'],'PENDIENTE_DE_DESCARGA')
        self.assertFalse(d['autorizacion'])
        p=diag.plan_descarga(d)
        self.assertFalse(p['instalacion_autorizada']);self.assertFalse(p['autorizacion'])
        self.assertEqual(p['estimacion_maxima_bytes'],8)
        self.assertEqual(p['archivos'],[fila()])
        self.assertEqual([c.args[0] for c in self.sondeo.call_args_list],['apt-dpkg-audit','apt-diagnostico'])

    def test_plan_vacio_valido_no_equivale_a_sistema_verificado(self):
        from contratos_mantenimiento import finalizar
        p=plan();p['candidatas']['paquetes']=[];p['simulacion']['actualizaciones']=[]
        finalizar(p)
        sondeo=Mock(side_effect=AssertionError('Sondeo no previsto'))
        d=diag.diagnosticar(plan=p,sondeo=sondeo)
        self.assertEqual(d['no_comprobado'],['sin_operacion_de_actualizacion_que_validar'])
        self.assertIn('no se han comprobado',d['recomendacion'])
        self.assertFalse(d['preparacion_permitida']);self.assertFalse(d['autorizacion'])
        self.assertEqual(d['evaluacion'],'NO_VERIFICABLE')
        with self.assertRaises(ValueError):diag.plan_descarga(d)
        sondeo.assert_not_called()

    def test_cinco_estados_y_precondiciones(self):
        verificado=nativo_observado('verificado')
        self.assertEqual(self.recoger(verificado)['evaluacion'],'APTO_PARA_PREPARAR')
        self.assertEqual(self.recoger(verificado,ejecutor=lambda:dict(estado='preparado'))['evaluacion'],'APTO_PARA_EJECUCION_CONTROLADA')
        inseguro=copy.deepcopy(verificado);inseguro['entorno_ejecucion']='no_protegido'
        self.assertEqual(self.recoger(inseguro,ejecutor=lambda:dict(estado='preparado'))['evaluacion'],'NO_VERIFICABLE')
        self.assertEqual(self.recoger(verificado,ejecutor=lambda:dict(estado='preparado'),diario=lambda:dict(estado='no_verificable'))['evaluacion'],'NO_VERIFICABLE')
        self.assertEqual(self.recoger(medir=lambda _:dict(estado='insuficiente'))['evaluacion'],'BLOQUEADO')
        self.assertEqual(self.recoger(medir=lambda _:dict(estado='no_verificable'))['evaluacion'],'NO_VERIFICABLE')

    def test_archivos_corruptos_o_no_comprobables_bloquean_preparacion(self):
        for estado in ('inseguro','tamano_incorrecto','hash_incorrecto','cabecera_incorrecta','archivo_cambiado','no_verificable'):
            with self.subTest(estado=estado):
                d=self.recoger(nativo_observado(estado))
                self.assertEqual(d['evaluacion'],'BLOQUEADO')
                with self.assertRaises(ValueError):diag.plan_descarga(d)

    def test_concurrencia_observada_bloquea_sin_garantizar_exclusion(self):
        for clave in ('locks','procesos'):
            c=dict(estado='observado',locks=[],procesos=[],garantia=False);c[clave]=[dict(pid=123)]
            d=self.recoger(concurrencia=lambda:c)
            self.assertEqual(d['evaluacion'],'BLOQUEADO')
            self.assertFalse(d['hechos']['concurrencia']['garantia'])
        d=self.recoger(concurrencia=lambda:dict(estado='no_verificable',locks=[],procesos=[],garantia=False))
        self.assertEqual(d['evaluacion'],'NO_VERIFICABLE')

    def test_simulacion_distinta_y_metadatos_incompletos(self):
        n=nativo_observado();n['acciones'][0]['propuesta']='3'
        self.assertEqual(self.recoger(n)['evaluacion'],'BLOQUEADO')
        n=nativo_observado();n['archivos'][0]['sha256']='no es hash'
        self.assertEqual(self.recoger(n)['evaluacion'],'NO_VERIFICABLE')

    def test_fallos_parciales_y_dpkg_no_se_ocultan(self):
        def sondeo(modo,fin):return dict(estado='error',stdout='')
        self.assertEqual(self.recoger(sondeo=sondeo)['evaluacion'],'NO_VERIFICABLE')
        def sondeo(modo,fin):return dict(estado='completo',stdout='paquete a medio configurar' if modo=='apt-dpkg-audit' else json.dumps(nativo_observado()))
        self.assertEqual(self.recoger(sondeo=sondeo)['evaluacion'],'BLOQUEADO')

    def test_fedora_no_invoca_sondeos_apt(self):
        p=plan();p['distribucion']='fedora';p['gestor']='dnf'
        from contratos_mantenimiento import finalizar
        finalizar(p)
        s=Mock(side_effect=AssertionError('APT en Fedora'))
        d=diag.diagnosticar(plan=p,sondeo=s)
        self.assertEqual(d['evaluacion'],'NO_VERIFICABLE');s.assert_not_called()

    def test_cli_diagnostico_y_plan_no_solicitan_privilegios(self):
        d=self.recoger()
        for comando in ('diagnostico-mantenimiento','plan-descarga-apt'):
            with patch.object(diag,'diagnosticar',return_value=d),patch.object(cli.os,'geteuid',return_value=1000), \
                 patch('cliente_ejecucion_apt.descargar') as descargar,contextlib.redirect_stdout(io.StringIO()) as salida:
                self.assertEqual(cli.main(['--formato','json',comando]),0)
            self.assertFalse(json.loads(salida.getvalue())['autorizacion']);descargar.assert_not_called()

    def test_cli_descarga_explicita_usa_solo_propuesta_validada(self):
        d=self.recoger()
        with patch.object(diag,'diagnosticar',return_value=d),patch.object(cli.os,'geteuid',return_value=1000), \
             patch('cliente_ejecucion_apt.descargar',return_value=dict(estado='completo')) as descargar, \
             contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(['descargar-apt']),0)
        descargar.assert_called_once_with(d['hechos']['plan'],[fila()])

    def test_espacio_conservador_usa_todos_los_destinos(self):
        r=dict(fila(),comprobacion=dict(estado='ausente'))
        with patch.object(diag.os,'statvfs',return_value=types.SimpleNamespace(f_bavail=10**10,f_frsize=1)) as medir:
            d=diag.espacio([r])
        self.assertEqual(medir.call_count,5);self.assertEqual(d['descarga_bytes'],8)
        self.assertGreater(d['montajes'][0]['umbral_bytes'],8+16)


class AutorizacionDescarga(SinCambios):
    def test_autorizaciones_no_intercambiables(self):
        p=aut.crear_peticion(plan(),1000,operacion=aut.OPERACION_DESCARGA,archivos=[fila()])
        aut.validar_peticion(p,1000,operacion=aut.OPERACION_DESCARGA)
        with self.assertRaises(ValueError):aut.validar_peticion(p,1000)
        instalar=aut.crear_peticion(plan(),1000)
        with self.assertRaises(ValueError):aut.validar_peticion(instalar,1000,operacion=aut.OPERACION_DESCARGA)
        self.assertNotEqual(aut.frase(p),aut.frase(instalar))
        p['archivos'][0]['bytes']=9
        with self.assertRaises(ValueError):aut.validar_peticion(p,1000,operacion=aut.OPERACION_DESCARGA)

    def test_confirmacion_descarga_muestra_origen_tamano_y_hash(self):
        p=aut.crear_peticion(plan(),1000,operacion=aut.OPERACION_DESCARGA,archivos=[fila()])
        tty=Mock();tty.readline.return_value=aut.frase(p)+'\n'
        self.assertTrue(helper.confirmar_descarga_tty(tty,p))
        texto=''.join(c.args[0] for c in tty.write.call_args_list)
        for contenido in ('deb.debian.org','8 bytes',fila()['sha256'],'NO AUTORIZA INSTALACIÓN'):
            self.assertIn(contenido,texto)
        tty.readline.return_value='si\n';self.assertFalse(helper.confirmar_descarga_tty(tty,p))

    def test_manifiesto_rechaza_rutas_y_origenes_no_confiables(self):
        for clave,valor in (('origenes',[dict(origen='Debian',archivo='trixie',sitio='repo\u009boculto',confiable=True)]),('archivo','../../fuera.deb'),('sha256','0'),('bytes',-1),('origenes',[])):
            r=fila();r[clave]=valor
            with self.subTest(clave=clave),self.assertRaises(ValueError):archivos.validar_manifiesto([r],plan())


class DescargaSimulada(SinCambios):
    def setUp(self):
        super().setUp()
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.registro=Registro(self.tmp.name,uid=os.getuid()).__enter__()
        self.addCleanup(self.registro.__exit__,None,None,None)
        self.p=aut.crear_peticion(plan(),1000,operacion=aut.OPERACION_DESCARGA,archivos=[fila()])
        self.n=Mock();self.n.bloqueo.return_value=contextlib.nullcontext()
        self.n.simular.return_value=dict(simulacion=plan()['simulacion'],candidatas=plan()['candidatas']['paquetes'])
        self.n.descargar.return_value=dict(archivos=[dict(estado='verificado')])
        m=patch.object(archivos,'manifiesto',return_value=[fila()]);m.start();self.addCleanup(m.stop)

    def ejecutar(self):return motor.descargar(self.p,1000,self.n,self.registro,lambda p:True)

    def test_revalida_y_registra_sin_instalar(self):
        r=self.ejecutar();self.assertEqual(r['estado'],'completo');self.assertFalse(r['instalacion_realizada'])
        self.n.descargar.assert_called_once_with([fila()]);self.n.instalar.assert_not_called()
        nombres=[c[0] for c in self.n.mock_calls]
        self.assertLess(nombres.index('simular'),nombres.index('descargar'))
        self.assertEqual(self.registro.db.execute('SELECT estado FROM operaciones').fetchone()[0],'completo')

    def test_plan_o_manifiesto_cambiados_cancelan_antes_de_red(self):
        self.n.simular.return_value['simulacion']['actualizaciones'][0]['propuesta']='3'
        self.assertEqual(self.ejecutar()['error'],'plan_modificado');self.n.descargar.assert_not_called()
        self.p=aut.crear_peticion(plan(),1000,operacion=aut.OPERACION_DESCARGA,archivos=[fila()])
        self.n.simular.return_value['simulacion']=plan()['simulacion']
        with patch.object(archivos,'manifiesto',return_value=[]):
            self.assertEqual(self.ejecutar()['error'],'manifiesto_modificado')
        self.n.descargar.assert_not_called()

    def test_error_o_interrupcion_no_reintenta_y_bloquea_nueva_peticion(self):
        self.n.descargar.side_effect=KeyboardInterrupt()
        self.assertEqual(self.ejecutar()['estado'],'resultado_desconocido')
        self.p=aut.crear_peticion(plan(),1000,operacion=aut.OPERACION_DESCARGA,archivos=[fila()])
        self.assertEqual(self.ejecutar()['error'],'operacion_pendiente_revision')
        self.n.descargar.assert_called_once()

    def test_rechazo_y_error_de_diario_no_llegan_a_red(self):
        r=motor.descargar(self.p,1000,self.n,self.registro,lambda p:False)
        self.assertEqual(r['estado'],'cancelado');self.n.bloqueo.assert_not_called()
        with patch.object(self.registro,'fase',side_effect=OSError('disco')):
            self.assertEqual(self.ejecutar()['estado'],'cancelado')
        self.n.descargar.assert_not_called()

    def test_adquisicion_nativa_simulada_no_toca_instalador(self):
        obj=nativo.AptNativo();obj.pkg=Mock();obj.cache=Mock()
        obj.pkg.Acquire.RESULT_CONTINUE=0
        fetch=obj.pkg.Acquire.return_value
        fetch.items=[Mock(destfile='/var/cache/apt/archives/ejemplo_2_amd64.deb',is_trusted=True,complete=True)]
        fetch.run.return_value=0
        with patch.object(nativo.os,'statvfs',return_value=types.SimpleNamespace(f_bavail=10**9,f_frsize=1)), \
             patch.object(nativo,'capturar_salida',return_value=contextlib.nullcontext(bytearray())), \
             patch.object(archivos,'comprobar_archivo',return_value=dict(estado='verificado')):
            obj.descargar([fila()])
        fetch.run.assert_called_once();obj.cache.install_archives.assert_not_called()
        obj.cache.commit.assert_not_called();obj.pm.do_install.assert_not_called()

    def test_registro_final_fallido_no_declara_descarga_completa(self):
        with patch.object(self.registro,'finalizar',side_effect=OSError('disco lleno')):
            r=self.ejecutar()
        self.assertEqual(r['estado'],'resultado_desconocido')
        self.assertEqual(r['error'],'registro_final_no_confirmado')
        self.p=aut.crear_peticion(plan(),1000,operacion=aut.OPERACION_DESCARGA,archivos=[fila()])
        self.assertEqual(self.ejecutar()['error'],'operacion_pendiente_revision')
        self.n.descargar.assert_called_once()

    def test_helper_enruta_descarga_autorizada_sin_invocar_instalacion(self):
        import sys
        apt=types.ModuleType('apt');pkg=types.ModuleType('apt_pkg')
        for nombre in ('SystemLock','FileLock','PackageManager','pkgsystem_unlock_inner'):
            setattr(pkg,nombre,Mock())
        entrada=Mock();entrada.buffer.read.return_value=json.dumps(self.p).encode()
        with patch.object(helper,'verificar_instalacion'),patch.object(helper,'preparar_imports'), \
             patch.dict(sys.modules,{'apt':apt,'apt_pkg':pkg}), \
             patch('distribucion_linux.detectar_distribucion',return_value=dict(estado='soportado',id='debian',version_id='13')), \
             patch.dict(os.environ,{'SUDO_UID':'1000'}),patch.object(helper.sys,'stdin',entrada), \
             patch.object(helper.os,'geteuid',return_value=0),patch.object(helper,'confirmar_tty',return_value=True), \
             patch('registro_mantenimiento.Registro') as registro, \
             patch.object(motor,'ejecutar',side_effect=AssertionError('Instalador invocado')) as instalar, \
             patch.object(motor,'descargar',return_value=dict(version=1,estado='completo',instalacion_realizada=False)) as descargar, \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(helper.main(['descargar']),0)
        descargar.assert_called_once();instalar.assert_not_called()
        self.assertEqual(descargar.call_args.args[0],self.p)

    def test_origen_no_confiable_no_inicia_adquisicion(self):
        obj=nativo.AptNativo();obj.pkg=Mock();obj.cache=Mock()
        fetch=obj.pkg.Acquire.return_value
        fetch.items=[Mock(destfile='/var/cache/apt/archives/ejemplo_2_amd64.deb',is_trusted=False)]
        with patch.object(nativo.os,'statvfs',return_value=types.SimpleNamespace(f_bavail=10**9,f_frsize=1)):
            with self.assertRaisesRegex(ValueError,'archivos_no_verificados'):obj.descargar([fila()])
        fetch.run.assert_not_called()


class ArchivosLocales(SinCambios):
    def test_ausencia_y_enlace_no_son_archivos_verificados(self):
        with tempfile.TemporaryDirectory() as tmp:
            destino=Path(tmp,'paquete.deb')
            self.assertEqual(archivos.comprobar_archivo(fila(),destino)['estado'],'ausente')
            destino.symlink_to('/dev/null')
            self.assertNotEqual(archivos.comprobar_archivo(fila(),destino)['estado'],'verificado')

    def test_hash_y_cabecera_son_ambos_necesarios(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp,'paquete.deb');p.write_bytes(b'correcto');p.chmod(0o600)
            real=os.fstat
            def root(fd):
                st=real(fd)
                datos={k:getattr(st,k) for k in ('st_mode','st_nlink','st_size','st_dev','st_ino','st_mtime_ns','st_ctime_ns')}
                return types.SimpleNamespace(**datos,st_uid=0)
            with patch.object(archivos.os,'fstat',side_effect=root),patch.object(archivos.subprocess,'run') as leer:
                leer.return_value=types.SimpleNamespace(returncode=0,stderr=b'',stdout=b'ejemplo\tamd64\t2\n')
                self.assertEqual(archivos.comprobar_archivo(fila(),p)['estado'],'verificado')
                leer.return_value.stdout=b'ejemplo\tamd64\t3\n'
                self.assertEqual(archivos.comprobar_archivo(fila(),p)['estado'],'cabecera_incorrecta')
                r=fila();r['sha256']='0'*64;leer.reset_mock()
                self.assertEqual(archivos.comprobar_archivo(r,p)['estado'],'hash_incorrecto');leer.assert_not_called()
