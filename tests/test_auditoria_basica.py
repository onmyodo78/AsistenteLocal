"""Circuito autónomo simulado: no procesos, red ni auditoría del anfitrión."""
import copy
import hashlib
import io
import contextlib
import unittest
from unittest.mock import patch

import auditoria_basica as a
import contratos_autonomia as c
from distribucion_linux import detectar_distribucion
from contratos_mantenimiento import serializar
from test_ejecucion_apt import plan


def distro(nombre='debian'):
    return detectar_distribucion(contenido='ID='+nombre+'\nVERSION_ID='+('13' if nombre=='debian' else '44'))


def resultado(op):
    payload={
        'sistema':dict(kernel='Linux prueba',fuente={'estado':'correcta','codigo':0,'stderr':''}),
        'disco':dict(montajes=[dict(ruta='/',dispositivo=1,disponible_bytes=100,total_bytes=1000)]),
        'memoria':dict(version=1,herramienta='memoria',estado='completo',ram={'total_bytes':100},swap={'ocupada_bytes':1}),
        'servicios_fallidos':dict(version=1,estado_adquisicion='completo',datos={'unidades':[]}),
        'interfaces_red':dict(version=1,estado='completo',interfaces=[]),
        'auditoria_seguridad':dict(version=2,estado_adquisicion='completo',inventario_completo=True,inventario_dpkg=[],actualizaciones={},avisos_pendientes=[]),
        'plan_mantenimiento':plan(),
        'diagnostico_mantenimiento_apt':dict(version=1,tipo='diagnostico_mantenimiento_apt',evaluacion='PENDIENTE_DE_DESCARGA',autorizacion=False,preparacion_permitida=True,impedimentos=[],no_comprobado=[],hechos={}),
        'correlacion_seguridad':dict(detalle_dnf5='correcto',resultados=[],cisa_kev={'estado':'no_autorizada'}),
    }[op]
    return dict(estado='completo',resultado=payload,subconsultas=[])


class Reloj:
    def __init__(self):self.t=1000.
    def __call__(self):return self.t


class Herramientas:
    def __init__(self):
        self.llamadas=[];self.valores={};self.ausentes=set();self.fallo={};self.reloj=None
    def capacidad(self,op,d):
        return ('no_disponible' if op in self.ausentes or d['estado']!='soportado' else 'disponible'),[], 'simulada'
    def ejecutar(self,op,fin,previos):
        self.llamadas.append((op,fin,copy.deepcopy(previos)))
        if self.reloj:self.reloj.t+=self.paso
        if op in self.fallo:raise self.fallo[op]
        return copy.deepcopy(self.valores.get(op,resultado(op)))


class Auditoria(unittest.TestCase):
    def setUp(self):
        self.h=Herramientas();self.reloj=Reloj()
        self.pila=contextlib.ExitStack();self.addCleanup(self.pila.close)
        import subprocess, urllib.request
        self.pila.enter_context(patch.object(subprocess,'Popen',side_effect=AssertionError('Proceso real prohibido')))
        self.pila.enter_context(patch.object(urllib.request,'urlopen',side_effect=AssertionError('Red prohibida')))
    def ejecutar(self,nombre='debian',**kw):
        self.co=a.Coordinador(herramientas=self.h,detectar=lambda:distro(nombre),reloj=self.reloj,**kw)
        return self.co.ejecutar()
    def test_debian_siete_areas_y_ampliacion_plan_reutilizado(self):
        traza=self.ejecutar()
        self.assertEqual(list(traza[-1]['cobertura']),list(c.AREAS))
        self.assertTrue(all(f['estado']=='comprobada' for f in traza[-1]['cobertura'].values()))
        self.assertEqual(len(self.h.llamadas),8)
        self.assertEqual(self.h.llamadas[-1][0],'diagnostico_mantenimiento_apt')
        self.assertEqual(self.h.llamadas[-1][2]['plan_mantenimiento'],plan())
        self.assertEqual(self.h.llamadas[-2][2]['auditoria_seguridad']['version'],2)
        self.assertEqual(traza[-1]['presupuesto_final']['rondas'],2)
        c.validar_traza(traza)
    def test_fedora_correlacion_local_reutiliza_avisos(self):
        valor=resultado('auditoria_seguridad');valor['resultado'].update(inventario_rpm=[],avisos_pendientes=[dict(id='FEDORA-1',paquetes=['ejemplo-1'])])
        self.h.valores['auditoria_seguridad']=valor
        traza=self.ejecutar('fedora')
        self.assertEqual(self.h.llamadas[-1][0],'correlacion_seguridad')
        self.assertEqual(self.h.llamadas[-1][2]['auditoria_seguridad'],valor['resultado'])
        self.assertFalse(traza[0]['permisos']['externo'])
        self.assertTrue(any(r.get('prioridad')=='P2' for r in traza))
    def test_capacidad_ausente_y_no_soportado(self):
        self.h.ausentes={'memoria','servicios_fallidos'}
        traza=self.ejecutar()
        self.assertEqual(traza[-1]['cobertura']['memoria']['estado'],'no_disponible')
        self.assertEqual(traza[-1]['estado'],'parcial')
        self.h.llamadas=[]
        self.ejecutar('ubuntu')
        self.assertEqual(self.h.llamadas,[])
    def test_exclusiones_prevalecen(self):
        traza=a.auditar(herramientas=self.h,detectar=lambda:distro(),reloj=self.reloj,
                       exclusiones=['seguridad','mantenimiento'])
        self.assertEqual(len(self.h.llamadas),5)
        self.assertEqual(traza[-1]['cobertura']['mantenimiento']['estado'],'excluida')
        with self.assertRaises(ValueError):a.auditar(exclusiones=['shell'])
    def test_fallo_inventario_no_repite_por_plan(self):
        self.h.fallo['auditoria_seguridad']=OSError('fallo')
        traza=self.ejecutar()
        self.assertNotIn('plan_mantenimiento',[x[0] for x in self.h.llamadas])
        self.assertEqual(traza[-1]['cobertura']['mantenimiento']['motivo'],'adquisicion_previa_fallida_no_se_repite')
    def test_plazo_unico_incluso_lecturas_compuestas(self):
        self.h.reloj=self.reloj;self.h.paso=31
        traza=self.ejecutar()
        self.assertEqual(traza[-1]['motivo_parada'],'tiempo_agotado')
        self.assertEqual(len(self.h.llamadas),4)
        self.assertEqual({x[1] for x in self.h.llamadas},{1120.})
        self.assertEqual(traza[-1]['cobertura']['servicios']['estado'],'parcial')
    def test_cancelacion_y_interrupcion_sin_reintento(self):
        self.h.fallo['memoria']=KeyboardInterrupt()
        traza=self.ejecutar()
        self.assertEqual(traza[-1]['estado'],'cancelado')
        self.assertEqual(len(self.h.llamadas),3)
        self.h.llamadas=[]
        traza=self.ejecutar(cancelado=lambda:True)
        self.assertEqual(self.h.llamadas,[])
        self.assertEqual(traza[-1]['motivo_parada'],'cancelacion_usuario')
    def test_prioridades_reglas_y_pendientes_no_ejecutables(self):
        serv=resultado('servicios_fallidos');serv['resultado']['datos']['unidades']=[dict(nombre='ejemplo.service')]
        disco=resultado('disco');disco['resultado']['montajes'][0]['disponible_bytes']=0
        red=resultado('interfaces_red');red['resultado']['interfaces']=[dict(nombre='eth0',administrativo='UP',operativo='DOWN')]
        diag=resultado('diagnostico_mantenimiento_apt');diag['resultado']['impedimentos']=['dpkg_con_incidencias']
        self.h.valores.update(servicios_fallidos=serv,disco=disco,interfaces_red=red,diagnostico_mantenimiento_apt=diag)
        traza=self.ejecutar()
        self.assertEqual(sum(r.get('prioridad')=='P2' for r in traza),2)
        self.assertEqual(sum(r.get('prioridad')=='P1' for r in traza),1)
        self.assertTrue(any('INV-SVC-01' in p for p in traza[-1]['pendientes']))
        self.assertTrue(any('INV-RED-01' in p for p in traza[-1]['pendientes']))
        for r in traza:
            if r['tipo']=='hallazgo':self.assertTrue(r['evidencias'])
        self.assertNotIn('reparar',[r[0] for r in self.h.llamadas])
    def test_plan_instalaciones_no_genera_diagnostico_ejecutable(self):
        valor=resultado('plan_mantenimiento');valor['resultado']['simulacion']['instalaciones']=[dict(nombre='otro',arquitectura='amd64',anterior=None,propuesta='1')]
        from contratos_mantenimiento import finalizar
        valor['resultado']=finalizar(valor['resultado'])
        self.h.valores['plan_mantenimiento']=valor
        self.ejecutar()
        self.assertEqual(len(self.h.llamadas),7)
    def test_contratos_campos_extra_tipos_y_referencias(self):
        traza=self.ejecutar()
        for tipo in c.CAMPOS:
            registro=next(r for r in traza if r['tipo']==tipo)
            for mutacion in ('extra','version'):
                with self.subTest(tipo=tipo,mutacion=mutacion):
                    copia=copy.deepcopy(registro)
                    copia['extra']=True if mutacion=='extra' else None
                    if mutacion=='version':copia.pop('extra');copia['version']=True
                    with self.assertRaises(ValueError):c.validar(copia)
        for ref in ({'evidencia_id':'ajena','campo':''}, {'evidencia_id':next(r['id'] for r in traza if r['tipo']=='evidencia'),'campo':'/no_existe'}):
            copia=copy.deepcopy(traza)
            next(r for r in copia if r['tipo']=='hallazgo')['evidencias']=[ref]
            with self.assertRaises(ValueError):c.validar_traza(copia)
    def test_integridad_objetivo_enlaces_y_autoridad(self):
        original=self.ejecutar()
        for cambio in ('hash','objetivo','decision','truncado','permisos','limites','cobertura','regla'):
            with self.subTest(cambio=cambio):
                traza=copy.deepcopy(original)
                e=next(r for r in traza if r['tipo']=='evidencia')
                if cambio=='hash':e['datos']['resultado']['invento']=True
                elif cambio=='objetivo':e['objetivo_id']='otro'
                elif cambio=='decision':next(r for r in traza if r['tipo']=='actuacion')['decision_id']='ajena'
                elif cambio=='truncado':e['truncado']=True
                elif cambio=='permisos':traza[0]['permisos']['externo']=True
                elif cambio=='limites':traza[0]['limites']['llamadas']=9
                elif cambio=='regla':next(r for r in traza if r['tipo']=='decision')['regla_id']='regla_del_modelo'
                else:traza[-1]['cobertura']['identidad']['evidencias']=['ajena']
                with self.assertRaises(ValueError):c.validar_traza(traza)
    def test_registro_excesivo_no_publica_payload_ni_repite(self):
        valor=resultado('sistema');valor['resultado']['mucho']=['x'*17000]*256
        self.h.valores['sistema']=valor
        traza=self.ejecutar()
        self.assertEqual(traza[-1]['motivo_parada'],'registro_agotado')
        self.assertLess(len(serializar(traza)),4*1024*1024)
        self.assertEqual(len(self.h.llamadas),1)
    def test_objetivo_cerrado_no_acepta_propuestas_ni_repite(self):
        self.ejecutar()
        for op in ('diagnostico_vpn','sistema','actualizar_apt'):
            self.assertIsNone(self.co.adquirir(op,'INEXISTENTE',[]))
        self.assertEqual(len(self.h.llamadas),8)
        with self.assertRaises(ValueError):self.co.ejecutar()
    def test_informe_y_cli_conversacion_reutilizan_coordinador(self):
        traza=self.ejecutar()
        texto=a.informe(traza)
        self.assertIn('Comprobación realizada',texto)
        self.assertIn('Pendiente',texto)
        import cli,AsistenteLocal as app
        with patch.object(a,'auditar',return_value=traza) as ejecutar,contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(['--formato','json','auditoria-basica']),0)
            from test_lmstudio_comunicacion import completa
            with patch.object(app,'consultar_modelo',return_value=completa('Explicación simulada.')):
                self.assertEqual(app.preguntar('Realiza una auditoría básica del sistema'),traza)
            self.assertEqual(ejecutar.call_count,2)
    def test_json_pointer_estricto(self):
        self.assertEqual(c.puntero({'a/b':{'~x':[3]}},'/a~1b/~0x/0'),3)
        for ruta in ('/a~2b','/a~1b/~0x/01','/a~1b/~0x/-1'):
            with self.assertRaises(ValueError):c.puntero({'a/b':{'~x':[3]}},ruta)


class AdaptacionLecturas(unittest.TestCase):
    def setUp(self):
        self.pila=contextlib.ExitStack();self.addCleanup(self.pila.close)
        import subprocess
        self.pila.enter_context(patch.object(subprocess,'Popen',side_effect=AssertionError('Proceso real prohibido')))

    def test_plan_propaga_deadline_reutiliza_inventario_y_registra_subconsultas(self):
        from mantenimiento import consultar
        from adaptadores.debian import Debian
        from test_ejecucion_apt import plan as ejemplo
        p=ejemplo();datos={'inventario_previo':'simulado'}
        adaptador=Debian();fin=__import__('time').monotonic()+12
        observadas=[]
        with patch.object(adaptador,'capacidades',return_value=p['capacidades']) as capacidades, patch.object(
                adaptador,'consultar',return_value=(p['candidatas'],datos)) as candidatas, patch.object(
                adaptador,'simular',return_value=p['simulacion']) as simular:
            r=consultar('plan',distribucion=distro(),adaptador=adaptador,
                        deadline=fin,datos_previos=datos,observador=observadas.append)
        capacidades.assert_called_once_with(fin)
        candidatas.assert_called_once_with(fin,datos=datos)
        simular.assert_called_once_with(fin,datos)
        self.assertEqual(r['estado'],'completo')
        self.assertEqual(len(observadas),3)
        self.assertTrue(all(x['duracion_ms']>=0 for x in observadas))

    def test_adaptadores_reutilizan_inventario_sin_repetir_adquisicion(self):
        from adaptadores.debian import Debian
        from adaptadores.fedora import Fedora
        deb=dict(estado_inventario='completo',actualizaciones=dict(estado_adquisicion='completo',candidatos=[]))
        with patch('adaptadores.debian.consultar_auditoria',side_effect=AssertionError('No repetir')):
            self.assertEqual(Debian().consultar(100,datos=deb)[1],deb)
        fed=dict(inventario_completo=True,inventario_rpm=[dict(nombre='ejemplo',arquitectura='x86_64',epoch=0,version='1',release='1')])
        with patch('adaptadores.fedora.ejecutar',return_value=dict(estado='completo',stdout='',error=None)) as ejecutar:
            adaptador=Fedora()
            _,inventario=adaptador.consultar(100,datos=fed)
        self.assertEqual(len(inventario),1)
        self.assertEqual([c.args[0] for c in ejecutar.call_args_list],[adaptador.gestor+'-consultar'])

    def test_correlacion_fedora_forzosamente_local_y_diagnostico_sin_cliente_admin(self):
        from autonomia_herramientas import HerramientasLocales
        h=HerramientasLocales();fin=__import__('time').monotonic()+10
        local={'inventario_completo':True,'fuentes':{}}
        def correlacion(consultar_local,ejecutar,externo,deadline):
            self.assertFalse(externo);self.assertEqual(deadline,fin)
            self.assertEqual(consultar_local(fin),local)
            return dict(detalle_dnf5='correcto',estado_adquisicion='completo',resultados=[])
        with patch('correlacion_seguridad.consultar',side_effect=correlacion):
            self.assertEqual(h.ejecutar('correlacion_seguridad',fin,{'auditoria_seguridad':local})['estado'],'completo')
        def diagnostico(**kw):
            self.assertEqual(kw['plan'],plan());self.assertEqual(kw['deadline'],fin)
            return resultado('diagnostico_mantenimiento_apt')['resultado']
        with patch('diagnostico_mantenimiento.diagnosticar',side_effect=diagnostico), patch(
                'cliente_ejecucion_apt.invocar',side_effect=AssertionError('Cliente administrativo prohibido')):
            self.assertEqual(h.ejecutar('diagnostico_mantenimiento_apt',fin,{'plan_mantenimiento':plan()})['estado'],'completo')

    def test_esquemas_nested_y_limites_de_salida(self):
        h=Herramientas();r=Reloj()
        h.valores['sistema']=dict(estado='completo',resultado={'texto':'x'*18001},subconsultas=[])
        traza=a.auditar(herramientas=h,detectar=lambda:distro(),reloj=r)
        e=next(e for e in traza if e['tipo']=='evidencia')
        self.assertEqual(e['estado'],'error')
        self.assertLessEqual(len(a.informe(traza)),18000)
        for modificar in ('duracion','tipo_json','fuente','presupuesto'):
            copia=copy.deepcopy(traza)
            evidencia=next(e for e in copia if e['tipo']=='evidencia')
            if modificar=='duracion':evidencia['duracion_ms']=True
            elif modificar=='tipo_json':evidencia['datos']['resultado']['nan']=float('nan')
            elif modificar=='fuente':evidencia['version_origen']=True
            else:copia[-1]['presupuesto_final']['llamadas']=9
            with self.subTest(modificar=modificar),self.assertRaises(ValueError):c.validar_traza(copia)


if __name__=='__main__':unittest.main()
