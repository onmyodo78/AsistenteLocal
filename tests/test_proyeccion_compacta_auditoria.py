"""Proyección aislada: únicamente trazas adquiridas por herramientas simuladas."""
import copy
import hashlib
import socket
import subprocess
import unittest
from unittest.mock import patch

import auditoria_basica as auditoria
import proyeccion_compacta_auditoria as compacta
from contratos_autonomia import validar_traza
from contratos_mantenimiento import serializar, finalizar, paquete
from test_auditoria_basica import Herramientas, Reloj, distro, resultado


def escenario(nombre='basico'):
    h=Herramientas();reloj=Reloj();kw={};distribucion='debian'
    if nombre=='35_actualizaciones':
        plan=resultado('plan_mantenimiento')
        filas=[paquete('libreoffice-ficticio-'+str(i),'amd64','1.0','1.1') for i in range(35)]
        plan['resultado']['simulacion']['actualizaciones']=copy.deepcopy(filas)
        plan['resultado']['candidatas']['paquetes']=copy.deepcopy(filas)
        plan['resultado']=finalizar(plan['resultado'])
        h.valores['plan_mantenimiento']=plan
    elif nombre=='sin_datos':kw['cancelado']=lambda:True
    elif nombre=='prioridades':
        disco=resultado('disco');disco['resultado']['montajes'][0]['disponible_bytes']=0
        servicio=resultado('servicios_fallidos');servicio['resultado']['datos']['unidades']=[{'nombre':'ficticio.service'}]
        diag=resultado('diagnostico_mantenimiento_apt');diag['resultado']['impedimentos']=['dpkg_con_incidencias']
        h.valores.update(disco=disco,servicios_fallidos=servicio,diagnostico_mantenimiento_apt=diag)
    elif nombre=='parcial':
        h.ausentes={'interfaces_red','servicios_fallidos'}
        memoria=resultado('memoria');memoria['estado']='parcial';memoria['resultado']['ram']=None
        h.valores['memoria']=memoria
    elif nombre=='error':h.fallo['auditoria_seguridad']=OSError('fallo simulado')
    elif nombre=='plazo':h.reloj=reloj;h.paso=31
    elif nombre=='cancelado':h.fallo['memoria']=KeyboardInterrupt()
    elif nombre=='excluido':kw['exclusiones']=['seguridad','mantenimiento']
    elif nombre=='fedora':distribucion='fedora'
    elif nombre=='extenso':
        diag=resultado('diagnostico_mantenimiento_apt')
        diag['resultado']['limitaciones']=['Limitacion ficticia '+str(i)+': '+('x'*1000) for i in range(20)]
        h.valores['diagnostico_mantenimiento_apt']=diag
    return auditoria.auditar(herramientas=h,detectar=lambda:distro(distribucion),reloj=reloj,**kw)


def evidencia(t,op):return next(r for r in t if r['tipo']=='evidencia' and r['operacion_id']==op)
def rehacer_huella(e):e['sha256_payload']=hashlib.sha256(serializar(e['datos']).encode()).hexdigest()


class Compacta(unittest.TestCase):
    def setUp(self):
        self.procesos=patch.object(subprocess,'Popen',side_effect=AssertionError('proceso prohibido'))
        self.red=patch.object(socket,'socket',side_effect=AssertionError('red prohibida'))
        self.procesos.start();self.red.start()
        self.addCleanup(self.procesos.stop);self.addCleanup(self.red.stop)
        self.t=escenario();self.p=compacta.proyectar(self.t)

    def test_pureza_determinismo_y_copia(self):
        original=copy.deepcopy(self.t)
        self.assertEqual(self.p,compacta.proyectar(self.t));self.assertEqual(self.t,original)
        copia=compacta.validar(self.p,self.t);copia['pendientes'].append('otro')
        self.assertNotEqual(copia,self.p)
        self.assertEqual(len(self.p['cobertura']),7)
        self.assertEqual(sum(len(o['actuaciones']) for o in self.p['operaciones'].values()),8)
        self.assertFalse(self.p['autoriza_actuaciones'])
        self.assertEqual(self.p['prioridades'],dict(P1=0,P2=0,P3=1,informativa=7))

    def test_referencias_tipadas_y_objetivo(self):
        for r in self.p['hallazgos']+[m for g in self.p['informativas'] for m in g['miembros']]:
            h=compacta.resolver_alias(self.p,r['h'],self.t)
            original=next(x for x in self.t if x['id']==h['id'])
            for referencia,nativa in zip(r['refs'],original['evidencias']):
                res=compacta.resolver_referencia(self.p,referencia,self.t)
                self.assertEqual(res['evidencia_id'],nativa['evidencia_id'])
                self.assertEqual(res['campo'],nativa['campo'])
        for alias in ('E999','D0','H-1'):
            with self.subTest(alias=alias),self.assertRaises(ValueError):compacta.resolver_alias(self.p,alias,self.t)
        with self.assertRaises(ValueError):compacta.resolver_referencia(self.p,['H1',''],self.t)
        with self.assertRaises(ValueError):compacta.resolver_referencia(self.p,['E1','/inexistente'],self.t)
        with self.assertRaises(ValueError):compacta.validar(self.p,escenario())

    def test_alteraciones_semanticas_y_referencias_cruzadas(self):
        def prioridad(p):p['hallazgos'][0]['prioridad']='P1'
        def texto(p):p['hallazgos'][0]['texto']='No hay actualizaciones'
        def cruzada(p):p['hallazgos'][0]['refs'][0][0]='E1'
        def pierde(p):p['operaciones'].pop('memoria')
        def tipo(p):p['autoriza_actuaciones']=0
        def anade(p):p['autorizacion']='permitida'
        def cobertura(p):p['cobertura']['memoria']['e']=['E1']
        for mutacion in (prioridad,texto,cruzada,pierde,tipo,anade,cobertura):
            p=copy.deepcopy(self.p);mutacion(p)
            with self.subTest(mutacion=mutacion.__name__),self.assertRaises(ValueError):compacta.validar(p,self.t)

    def test_agrupacion_estricta_y_miembros_originales(self):
        t=copy.deepcopy(self.t);informativas=[r for r in t if r['tipo']=='hallazgo' and r['prioridad']=='informativa']
        # Dos observaciones de la misma regla: solo sus referencias individuales difieren.
        a,b=informativas[:2]
        for clave in ('regla_id','prioridad','verificabilidad','conclusion_python','limitaciones','siguiente_paso'):b[clave]=copy.deepcopy(a[clave])
        validar_traza(t)
        p=compacta.proyectar(t)
        self.assertEqual(sorted(len(g['miembros']) for g in p['informativas']),[7])
        for clave,valor in (('conclusion_python','E1 H1 son texto literal'),('verificabilidad','parcial'),
                            ('limitaciones',['a','b','a']),('siguiente_paso','memoria')):
            alterada=copy.deepcopy(t);next(r for r in alterada if r['id']==b['id'])[clave]=valor
            q=compacta.proyectar(alterada)
            self.assertEqual(len(q['informativas']),2)
        for valor in (['b','a'],['a','a']):
            alterada=copy.deepcopy(t)
            next(r for r in alterada if r['id']==a['id'])['limitaciones']=['a','b']
            next(r for r in alterada if r['id']==b['id'])['limitaciones']=valor
            self.assertEqual(len(compacta.proyectar(alterada)['informativas']),3)
        grupo=next(g for g in p['informativas'] if len(g['miembros'])==7)
        grupo['miembros'][1]=copy.deepcopy(grupo['miembros'][0])
        with self.assertRaises(ValueError):compacta.validar(p,t)

    def test_prioridades_no_se_agrupan_y_textos_no_se_reescriben(self):
        t=escenario('prioridades');p=compacta.proyectar(t)
        for prioridad in ('P1','P2','P3'):
            originales=[r for r in t if r.get('prioridad')==prioridad]
            self.assertEqual(len([r for r in p['hallazgos'] if r['prioridad']==prioridad]),len(originales))
            self.assertTrue(originales)
        h=next(r for r in t if r['tipo']=='hallazgo')
        h['conclusion_python']='E1 y H1 no son referencias en texto: '+('x'*400)
        q=compacta.proyectar(t)
        textos=[r['texto'] for r in q['hallazgos']+q['informativas']]
        self.assertIn(h['conclusion_python'],textos)

    def test_parcial_null_ausente_cero_y_errores_de_tipo(self):
        t=escenario('parcial');p=compacta.proyectar(t)
        memoria=p['operaciones']['memoria']['evidencias'];alias=next(iter(memoria))
        self.assertIsNone(memoria[alias]['datos']['ram'])
        self.assertIn('adquisicion_parcial',p['desconocidos'][alias]['estados'])
        self.assertIn(['/ram','null'],p['desconocidos'][alias]['valores'])
        self.assertTrue(p['no_realizadas'])
        for valor in (0,None,True,'100'):
            t=copy.deepcopy(self.t);e=evidencia(t,'memoria');e['datos']['resultado']['ram']['total_bytes']=valor;rehacer_huella(e)
            if valor is True or type(valor) is str:
                with self.subTest(valor=valor),self.assertRaises(ValueError):compacta.proyectar(t)
            else:
                q=compacta.proyectar(t);fila=next(iter(q['operaciones']['memoria']['evidencias'].values()))
                self.assertEqual(fila['datos']['ram']['total_bytes'],valor)
        fila=next(iter(self.p['operaciones']['memoria']['evidencias']))
        self.assertIn('/resultado/ram/disponible_estimada_bytes',self.p['desconocidos'][fila]['ausentes'])

    def test_fallos_plazos_cancelacion_exclusiones_y_fedora(self):
        for nombre in ('error','plazo','cancelado','excluido','fedora','sin_datos'):
            with self.subTest(nombre=nombre):
                t=escenario(nombre);p=compacta.proyectar(t);compacta.validar(p,t)
                self.assertEqual(p['estado'],t[-1]['estado'])
                self.assertEqual(p['motivo'],t[-1]['motivo_parada'])
                self.assertEqual(p['pendientes'],t[-1]['pendientes'])
                for op,datos in p['operaciones'].items():
                    for acc in datos['actuaciones'].values():
                        self.assertEqual(acc['estado'],next(r['estado'] for r in t if r['tipo']=='actuacion' and r['operacion_id']==op))

    def test_presupuesto_no_elimina_datos_y_limites_estrictos(self):
        t=escenario('extenso');p=compacta.proyectar(t);antes=copy.deepcopy(p)
        presupuesto=compacta.evaluar_presupuesto(p)
        self.assertTrue(presupuesto['excede_meta']);self.assertTrue(presupuesto['excede_limite'])
        self.assertFalse(presupuesto['recortada']);self.assertEqual(p,antes)
        self.assertEqual(sum(x.startswith('Limitacion ficticia') for x in p['limitaciones']),20)
        compacta.validar(p,t)
        for meta,limite in ((0,18000),(6000,19000),(6001,6000),(True,18000)):
            with self.subTest(meta=meta,limite=limite),self.assertRaises(ValueError):compacta.evaluar_presupuesto(p,meta,limite)
        exacto=compacta.evaluar_presupuesto(self.p)['bytes']
        self.assertFalse(compacta.evaluar_presupuesto(self.p,exacto,18000)['excede_meta'])
        self.assertTrue(compacta.evaluar_presupuesto(self.p,exacto-1,18000)['excede_meta'])

    def test_inventarios_y_datos_no_seleccionados_no_se_copian(self):
        t=copy.deepcopy(self.t)
        for op in ('sistema','memoria','auditoria_seguridad'):
            e=evidencia(t,op);e['datos']['resultado']['dato_privado_no_relevante']='MARCADOR_PRIVADO_FICTICIO';rehacer_huella(e)
        p=compacta.proyectar(t)
        self.assertNotIn('MARCADOR_PRIVADO_FICTICIO',serializar(p))
        self.assertEqual(len(p['omisiones']['detalle_fuera_del_resumen']),8)
        self.assertFalse(p['omisiones']['por_presupuesto'])

    def test_recuentos_del_resolvedor_no_confunden_desconocidos_con_cero(self):
        t=escenario('35_actualizaciones');p=compacta.proyectar(t)
        datos=next(iter(p['operaciones']['plan_mantenimiento']['evidencias'].values()))['datos']
        self.assertEqual(datos['recuentos'],dict(paquetes=35,actualizaciones=35,instalaciones=0,eliminaciones=0,retenciones=0))
        e=evidencia(t,'plan_mantenimiento')
        e['datos']['resultado']['simulacion']['retenciones_estado']='no_verificable'
        rehacer_huella(e)
        q=compacta.proyectar(t)
        alias=next(iter(q['operaciones']['plan_mantenimiento']['evidencias']))
        datos=q['operaciones']['plan_mantenimiento']['evidencias'][alias]['datos']
        self.assertIsNone(datos['recuentos']['retenciones'])
        self.assertIn(['/recuentos/retenciones','null'],q['desconocidos'][alias]['valores'])
        self.assertEqual(datos['recuentos']['actualizaciones'],35)

    def test_limitaciones_conservan_asociaciones_orden_y_multiplicidad(self):
        t=copy.deepcopy(self.t)
        e=evidencia(t,'memoria');e['limitaciones']=['uno','dos','uno']
        e['datos']['resultado']['limitaciones']=['tres'];rehacer_huella(e)
        p=compacta.proyectar(t)
        fila=next(iter(p['operaciones']['memoria']['evidencias'].values()))
        self.assertEqual([p['limitaciones'][i] for i in fila['lim']],['uno','dos','uno','tres'])
        fila['lim'].reverse()
        with self.assertRaises(ValueError):compacta.validar(p,t)

    def test_punteros_escapados_se_resuelven_sin_sustitucion_de_textos(self):
        t=copy.deepcopy(self.t);e=evidencia(t,'memoria')
        e['datos']['resultado']['a/b~c']='ficticio';rehacer_huella(e)
        h=next(r for r in t if r['tipo']=='hallazgo' and any(ref['evidencia_id']==e['id'] for ref in r['evidencias']))
        h['evidencias']=[dict(evidencia_id=e['id'],campo='/resultado/a~1b~0c')]
        p=compacta.proyectar(t)
        r=next(m for g in p['informativas'] for m in g['miembros'] if compacta.resolver_alias(p,m['h'],t)['id']==h['id'])
        self.assertEqual(compacta.resolver_referencia(p,r['refs'][0],t)['valor'],'ficticio')
        for referencia in (['E3','/resultado/a~2b'],['E3'],['E3',0]):
            with self.subTest(referencia=referencia),self.assertRaises(ValueError):compacta.resolver_referencia(p,referencia,t)

    def test_origen_corrupto_no_se_acepta(self):
        t=copy.deepcopy(self.t);evidencia(t,'memoria')['datos']['resultado']['ram']['total_bytes']=1234
        with self.assertRaises(ValueError):compacta.proyectar(t)
        t=copy.deepcopy(self.t)
        next(r for r in t if r['tipo']=='hallazgo')['evidencias'][0]['evidencia_id']='inventada'
        with self.assertRaises(ValueError):compacta.proyectar(t)


if __name__=='__main__':unittest.main()
