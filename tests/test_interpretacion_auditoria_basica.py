"""Continuación explicativa simulada: sin auditoría real, HTTP ni procesos."""
import contextlib
import copy
import io
import json
import os
import unittest
from unittest.mock import patch

import AsistenteLocal as app
import auditoria_basica as basica
from contratos_autonomia import validar_traza
from contratos_mantenimiento import serializar
from proyeccion_auditoria_basica import proyectar
from test_auditoria_basica import Herramientas,Reloj,distro,resultado
from test_lmstudio_comunicacion import completa,HTTP
from test_p0 import llamada

FRASE=('Realiza una auditoría básica del sistema y explícame los problemas '
       'encontrados, ordenados por prioridad')


class Interpretacion(unittest.TestCase):
    def setUp(self):
        self.clock=Reloj();self.h=Herramientas();self.h.reloj=self.clock;self.h.paso=3
        self.salida=io.StringIO();self.pila=contextlib.ExitStack();self.addCleanup(self.pila.close)
        self.pila.enter_context(contextlib.redirect_stdout(self.salida))
        self.pila.enter_context(patch.dict(os.environ, {'ASISTENTE_PROYECCION_AUDITORIA':'actual'}))
        self.pila.enter_context(patch.object(app.time,'monotonic',self.clock))
        self.pila.enter_context(patch.object(app.subprocess,'Popen',side_effect=AssertionError('Proceso real prohibido')))
        self.pila.enter_context(patch.object(app,'abrir_http_local',side_effect=AssertionError('HTTP real prohibido')))
        self.pila.enter_context(patch.object(app,'herramientas_para_modelo',return_value={}))
        self.pila.enter_context(patch.object(app,'ejecutar_consulta',side_effect=AssertionError('No repetir por ruta anterior')))
        self.real=basica.auditar
        def adquirir(**opciones):
            self.deadline=opciones['deadline']
            self.traza=self.real(herramientas=self.h,detectar=lambda:distro(),reloj=self.clock,**opciones)
            self.antes=serializar(self.traza)
            return self.traza
        self.co=self.pila.enter_context(patch.object(basica,'auditar',side_effect=adquirir))

    def comprobar_conservacion(self,traza):
        self.assertEqual(serializar(traza),self.antes)
        validar_traza(traza)
        self.assertEqual(len(self.h.llamadas),len(set(x[0] for x in self.h.llamadas)))
        self.assertLessEqual(len(self.h.llamadas),8)
        self.assertEqual({x[1] for x in self.h.llamadas},{self.deadline})
        self.assertIn('=== FIN DEL INFORME FACTUAL ===',self.salida.getvalue())

    def test_exito_orden_flags_y_presupuesto_compartido(self):
        with patch.object(app,'consultar_modelo',return_value=completa('Hay actualizaciones pendientes, con prioridad P3.')) as modelo:
            traza=app.preguntar(FRASE)
        self.comprobar_conservacion(traza)
        self.co.assert_called_once_with(deadline=1120.)
        modelo.assert_called_once()
        self.assertEqual(modelo.call_args.args[1],1120.)
        self.assertEqual(modelo.call_args.kwargs,dict(permitir_herramientas=False,omitir_tools=True,interpretacion=True))
        mensajes=modelo.call_args.args[0]
        proyeccion=json.loads(mensajes[1]['content'])
        self.assertEqual(proyeccion['tipo'],'proyeccion_explicativa_auditoria_basica')
        self.assertEqual(proyeccion['prioridades']['P3'],1)
        self.assertFalse(proyeccion['autoriza_actuaciones'])
        self.assertTrue(proyeccion['hallazgos'][0]['referencias'])
        texto=self.salida.getvalue()
        self.assertLess(texto.index('=== FIN DEL INFORME FACTUAL ==='),texto.index('Interpretación del modelo'))
        self.assertIn('Modelo | Asistente:',texto)
        self.assertIn('no verificada',texto)

    def test_compacta_explicita_validada_y_sin_herramientas(self):
        import proyeccion_compacta_auditoria as compacta
        with patch.dict(os.environ, {'ASISTENTE_PROYECCION_AUDITORIA':'compacta'}), \
             patch.object(compacta,'validar',wraps=compacta.validar) as validar, \
             patch.object(app,'consultar_modelo',return_value=completa('Explicación compacta.')) as modelo:
            traza=app.preguntar(FRASE)
        validar.assert_called_once()
        modelo.assert_called_once()
        self.assertEqual(modelo.call_args.args[1],self.deadline)
        self.assertEqual(modelo.call_args.kwargs,dict(permitir_herramientas=False,omitir_tools=True,interpretacion=True))
        p=json.loads(modelo.call_args.args[0][1]['content'])
        self.assertEqual(p['formato'],'explicacion_compacta_v1')
        compacta.validar(p,traza)
        self.comprobar_conservacion(traza)
        texto=self.salida.getvalue()
        self.assertLess(texto.index('=== FIN DEL INFORME FACTUAL ==='),texto.index('Modelo |'))

    def test_predeterminado_y_reversion_sin_reiniciar_proceso(self):
        import proyeccion_compacta_auditoria as compacta
        with patch.object(app,'consultar_modelo',return_value=completa('Explicación.')) as modelo:
            for opcion,esperado in ((None,'actual'),('compacta','compacta'),('actual','actual'),(None,'actual')):
                self.clock.t=1000.;self.h.llamadas=[]
                with patch.dict(os.environ):
                    if opcion is None:os.environ.pop('ASISTENTE_PROYECCION_AUDITORIA',None)
                    else:os.environ['ASISTENTE_PROYECCION_AUDITORIA']=opcion
                    with patch.object(compacta,'proyectar',wraps=compacta.proyectar) as construir:
                        traza=app.preguntar(FRASE)
                    p=json.loads(modelo.call_args.args[0][1]['content'])
                    self.assertEqual('formato' in p,esperado=='compacta')
                    self.assertEqual(construir.call_count,1 if esperado=='compacta' else 0)
                    self.comprobar_conservacion(traza)
            self.assertEqual(modelo.call_count,4)  # Una solicitud por objetivo, sin duplicación.

    def test_compacta_fallos_de_construccion_y_validacion_no_envian_ni_retroceden(self):
        import proyeccion_compacta_auditoria as compacta
        casos=(('proyectar',RuntimeError('fallo sintético')),('validar',ValueError('asociación inválida')))
        for funcion,error in casos:
            self.clock.t=1000.;self.h.llamadas=[]
            with self.subTest(funcion=funcion), \
                 patch.dict(os.environ, {'ASISTENTE_PROYECCION_AUDITORIA':'compacta'}), \
                 patch.object(compacta,funcion,side_effect=error), \
                 patch('proyeccion_auditoria_basica.proyectar',side_effect=AssertionError('Sin fallback')), \
                 patch.object(app,'consultar_modelo') as modelo:
                traza=app.preguntar(FRASE)
            modelo.assert_not_called();self.comprobar_conservacion(traza)
            self.assertIn('no disponible',self.salida.getvalue())

    def test_compacta_alterada_y_opcion_desconocida_se_rechazan(self):
        import proyeccion_compacta_auditoria as compacta
        construir=compacta.proyectar
        def alterar(t):
            p=construir(t);p['hallazgos'][0]['prioridad']='P1'
            return p
        for opcion in ('compacta','compactaa'):
            self.clock.t=1000.;self.h.llamadas=[]
            with self.subTest(opcion=opcion), \
                 patch.dict(os.environ, {'ASISTENTE_PROYECCION_AUDITORIA':opcion}), \
                 patch.object(compacta,'proyectar',side_effect=alterar), \
                 patch.object(app,'consultar_modelo') as modelo:
                traza=app.preguntar(FRASE)
            modelo.assert_not_called();self.comprobar_conservacion(traza)

    def test_compacta_excede_presupuesto_compartido_o_maximo_no_se_recorta(self):
        import proyeccion_compacta_auditoria as compacta
        for caso in ('compartido','maximo'):
            self.clock.t=1000.;self.h.llamadas=[]
            t=self.real(herramientas=self.h,detectar=lambda:distro(),reloj=self.clock)
            if caso=='maximo':
                next(r for r in t if r['tipo']=='hallazgo')['limitaciones']=['Aviso '+str(i)+'x'*1000 for i in range(20)]
            p=compacta.proyectar(t);tamano=len(serializar(p).encode())
            factual=(app.MAX_TOTAL_OUTPUT-t[-1]['presupuesto_final']['salida']-2*(tamano-1)) if caso=='compartido' else 0
            if caso=='maximo':self.assertGreater(tamano,app.MAX_OUTPUT)
            antes=serializar(t);llamadas=len(self.h.llamadas)
            app.mostrar_informe_factual('Informe factual conservado')
            with self.subTest(caso=caso), \
                 patch.dict(os.environ, {'ASISTENTE_PROYECCION_AUDITORIA':'compacta'}), \
                 patch.object(app,'consultar_modelo') as modelo:
                app.interpretar_auditoria_basica(t,1120.,factual)
            modelo.assert_not_called();self.assertEqual(antes,serializar(t))
            self.assertEqual(llamadas,len(self.h.llamadas))
            self.assertIn('presupuesto vigente de entrada',self.salida.getvalue())
            self.assertIn('Informe factual conservado',self.salida.getvalue())
            self.assertIn('No se truncan datos',self.salida.getvalue())

    def test_compacta_meta_orientativa_no_sustituye_presupuesto_y_http_solo_simulado(self):
        valor=resultado('diagnostico_mantenimiento_apt');valor['resultado']['limitaciones']=['Limitación ficticia '+('x'*1500)]
        self.h.valores['diagnostico_mantenimiento_apt']=valor
        cuerpo=json.dumps(completa('Explicación simulada.')).encode()
        with patch.dict(os.environ, {'ASISTENTE_PROYECCION_AUDITORIA':'compacta'}), \
             patch.object(app,'abrir_http_local',return_value=HTTP(cuerpo)) as abrir, \
             patch.object(app,'registrar_metadatos'):
            traza=app.preguntar(FRASE)
        abrir.assert_called_once()
        carga=json.loads(abrir.call_args.args[0].data)
        self.assertGreater(len(carga['messages'][1]['content'].encode()),6000)
        self.assertNotIn('tools',carga);self.assertNotIn('stream',carga)
        self.assertEqual(carga['tool_choice'],'none')
        self.assertEqual(carga['model'],app.MODEL)
        self.assertEqual(carga['max_tokens'],1800);self.assertEqual(carga['temperature'],0.2)
        self.assertLessEqual(abrir.call_args.kwargs['timeout'],90)
        self.assertLessEqual(abrir.call_args.kwargs['deadline'],1120.)
        self.comprobar_conservacion(traza)

    def test_timeout_una_solicitud_y_ninguna_adquisicion_adicional(self):
        def agotar(*args,**kwargs):
            self.assertEqual(len(self.h.llamadas),8)
            self.clock.t+=45
            raise TimeoutError('espera_cabeceras')
        with patch.object(app,'consultar_modelo',side_effect=agotar) as modelo:
            traza=app.preguntar(FRASE)
        modelo.assert_called_once()
        self.comprobar_conservacion(traza)
        self.assertIn('timeout del modelo',self.salida.getvalue())
        self.assertIn('no se reintenta',self.salida.getvalue())

    def test_sin_tiempo_omite_interpretacion_y_conserva_cierre(self):
        self.h.paso=15
        with patch.object(app,'consultar_modelo',side_effect=AssertionError('No queda tiempo')) as modelo:
            traza=app.preguntar(FRASE)
        modelo.assert_not_called()
        self.comprobar_conservacion(traza)
        self.assertEqual(traza[-1]['motivo_parada'],'tiempo_agotado')
        self.assertIn('Interpretación omitida',self.salida.getvalue())

    def test_respuestas_invalidas_incompletas_y_tool_calls_se_rechazan(self):
        con_tools=completa('Intento usar una herramienta.')
        con_tools['choices'][0]['message']['tool_calls']=[llamada('actualizar_apt')]
        casos=[{},con_tools,completa('Parcial','length'),
               completa('Filtrado','content_filter'),completa('No terminado',None),
               completa('  '),completa('x'*18001),
               {'choices':[{'message':{'role':'user','content':'No assistant'}}]}]
        for caso in casos:
            with self.subTest(caso=str(caso)[:60]):
                self.clock.t=1000.;self.h=Herramientas();self.h.reloj=self.clock;self.h.paso=3
                self.salida.seek(0);self.salida.truncate()
                with patch.object(app,'consultar_modelo',return_value=caso) as modelo:
                    traza=app.preguntar(FRASE)
                modelo.assert_called_once();self.comprobar_conservacion(traza)
                self.assertIn('no disponible',self.salida.getvalue())
                self.assertNotIn('Modelo |',self.salida.getvalue())

    def test_error_transporte_y_cancelacion_no_reintentan(self):
        import urllib.error
        for error in (urllib.error.URLError('sin servidor'),KeyboardInterrupt(),OSError('desconectado'),urllib.error.URLError(TimeoutError('espera_cabeceras'))):
            with self.subTest(error=type(error).__name__):
                self.clock.t=1000.;self.h=Herramientas();self.h.reloj=self.clock;self.h.paso=3
                with patch.object(app,'consultar_modelo',side_effect=error) as modelo:
                    traza=app.preguntar(FRASE)
                modelo.assert_called_once();self.comprobar_conservacion(traza)
        self.assertIn('cancelada por el usuario',self.salida.getvalue())
        self.assertIn('timeout del modelo',self.salida.getvalue())

    def test_proyeccion_sin_inventarios_datos_personales_ni_terminal(self):
        audit=resultado('auditoria_seguridad');audit['resultado']['inventario_dpkg']=[{'nombre':'PRIVADO_INVENTARIO'}]
        identidad=resultado('sistema');identidad['resultado']['kernel']='HOST_PRIVADO'
        red=resultado('interfaces_red');red['resultado']['interfaces']=[dict(nombre='DISPOSITIVO_PRIVADO',networkmanager={'conexion_observada':'CONEXION_PRIVADA'})]
        self.h.valores.update(auditoria_seguridad=audit,sistema=identidad,interfaces_red=red)
        with patch.object(app,'consultar_modelo',return_value=completa('Explicación.')) as modelo:
            traza=app.preguntar(FRASE)
        enviado=serializar(modelo.call_args.args[0])
        for secreto in ('PRIVADO_INVENTARIO','HOST_PRIVADO','DISPOSITIVO_PRIVADO','CONEXION_PRIVADA','=== INFORME FACTUAL'):
            self.assertNotIn(secreto,enviado)
        self.comprobar_conservacion(traza)

    def test_proyeccion_acotada_con_omisiones_y_prioridades_intactas(self):
        traza=self.real(herramientas=self.h,detectar=lambda:distro(),reloj=self.clock)
        for r in traza:
            if r['tipo']=='hallazgo':
                r['conclusion_python']='Observación '+('x'*10000)
                r['limitaciones']=['Limitación '+str(i)+'x'*400 for i in range(40)]
        antes=serializar(traza);p=proyectar(traza,5000)
        self.assertLessEqual(len(serializar(p)),5000)
        self.assertTrue(p['abreviada'])
        self.assertGreater(sum(p['omisiones'].values()),0)
        self.assertEqual(p['prioridades']['P3'],1)
        self.assertEqual(antes,serializar(traza))
        self.assertEqual(json.loads(serializar(p)),p)

    def test_cliente_http_simulado_omite_catalogo_y_respeta_timeout_explicativo(self):
        cuerpo=json.dumps(completa('Explicación por HTTP simulado.')).encode()
        with patch.object(app,'abrir_http_local',return_value=HTTP(cuerpo)) as abrir,patch.object(app,'registrar_metadatos'):
            traza=app.preguntar(FRASE)
        abrir.assert_called_once()
        carga=json.loads(abrir.call_args.args[0].data)
        self.assertNotIn('tools',carga)
        self.assertEqual(carga['tool_choice'],'none')
        self.assertEqual(carga['model'],app.MODEL)
        self.assertLessEqual(abrir.call_args.kwargs['timeout'],90)
        self.assertLessEqual(abrir.call_args.kwargs['deadline'],1120.)
        self.comprobar_conservacion(traza)

    def test_deadline_externo_acorta_coordinador_y_presupuesto_salida_se_respeta(self):
        traza=self.real(herramientas=self.h,detectar=lambda:distro(),reloj=self.clock,deadline=1002.)
        self.assertEqual({x[1] for x in self.h.llamadas},{1002.})
        self.assertEqual(traza[-1]['motivo_parada'],'tiempo_agotado')
        traza[-1]['presupuesto_final']['salida']=60000
        antes=serializar(traza)
        with patch.object(app,'consultar_modelo') as modelo:
            app.interpretar_auditoria_basica(traza,1120.,100)
        modelo.assert_not_called()
        self.assertEqual(antes,serializar(traza))
        self.assertIn('límite de salida',self.salida.getvalue())


if __name__=='__main__':unittest.main()
