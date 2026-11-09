"""Plazos de interpretación: reloj y HTTP simulados, sin red ni adquisición real."""
import contextlib
import copy
import io
import json
import socket
import subprocess
import unittest
import urllib.error
from unittest.mock import patch
import AsistenteLocal as app
import auditoria_basica as basica
from test_lmstudio_comunicacion import HTTP, completa
from test_auditoria_basica import Herramientas, Reloj, distro
from motor_consultas import ContextoFactual


class Limites(unittest.TestCase):
    def setUp(self):
        self.reloj=Reloj();self.salida=io.StringIO();self.pila=contextlib.ExitStack()
        self.addCleanup(self.pila.close)
        self.pila.enter_context(contextlib.redirect_stdout(self.salida))
        self.pila.enter_context(patch.object(app.time,'monotonic',self.reloj))
        self.pila.enter_context(patch.object(subprocess,'Popen',side_effect=AssertionError('Proceso real prohibido')))
        self.pila.enter_context(patch.object(socket,'socket',side_effect=AssertionError('Red real prohibida')))
        self.pila.enter_context(patch.object(app,'herramientas_para_modelo',return_value={}))
        self.pila.enter_context(patch.object(app,'registrar_metadatos'))
        self.pila.enter_context(patch.object(app,'seleccionar_backend_seguridad',return_value={'backend':'debian','estado':'soportado'}))
        self.pila.enter_context(patch.object(app,'prompt_segun_backend',return_value='Hechos Python.'))

    def transporte(self,latencia=60,cuerpo=None,error=None):
        def abrir(req,**opciones):
            self.reloj.t+=latencia
            if self.reloj.t>=opciones['deadline']:raise TimeoutError('simulado')
            if error is not None:raise error
            return HTTP(json.dumps(cuerpo if cuerpo is not None else completa('Explicación.')).encode())
        return patch.object(app,'abrir_http_local',side_effect=abrir)

    def test_solo_marca_explicita_amplia_a_90_y_conserva_payload(self):
        for explicita,latencia in ((False,60),(True,60),(True,89)):
            with self.subTest(explicita=explicita,latencia=latencia):
                self.reloj.t=1000.
                with self.transporte(latencia) as abrir:
                    opciones=dict(permitir_herramientas=False,omitir_tools=True)
                    if explicita:
                        r=app.consultar_modelo([],1120.,interpretacion=True,**opciones)
                        self.assertEqual(r['choices'][0]['finish_reason'],'stop')
                    else:
                        with self.assertRaises(TimeoutError):app.consultar_modelo([],1120.,**opciones)
                abrir.assert_called_once()
                self.assertEqual(abrir.call_args.kwargs['timeout'],90 if explicita else 45)
                p=json.loads(abrir.call_args.args[0].data)
                self.assertEqual(set(p),{'model','messages','temperature','max_tokens','tool_choice'})
                self.assertEqual((p['max_tokens'],p['temperature'],p['tool_choice']),(1800,.2,'none'))
        self.assertEqual((app.MAX_SECONDS,app.MAX_MODEL_SECONDS,app.MAX_INTERPRETATION_SECONDS),(120,45,90))

    def test_conversacion_y_seleccion_ordinarias_siguen_a_45(self):
        with self.transporte(latencia=46) as abrir:
            with self.assertRaises(TimeoutError):app.consultar_modelo([],1120.)
        abrir.assert_called_once();self.assertEqual(abrir.call_args.kwargs['timeout'],45)
        self.assertEqual(json.loads(abrir.call_args.args[0].data)['tool_choice'],'auto')

    def test_marca_invalida_o_herramientas_no_desactivadas_no_envian(self):
        for kw in ({'interpretacion':True},{'interpretacion':True,'permitir_herramientas':False},
                   {'interpretacion':1,'permitir_herramientas':False,'omitir_tools':True}):
            with self.subTest(kw=kw),patch.object(app,'abrir_http_local') as abrir:
                with self.assertRaises(ValueError):app.consultar_modelo([],1120.,**kw)
                abrir.assert_not_called()

    def test_deadline_global_recorta_y_su_agotamiento_no_envia(self):
        for restante in (70,10):
            self.reloj.t=1000.
            with self.subTest(restante=restante),self.transporte(restante+1) as abrir:
                with self.assertRaises(TimeoutError):
                    app.consultar_modelo([],1000.+restante,False,True,interpretacion=True)
                self.assertEqual(abrir.call_args.kwargs['deadline'],1000.+restante)
                self.assertEqual(abrir.call_args.kwargs['timeout'],restante)
                abrir.assert_called_once()
        with patch.object(app,'abrir_http_local') as abrir:
            with self.assertRaises(TimeoutError):app.consultar_modelo([],self.reloj.t,False,True,interpretacion=True)
            abrir.assert_not_called()

    def test_cuerpo_no_reinicia_presupuesto_tras_cabeceras(self):
        reloj=self.reloj
        class Lenta(HTTP):
            def read1(self,n):
                reloj.t+=31
                return super().read1(n)
        def abrir(*a,**kw):
            self.reloj.t+=60
            return Lenta(json.dumps(completa()).encode())
        with patch.object(app,'abrir_http_local',side_effect=abrir) as transporte:
            with self.assertRaises(TimeoutError):app.consultar_modelo([],1120.,False,True,interpretacion=True)
        transporte.assert_called_once()
        self.assertEqual(transporte.call_args.kwargs['deadline'],1090.)

    def datos(self):
        return app.ResultadoDebian(dict(backend='debian',herramienta='auditoria_seguridad',
            estado_inventario='completo',total_instalados=3109,inventario_dpkg=[],
            actualizaciones={'estado_adquisicion':'completo','total_posibles':37,'candidatos':[],
                'indices':{'necesarios':21,'opcionales':1,'no_aplicables':13}}),app.MAX_OUTPUT)

    def test_continuacion_apt_60_segundos_y_metadatos_de_indices_intactos(self):
        datos=self.datos();original=copy.deepcopy(datos.datos)
        with patch.object(app,'ejecutar_consulta',return_value=datos) as adquirir,self.transporte() as abrir:
            app.preguntar('Consulta ahora las actualizaciones pendientes de Debian')
        adquirir.assert_called_once();abrir.assert_called_once()
        self.assertEqual(adquirir.call_args.args[1],1120.)
        self.assertEqual(abrir.call_args.kwargs['deadline'],1090.)
        p=json.loads(abrir.call_args.args[0].data)
        enviados=json.loads(next(m['content'] for m in p['messages'] if m['role']=='tool'))
        self.assertEqual(enviados['actualizaciones']['indices'],original['actualizaciones']['indices'])
        self.assertIn('no paquetes ni actualizaciones',p['messages'][0]['content'])
        self.assertEqual(datos.datos,original)
        texto=self.salida.getvalue()
        self.assertLess(texto.index('FIN DEL INFORME FACTUAL'),texto.index('Modelo |'))

    def test_fallback_apt_errores_no_reintentan_y_conservan_factual(self):
        for latencia,error,cuerpo in ((91,None,None),(1,urllib.error.HTTPError('http://local',500,'simulado',{},io.BytesIO()),None),(1,None,completa('Parcial','length'))):
            self.reloj.t=1000.;self.salida.seek(0);self.salida.truncate()
            with self.subTest(latencia=latencia,error=type(error).__name__), \
                 patch.object(app,'ejecutar_consulta',return_value=self.datos()) as adquirir, \
                 self.transporte(latencia,cuerpo,error) as abrir:
                app.preguntar('Consulta ahora las actualizaciones pendientes de Debian')
            adquirir.assert_called_once();abrir.assert_called_once()
            texto=self.salida.getvalue()
            self.assertIn('Total de posibles actualizaciones: 37',texto)
            self.assertIn('FIN DEL INFORME FACTUAL',texto)
            self.assertIn('no está disponible',texto);self.assertNotIn('Modelo |',texto)

    def test_auditoria_basica_y_reutilizacion_marcan_interpretacion(self):
        real=basica.auditar;h=Herramientas()
        def adquirir(**kw):return real(herramientas=h,detectar=lambda:distro(),reloj=self.reloj,**kw)
        with patch.object(basica,'auditar',side_effect=adquirir),self.transporte() as abrir:
            traza=app.preguntar('Realiza una auditoría básica del sistema')
        abrir.assert_called_once();self.assertEqual(abrir.call_args.kwargs['deadline'],1090.)
        self.assertEqual(len(h.llamadas),8);self.assertEqual(traza[-1]['estado'],'completo')
        self.reloj.t=1000.
        contexto=ContextoFactual(reloj=self.reloj);contexto.guardar('auditoria_seguridad','37 candidatas; seguridad no evaluada.')
        with patch.object(app,'ejecutar_consulta',side_effect=AssertionError('Sin adquisición nueva')),self.transporte() as abrir:
            app.interpretar_contexto('Explica los resultados anteriores',contexto,('auditoria_seguridad',),1120.)
        abrir.assert_called_once();self.assertEqual(abrir.call_args.kwargs['deadline'],1090.)

if __name__=='__main__':unittest.main()
