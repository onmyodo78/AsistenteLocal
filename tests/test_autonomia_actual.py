"""Regresión de auditoría previa y rechazo de ampliaciones operativas imprecisas."""
import contextlib
import io
import json
import unittest
from unittest.mock import patch

import AsistenteLocal as app
from motor_consultas import planificar
from test_p0 import llamada, respuesta


class AutonomiaActual(unittest.TestCase):
    def setUp(self):
        self.pila = contextlib.ExitStack()
        self.addCleanup(self.pila.close)
        self.salida = io.StringIO()
        self.pila.enter_context(contextlib.redirect_stdout(self.salida))
        self.pila.enter_context(patch.object(app, 'seleccionar_backend_seguridad',
                                           return_value={'backend': 'debian'}))
        self.pila.enter_context(patch.object(app, 'ALLOW_EXTERNAL', False))
        self.pila.enter_context(patch.object(app.subprocess, 'Popen',
            side_effect=AssertionError('Procesos reales prohibidos')))
        self.pila.enter_context(patch.object(app, 'abrir_http_local',
            side_effect=AssertionError('HTTP real prohibido')))

    def test_peticion_imprecisa_no_delega_ampliaciones_al_modelo(self):
        with patch.object(app, 'consultar_modelo') as modelo, patch.object(
                app, 'ejecutar_consulta') as ejecutar:
            app.preguntar('Comprueba recursos y amplía el diagnóstico si procede')
        modelo.assert_not_called()
        ejecutar.assert_not_called()
        self.assertIn('Solicitud ambigua', self.salida.getvalue())

    def test_denegaciones_no_ejecutan_aunque_modelo_invoque_operaciones(self):
        casos = [llamada('terminal', '{"comando":"id"}'),
                 llamada('actualizar_apt'), llamada('diagnostico_vpn'),
                 llamada('disco', '{"autorizado":true}'),
                 llamada('disco', '{"comando":"sudo apt upgrade"}')]
        for solicitud in casos:
            with self.subTest(solicitud=solicitud), patch.object(app, 'ejecutar_consulta') as ejecutar, patch.object(
                    app, 'consultar_modelo', side_effect=[
                        respuesta([solicitud]), respuesta(content='Operación no realizada.')]):
                app._preguntar_con_herramientas('Comprueba recursos disponibles')
                ejecutar.assert_not_called()
        self.assertNotIn('diagnostico_vpn', app.herramientas_disponibles())

    def test_objetivo_general_tiene_ruta_determinista_separada(self):
        from auditoria_basica import es_objetivo_basico
        self.assertTrue(es_objetivo_basico('Realiza una auditoría básica del sistema'))
        self.assertFalse(es_objetivo_basico('No realices una auditoría básica del sistema'))
        plan = planificar('Realiza una auditoría básica del sistema')
        self.assertEqual(plan.nombres, ('auditoria_seguridad',))
        self.assertNotIn('diagnostico_mantenimiento_apt', app.TOOLS)
        self.assertNotIn('solicitar_operacion_apt', app.TOOLS)


class EnrutamientoBasico(unittest.TestCase):
    FRASE = ('Realiza una auditoría básica del sistema y explícame los problemas '
             'encontrados, ordenados por prioridad.')

    def setUp(self):
        self.pila=contextlib.ExitStack();self.addCleanup(self.pila.close)
        self.salida=io.StringIO()
        self.pila.enter_context(contextlib.redirect_stdout(self.salida))
        self.pila.enter_context(patch.object(app,'seleccionar_backend_seguridad',return_value={'backend':'debian'}))
        self.pila.enter_context(patch.object(app,'ALLOW_EXTERNAL',False))
        self.pila.enter_context(patch.object(app.subprocess,'Popen',side_effect=AssertionError('Procesos reales prohibidos')))
        self.pila.enter_context(patch.object(app,'abrir_http_local',side_effect=AssertionError('HTTP real prohibido')))

    def test_intencion_explicita_y_limites_del_reconocedor(self):
        from auditoria_basica import es_objetivo_basico
        positivas=(self.FRASE,'Auditoría básica',
                   'Haz una auditoría básica completa del sistema y resume los resultados.',
                   'Ejecuta una auditoría básica del sistema, muestra los hallazgos por prioridad.')
        negativas=('Realiza una auditoría de seguridad de Debian 13.',
                   'Qué es una auditoría básica del sistema',
                   'No realices una auditoría básica del sistema',
                   'Interpreta la auditoría básica anterior',
                   'Realiza una auditoría básica del sistema y descarga los paquetes',
                   'Realiza una auditoría básica del sistema sin consultar la red',
                   'Realiza una auditoría básica del sistema y explícame los problemas e instala las actualizaciones')
        for texto in positivas:
            with self.subTest(texto=texto):self.assertTrue(es_objetivo_basico(texto))
        for texto in negativas:
            with self.subTest(texto=texto):self.assertFalse(es_objetivo_basico(texto))

    def test_frase_exacta_usa_coordinador_completo_sin_depender_del_modelo(self):
        for origen in (10.,10000.):
            with self.subTest(origen=origen):
                self.salida.seek(0);self.salida.truncate()
                self.comprobar_frase_exacta(origen)

    def comprobar_frase_exacta(self,origen):
        import auditoria_basica as basica
        import cli
        from test_auditoria_basica import Herramientas,Reloj,distro,resultado
        from contratos_autonomia import validar_traza
        real=basica.auditar;ejecuciones=[]
        reloj=Reloj()
        # La entrada y el coordinador deben compartir origen monotónico.
        reloj.t=origen
        def adquirir(**opciones):
            herramientas=Herramientas()
            diag=resultado('diagnostico_mantenimiento_apt')
            diag['resultado'].update(evaluacion='BLOQUEADO',impedimentos=['dpkg_con_incidencias'])
            herramientas.valores['diagnostico_mantenimiento_apt']=diag
            traza=real(herramientas=herramientas,detectar=lambda:distro(),reloj=reloj,**opciones)
            ejecuciones.append((herramientas,traza))
            return traza
        with patch.object(app.time,'monotonic',side_effect=reloj), patch.object(basica,'auditar',side_effect=adquirir) as coordinador, patch.object(
                app,'planificar',side_effect=AssertionError('No usar el planificador de seguridad')), patch.object(
                app,'ejecutar_consulta',side_effect=AssertionError('No duplicar adquisiciones')), patch.object(
                app,'consultar_modelo',side_effect=TimeoutError('espera_cabeceras')) as modelo:
            traza=app.preguntar(self.FRASE)
            coordinador.assert_called_once()
            self.assertIn('deadline',coordinador.call_args.kwargs)
            self.assertEqual(coordinador.call_args.kwargs['deadline'],reloj.t+120)
            modelo.assert_called_once()
            self.assertEqual(modelo.call_args.kwargs,dict(permitir_herramientas=False,omitir_tools=True,interpretacion=True))
            texto=self.salida.getvalue()
            self.assertIn('Áreas comprobadas: 7/7',texto)
            self.assertIn('Preparación APT: BLOQUEADO',texto)
            self.assertIn('P1 |',texto)
            self.assertIn('Memoria:',texto)
            self.assertIn('Red:',texto)
            self.assertNotIn('[Consulta autorizada: auditoria_seguridad]',texto)
            salida_cli=io.StringIO()
            with contextlib.redirect_stdout(salida_cli):
                self.assertEqual(cli.main(['--formato','json','auditoria-basica']),0)
            desde_cli=json.loads(salida_cli.getvalue())
        self.assertEqual(traza[-1]['cobertura'].keys(),desde_cli[-1]['cobertura'].keys())
        for herramientas,t in ejecuciones:
            validar_traza(t)
            operaciones=[c[0] for c in herramientas.llamadas]
            self.assertEqual(len(operaciones),8)
            self.assertEqual(len(set(operaciones)),8)
            self.assertEqual(operaciones[-1],'diagnostico_mantenimiento_apt')
            self.assertLessEqual(t[-1]['presupuesto_final']['rondas'],4)
            self.assertEqual(t[0]['limites']['segundos'],120)
            self.assertFalse(t[0]['permisos']['externo'])

    def test_frase_exacta_respeta_agotamiento_del_reloj_compartido(self):
        import auditoria_basica as basica
        from test_auditoria_basica import Herramientas,Reloj,distro
        real=basica.auditar;reloj=Reloj();reloj.t=10.
        herramientas=Herramientas();herramientas.reloj=reloj;herramientas.paso=31
        def adquirir(**opciones):
            self.assertEqual(opciones['deadline'],130.)
            return real(herramientas=herramientas,detectar=lambda:distro(),reloj=reloj,**opciones)
        with patch.object(app.time,'monotonic',side_effect=reloj), patch.object(
                basica,'auditar',side_effect=adquirir), patch.object(app,'consultar_modelo') as modelo:
            traza=app.preguntar(self.FRASE)
        modelo.assert_not_called()
        self.assertEqual(traza[-1]['motivo_parada'],'tiempo_agotado')
        self.assertEqual(len(herramientas.llamadas),4)
        self.assertEqual({c[1] for c in herramientas.llamadas},{130.})

    def seguridad(self, respuesta_modelo):
        import auditoria_basica as basica
        import test_continuacion_auditoria as continuacion
        from motor_consultas import ContextoFactual
        contexto=ContextoFactual()
        resultado=continuacion.ContinuacionAuditoria.resultado(self)
        with patch.object(basica,'auditar',side_effect=AssertionError('No ampliar una auditoría de seguridad')), patch.object(
                app,'ejecutar_consulta',return_value=resultado) as ejecutar, patch.object(
                app,'consultar_modelo',side_effect=respuesta_modelo) as modelo:
            app.preguntar('Realiza una auditoría de seguridad de Debian 13.',contexto=contexto)
        self.assertEqual(ejecutar.call_count,1)
        self.assertEqual(ejecutar.call_args.args[0],'auditoria_seguridad')
        modelo.assert_called_once()
        self.assertFalse(modelo.call_args.kwargs['permitir_herramientas'])
        self.assertIn('3109',self.salida.getvalue())
        self.assertIn('3109',contexto.consultar()['auditoria_seguridad'][1])
        return self.salida.getvalue()

    def test_auditoria_seguridad_especifica_conserva_ruta_independiente(self):
        self.seguridad(lambda *args,**kw:respuesta(content='Interpretación de seguridad.'))

    def test_timeout_real_simulado_en_interpretacion_seguridad_conserva_hechos(self):
        texto=self.seguridad(TimeoutError('espera_cabeceras'))
        self.assertIn('interpretación de LM Studio no está disponible',texto)
        self.assertIn('No se reintenta',texto)


if __name__ == '__main__':
    unittest.main()
