"""Resultados y respuestas simuladas, sin ejecución de comandos ni LM Studio."""
import contextlib
import io
import json
import unittest
from unittest.mock import Mock, patch

import AsistenteLocal as app
from sesion_resultados import ColeccionSesion
from test_p0 import respuesta, llamada
from test_contratos_fedora import local
from test_historial_contratos import debian, apt_error
from test_interfaces_red import datos as interfaces


class CapturaConversacional(unittest.TestCase):
    def setUp(self):
        self.coleccion = ColeccionSesion()
        self.addCleanup(self.coleccion.cerrar)

    def preguntar(self, nombre, resultado, *, coleccion=None, fallo=False):
        mensajes = []
        def modelo(ms, *a, **kw):
            mensajes.append(json.loads(json.dumps(ms)))
            if len(mensajes) == 1:
                return respuesta([llamada(nombre)])
            if fallo:
                raise OSError('modelo no disponible')
            return respuesta(content='Interpretación simulada')
        with patch.object(app, 'consultar_modelo', side_effect=modelo), \
             patch.object(app, 'ejecutar_consulta', return_value=resultado) as ejecutar, \
             patch.object(app, 'seleccionar_backend_seguridad', return_value={'backend':'debian', 'estado':'parcial'}), \
             contextlib.redirect_stdout(io.StringIO()):
            app.preguntar('consulta', coleccion=self.coleccion if coleccion is None else coleccion)
        ejecutar.assert_called_once()
        return mensajes

    def test_fedora_captura_sin_inventario_ni_textos(self):
        original = app.ResultadoAuditoria(local(), app.MAX_OUTPUT)
        self.preguntar('auditoria_seguridad', original)
        r = self.coleccion.consultar()[0]['registro']
        self.assertEqual(r['procedencia'], 'fedora_auditoria_v1')
        self.assertNotIn('inventario_rpm', r)
        self.assertNotIn('kernel-core', json.dumps(r))
        self.assertIsNone(self.coleccion.consultar()[0]['observacion'])

    def test_debian_preserva_dpkg_y_error_apt(self):
        d = debian(2)
        d.update(estado_adquisicion='parcial', estado_inventario='completo', actualizaciones=apt_error())
        self.preguntar('auditoria_seguridad', app.ResultadoDebian(d, app.MAX_OUTPUT))
        r = self.coleccion.consultar()[0]['registro']
        self.assertEqual(r['componentes']['dpkg']['ejecucion'], 'correcto')
        self.assertEqual(r['componentes']['apt']['ejecucion'], 'error')
        self.assertIsNone(r['metricas']['apt_total_posibles'])

    def test_interfaces_captura_y_copia_independiente(self):
        original = app.ResultadoInterfaces(interfaces(), app.MAX_OUTPUT)
        self.preguntar('interfaces_red', original)
        antes = self.coleccion.consultar()
        original.datos['interfaces'][0]['nombre'] = 'privado'
        self.assertEqual(self.coleccion.consultar(), antes)
        r = antes[0]['registro']
        self.assertEqual(r['herramienta'], 'interfaces_red')
        self.assertEqual(set(r['metricas']), {'interfaces_enumeradas_ip'})

    def test_contrato_invalido_no_captura_sin_afectar(self):
        original = app.ResultadoDebian(debian(), app.MAX_OUTPUT)
        with patch.object(app, 'sanear_auditoria', side_effect=ValueError('privado')):
            self.preguntar('auditoria_seguridad', original)
        self.assertEqual(self.coleccion.consultar(), [])

    def test_sin_captura_desde_texto_u_otra_herramienta(self):
        self.preguntar('memoria', 'salida textual')
        self.assertEqual(self.coleccion.consultar(), [])
        app.capturar_resultado_saneado(self.coleccion, 'otra', app.ResultadoDebian(debian(), app.MAX_OUTPUT))
        self.assertEqual(self.coleccion.consultar(), [])

    def test_conserva_registro_si_falla_despues_modelo(self):
        self.preguntar('auditoria_seguridad', app.ResultadoAuditoria(local(), app.MAX_OUTPUT), fallo=True)
        self.assertEqual(len(self.coleccion.consultar()), 1)

    def test_llena_caducada_cerrada_no_afectan_mensajes(self):
        original = app.ResultadoAuditoria(local(), app.MAX_OUTPUT)
        referencia = self.preguntar('auditoria_seguridad', original, coleccion=Mock())
        with patch('sesion_resultados.MAX_REGISTROS', 0):
            self.assertEqual(self.preguntar('auditoria_seguridad', original), referencia)
        ahora = [0.]
        caducada = ColeccionSesion(reloj=lambda: ahora[0])
        ahora[0] = 1800.
        self.assertEqual(self.preguntar('auditoria_seguridad', original, coleccion=caducada), referencia)
        self.coleccion.cerrar()
        self.assertEqual(self.preguntar('auditoria_seguridad', original), referencia)

    def test_compatibilidad_preguntar_sin_coleccion(self):
        with patch.object(app, 'consultar_modelo', return_value=respuesta(content='respuesta')), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertIsNone(app.preguntar('consulta'))

    def test_main_crea_una_sesion_y_cierra(self):
        sesion = Mock()
        with patch.object(app.sys, 'argv', ['AsistenteLocal.py']), \
             patch.object(app, 'ColeccionSesion', return_value=sesion) as crear, \
             patch.object(app, 'informar_entorno'), patch('builtins.input', side_effect=['consulta', 'salir']), \
             patch.object(app, 'preguntar', side_effect=lambda texto: self.assertIs(app._COLECCION_SESION.get(), sesion)) as preguntar, contextlib.redirect_stdout(io.StringIO()):
            app.main()
        crear.assert_called_once_with()
        preguntar.assert_called_once_with('consulta')
        self.assertIsNone(app._COLECCION_SESION.get())
        sesion.cerrar.assert_called_once_with()

    def test_modos_verificados_no_crean_coleccion(self):
        with patch.object(app.sys, 'argv', ['AsistenteLocal.py', '--memoria-verificada']), \
             patch.object(app, 'ejecutar_memoria_verificada', return_value=3), \
             patch.object(app, 'ColeccionSesion') as crear:
            self.assertEqual(app.main(), 3)
        crear.assert_not_called()

    def test_modelo_no_puede_operar_la_coleccion(self):
        with patch.object(app, 'consultar_modelo', side_effect=[respuesta([llamada('vaciar_coleccion')]), respuesta(content='fin')]), \
             patch.object(app, 'ejecutar_consulta') as ejecutar, contextlib.redirect_stdout(io.StringIO()):
            app.preguntar('consulta', coleccion=self.coleccion)
        ejecutar.assert_not_called()
        self.assertEqual(len(app.TOOLS), 14)
        self.assertEqual(self.coleccion.consultar(), [])

    def test_captura_ocurre_antes_de_ajustar_para_modelo(self):
        original = app.ResultadoAuditoria(local(), app.MAX_OUTPUT)
        ajustar = original.ajustar
        def comprobar(limite):
            self.assertEqual(len(self.coleccion.consultar()), 1)
            return ajustar(limite)
        with patch.object(original, 'ajustar', side_effect=comprobar):
            self.preguntar('auditoria_seguridad', original)

    def test_main_eof_cierra_y_restaura_contexto(self):
        sesion = Mock()
        with patch.object(app.sys, 'argv', ['AsistenteLocal.py']), \
             patch.object(app, 'ColeccionSesion', return_value=sesion), \
             patch.object(app, 'informar_entorno'), patch('builtins.input', side_effect=EOFError()), \
             contextlib.redirect_stdout(io.StringIO()):
            app.main()
        sesion.cerrar.assert_called_once_with()
        self.assertIsNone(app._COLECCION_SESION.get())


class PresentacionDebian(unittest.TestCase):
    def datos(self, dpkg='completo', apt='error', total=None):
        d = debian(2)
        d.update(estado_inventario=dpkg, inventario_completo=dpkg == 'completo',
                 estado_adquisicion='completo' if dpkg == apt == 'completo' else
                    'error' if dpkg == apt == 'error' else 'parcial',
                 total_instalados=1 if dpkg == 'completo' else None)
        d['recuentos_recogidos']['instalado'] = 1
        d['inventario_dpkg'] = [dict(nombre_binario='paquete-privado',arquitectura='amd64',
            version='1:9.8-7+deb13u1',estado_instalacion='install ok installed',
            categoria='instalado',nombre_fuente='fuente-privada',version_fuente='9.8-7')]
        a = apt_error()
        a.update(estado_adquisicion=apt,total_posibles=total)
        disponible = apt != 'completo' or total == 1
        a['candidatos'] = [] if apt == 'error' else [dict(
            nombre_binario='paquete-privado',arquitectura='amd64',
            instalada='1:9.8-7+deb13u1',candidata='2:10.2-1' if disponible else None,
            prioridad=990 if disponible else None,retenido=False,
            superior=disponible,posible_actualizacion=disponible,instalable_garantizada=False,
            origenes=[dict(origen='origen-privado',archivo='trixie',componente='main',
                          sitio='repositorio-privado.invalid',confiable_segun_apt=True)] if disponible else [])]
        a['recuentos_recogidos'].update(registros=len(a['candidatos']),
            superiores=int(bool(a['candidatos']) and disponible),
            posibles=int(bool(a['candidatos']) and disponible))
        d['actualizaciones'] = a
        return d

    def ejecutar(self, datos, *, fallo=False, contenido='Interpretación simulada'):
        resultado = app.ResultadoDebian(datos,app.MAX_OUTPUT)
        efectos = [respuesta([llamada('auditoria_seguridad')]),
                   OSError('modelo simulado caído') if fallo else respuesta(content=contenido)]
        with patch.object(app,'consultar_modelo',side_effect=efectos) as modelo, \
             patch.object(app,'ejecutar_consulta',return_value=resultado) as adquirir, \
             patch.object(app.subprocess,'Popen',side_effect=AssertionError('Proceso real')), \
             patch.object(app,'abrir_http_local',side_effect=AssertionError('LM Studio real')), \
             contextlib.redirect_stdout(io.StringIO()) as salida:
            app.preguntar('auditoría simulada')
        adquirir.assert_called_once()
        self.assertEqual(modelo.call_count,2)
        mensajes = modelo.call_args.args[0]
        herramienta = [m['content'] for m in mensajes if m['role'] == 'tool'][0]
        for privado in ('paquete-privado','fuente-privada','1:9.8-7+deb13u1','2:10.2-1',
                        'repositorio-privado.invalid','origen-privado'):
            self.assertNotIn(privado,herramienta)
            self.assertNotIn(privado,salida.getvalue())
        self.assertNotIn('inventario_dpkg',json.loads(herramienta))
        self.assertNotIn('candidatos',json.loads(herramienta)['actualizaciones'])
        return salida.getvalue(),json.loads(herramienta)

    def test_dpkg_completo_apt_fallido_y_total_desconocido(self):
        texto,dato = self.ejecutar(self.datos())
        self.assertIn('Inventario dpkg: completo. Total de paquetes instalados: 1.',texto)
        self.assertIn('Adquisición APT: fallida. Total de posibles actualizaciones: desconocido.',texto)
        self.assertIn('Seguridad: no evaluada',texto)
        self.assertIn('no permiten confirmar ausencia de actualizaciones',texto)
        self.assertLess(texto.index('Hechos de auditoría Debian'),texto.index('Interpretación del modelo'))
        self.assertIsNone(dato['actualizaciones']['total_posibles'])
        self.assertEqual(dato['estado_inventario'],'completo')

    def test_auditoria_parcial_conserva_incertidumbre_de_ambas_fuentes(self):
        texto,dato = self.ejecutar(self.datos('parcial','parcial'))
        self.assertIn('Inventario dpkg: parcial. Total de paquetes instalados: desconocido.',texto)
        self.assertIn('Adquisición APT: parcial',texto)
        self.assertIn('Total de posibles actualizaciones: desconocido.',texto)
        self.assertEqual(dato['estado_adquisicion'],'parcial')

    def test_respuesta_incorrecta_modelo_no_sustituye_hechos(self):
        incorrecta = 'No hay actualizaciones pendientes.'
        texto,_ = self.ejecutar(self.datos(),contenido=incorrecta)
        self.assertIn('Total de posibles actualizaciones: desconocido.',texto)
        self.assertIn('Interpretación del modelo — no verificada; puede contradecir los hechos anteriores.',texto)
        self.assertLess(texto.index('Adquisición APT: fallida'),texto.index(incorrecta))
        self.assertLess(texto.index('Interpretación del modelo'),texto.index(incorrecta))

    def test_fallo_posterior_lmstudio_conserva_hechos_y_no_repite_consulta(self):
        texto,_ = self.ejecutar(self.datos(),fallo=True)
        self.assertIn('Inventario dpkg: completo',texto)
        self.assertIn('Adquisición APT: fallida',texto)
        self.assertIn('La interpretación de LM Studio no está disponible',texto)
        self.assertIn('No se reintenta ni se repiten las consultas.',texto)
        self.assertNotIn('Asistente:',texto)

    def test_completa_simulada_no_confunde_recuento_con_seguridad(self):
        for total in (0,1):
            with self.subTest(total=total):
                texto,dato = self.ejecutar(self.datos('completo','completo',total))
                self.assertIn('Adquisición APT: completa. Total de posibles actualizaciones: '+str(total)+'.',texto)
                self.assertIn('frescura no verificada',texto)
                self.assertIn('Seguridad: no evaluada',texto)
                self.assertEqual(dato['actualizaciones']['total_posibles'],total)

    def test_dpkg_fallido_y_limpieza_no_confirmada_explicitos(self):
        d = self.datos('error','error')
        d['fuente']['motivo'] = 'terminacion_no_confirmada'
        d['actualizaciones']['motivo'] = 'error_recogida'
        texto,_ = self.ejecutar(d)
        self.assertIn('Inventario dpkg: fallido',texto)
        self.assertIn('No se ha confirmado la recogida o el cierre del proceso dpkg.',texto)
        self.assertIn('No se ha confirmado la recogida o el cierre del proceso APT.',texto)

    def test_resumen_numeros_y_etiquetas_cerradas_sin_reflejar_texto(self):
        d = self.datos()
        d.update(estado_inventario='SECRETO',total_instalados='SECRETO')
        d['actualizaciones'].update(estado_adquisicion='SECRETO',total_posibles='SECRETO')
        d['estado_seguridad'] = 'SECRETO'
        self.assertNotIn('SECRETO',app.resumen_factual_debian(d))
        d = self.datos('completo','completo',True)
        self.assertIn('Total de posibles actualizaciones: desconocido.',app.resumen_factual_debian(d))
        # Contrato dpkg v1: APT no ejecutado, sin inventar un recuento cero.
        self.assertIn('Adquisición APT: no disponible',app.resumen_factual_debian(debian()))
