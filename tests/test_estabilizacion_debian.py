"""Backend y contratos de integración simulados: sin APT, procesos ni HTTP reales."""
import contextlib
import copy
import io
import json
import unittest
from unittest.mock import Mock, patch

import AsistenteLocal as app
import auditoria_debian as deb
import apt_debian as apt
import backend_seguridad as backend
import test_integracion_local as integracion
from distribucion_linux import detectar_distribucion
from evidencia_local import comprobar, comprobar_debian, comprobar_respuesta
import test_auditoria_debian as fixtures_dpkg
from test_auditoria_debian import fila
import test_apt_debian as fixtures_apt
from test_apt_debian import salida, registro
from test_p0 import respuesta


class EstabilizacionDebian(unittest.TestCase):
    def setUp(self):
        self.pila = contextlib.ExitStack()
        self.addCleanup(self.pila.close)
        self.pila.enter_context(patch.object(app.subprocess,'Popen',side_effect=AssertionError('Proceso real')))
        self.pila.enter_context(patch.object(app,'abrir_http_local',side_effect=AssertionError('HTTP real')))
        self.pila.enter_context(patch.object(app.urllib.request,'build_opener',side_effect=AssertionError('HTTP real')))
        importar = __import__
        def sin_apt(nombre,*args,**kw):
            if nombre == 'apt_pkg' or nombre == 'apt' or nombre.startswith('apt.'):
                raise AssertionError('APT real')
            return importar(nombre,*args,**kw)
        self.pila.enter_context(patch('builtins.__import__',side_effect=sin_apt))

    def seleccionar(self, distro='debian'):
        texto = {'debian':'ID=debian\nVERSION_ID=13','fedora':'ID=fedora\nVERSION_ID=44',
                 'otra':'ID=otra'}[distro]
        return patch.object(backend,'detectar_distribucion',return_value=detectar_distribucion(contenido=texto))

    def datos(self, dpkg_parcial=False, apt_estado='error', motivo=None):
        inventario = fixtures_dpkg.InventarioDebian().adquirir(fila(version='1:1.0-1')+('invalido\n' if dpkg_parcial else ''))
        if apt_estado == 'completo':
            actualizaciones = fixtures_apt.AptLocal().adquirir()
        elif apt_estado == 'parcial':
            actualizaciones = fixtures_apt.AptLocal().adquirir(salida(fin=False),codigo=72)
        else:
            actualizaciones = fixtures_apt.AptLocal().adquirir('',codigo=70 if motivo == 'python3_apt_no_disponible' else 72)
        with patch.object(deb,'consultar_inventario',return_value=inventario), \
             patch.object(apt,'consultar_actualizaciones',return_value=actualizaciones):
            return deb.consultar_auditoria(120)

    def resultado(self,**kw):
        return app.ResultadoDebian(self.datos(**kw),5000)

    def test_descripciones_debian_no_anuncian_fedora_y_conservan_registro(self):
        originales = copy.deepcopy(app.TOOLS)
        with self.seleccionar():
            herramientas = app.herramientas_para_modelo()
            texto = herramientas['auditoria_seguridad']['description']
            for esperado in ('dpkg','parcial','no verificable','desconocido','no implementada'):
                self.assertIn(esperado,texto)
            self.assertNotIn('Fedora',texto)
            self.assertNotIn('DNF',texto)
            self.assertNotIn('RPM',texto)
            self.assertIn('no implementada',herramientas['correlacion_seguridad']['description'])
            self.assertIn('null es desconocido',app.prompt_segun_backend())
            self.assertNotIn('para Fedora KDE',app.prompt_segun_backend())
            self.assertEqual(json.loads(app.ejecutar_consulta('correlacion_seguridad'))['estado'],'no_implementado')
        self.assertEqual(app.TOOLS,originales)

    def test_fedora_conserva_descripciones_y_prompt(self):
        with self.seleccionar('fedora'):
            herramientas = app.herramientas_para_modelo()
            for nombre in app.HERRAMIENTAS_SEGURIDAD:
                self.assertEqual(herramientas[nombre]['description'],app.TOOLS[nombre]['description'])
            self.assertEqual(app.prompt_segun_backend(),app.SYSTEM_PROMPT)
        with self.seleccionar('otra'):
            for nombre in app.HERRAMIENTAS_SEGURIDAD:
                self.assertIn('no disponible',app.herramientas_para_modelo()[nombre]['description'])

    def test_mensajes_entorno_coherentes_y_dependencia_opcional(self):
        for distro in ('debian','fedora','otra'):
            with self.subTest(distro=distro),self.seleccionar(distro), \
                 patch.object(app.shutil,'which',return_value='/bin/simulado'), \
                 patch.object(app.importlib.util,'find_spec',return_value=None), \
                 contextlib.redirect_stdout(io.StringIO()) as consola:
                app.informar_entorno()
            texto = consola.getvalue()
            if distro == 'debian':
                for esperado in ('inventario dpkg disponible','puede ser parcial o no verificable',
                                 'Correlación CVE Debian no implementada','python:apt_pkg: ausente'):
                    self.assertIn(esperado,texto)
                for incorrecto in ('Fedora','DNF','RPM'):
                    self.assertNotIn(incorrecto,texto)
            elif distro == 'fedora':
                self.assertIn('terminal nativa de Fedora anfitrión',texto)
                self.assertNotIn('Debian',texto)
            else:
                self.assertIn('distribución no soportada',texto)

    def test_payload_modelo_usa_descripciones_del_backend_sin_http(self):
        http = Mock(status=200,fp=None)
        http.__enter__ = Mock(return_value=http)
        http.__exit__ = Mock(return_value=False)
        http.read1.side_effect = [json.dumps(respuesta(content='simulado')).encode(),b'']
        with self.seleccionar(),patch.object(app,'abrir_http_local',return_value=http) as abrir, \
             patch.object(app,'registrar_metadatos'):
            app.consultar_modelo([{'role':'user','content':'simulado'}])
        contenido = json.loads(abrir.call_args.args[0].data)
        descripciones = {t['function']['name']:t['function']['description'] for t in contenido['tools']}
        self.assertIn('Inventario local dpkg',descripciones['auditoria_seguridad'])
        self.assertIn('no implementada',descripciones['correlacion_seguridad'])

    def test_contrato_parcial_acepta_degradacion_no_cobertura_completa(self):
        for dpkg_parcial in (False,True):
            for estado in ('error','parcial','completo'):
                with self.subTest(dpkg=dpkg_parcial,apt=estado):
                    resultado = self.resultado(dpkg_parcial=dpkg_parcial,apt_estado=estado)
                    evidencia = comprobar('auditoria_seguridad',resultado,nivel_debian='contrato')
                    self.assertIn('Contrato Debian verificado',evidencia)
                    if not dpkg_parcial and estado == 'completo':
                        self.assertIn('Cobertura APT completa',comprobar_debian(resultado,apt_completo=True))
                    else:
                        self.assertIn('cobertura APT no confirmada',evidencia)
                        self.assertIsNone(resultado.datos['actualizaciones']['total_posibles'])
                        with self.assertRaises(AssertionError):
                            comprobar_debian(resultado,apt_completo=True)

    def test_rechaza_parciales_incoherentes_y_candidatas_inventadas(self):
        referencia = self.datos(apt_estado='parcial')
        cambios = [lambda d:d['actualizaciones'].update(total_posibles=0),
                   lambda d:d.update(estado_adquisicion='completo'),
                   lambda d:d['actualizaciones'].update(motivo=None),
                   lambda d:d['actualizaciones']['recuentos_recogidos'].update(posibles=0),
                   lambda d:d['actualizaciones'].update(candidatos=[]),
                   lambda d:d.update(estado_seguridad='seguro'),
                   lambda d:d['actualizaciones']['candidatos'][0].update(candidata=None)]
        for cambio in cambios:
            dato = copy.deepcopy(referencia)
            cambio(dato)
            with self.subTest(cambio=cambio),self.assertRaises(AssertionError):
                comprobar_debian(app.ResultadoDebian(dato,5000))
        dato = self.datos(apt_estado='completo')
        dato['actualizaciones']['candidatos'][0]['nombre_binario'] = 'inventado'
        with self.assertRaises(AssertionError):
            comprobar_debian(app.ResultadoDebian(dato,5000),apt_completo=True)

    def test_fallo_inventario_no_se_convierte_en_degradacion_aceptable(self):
        d = self.datos()
        d.update(estado_inventario='error',inventario_completo=False,inventario_dpkg=[],
                 estado_adquisicion='error',total_instalados=None,
                 recuentos_recogidos=dict(instalado=0,incompleto=0,residual=0,no_instalado=0))
        d['fuente']['motivo'] = 'permiso_denegado'
        with self.assertRaises(AssertionError):
            comprobar_debian(app.ResultadoDebian(d,5000))

    def test_errores_y_advertencias_no_pueden_desaparecer_del_resumen(self):
        r = self.resultado(motivo='python3_apt_no_disponible')
        comprobar_debian(r)
        self.assertEqual(r.datos['actualizaciones']['motivo'],'python3_apt_no_disponible')
        for campo,valor in (('motivo',None),('limitaciones',[]),('codigo',0)):
            vista = json.loads(r)
            vista['actualizaciones'][campo] = valor
            # Usar un subtipo que altere solo la vista pública, conservando datos.
            copia = str.__new__(app.ResultadoDebian,json.dumps(vista))
            copia._instantanea = json.dumps(r.datos)
            with self.subTest(campo=campo),self.assertRaises(AssertionError):
                comprobar_debian(copia)

    def test_sin_candidata_confirmada_no_es_error_ni_candidata_inventada(self):
        d = self.datos(apt_estado='completo')
        d['actualizaciones']['candidatos'] = [registro(candidata=None,prioridad=None,
            superior=False,posible_actualizacion=False)]
        d['actualizaciones']['recuentos_recogidos'].update(superiores=0,posibles=0)
        d['actualizaciones']['total_posibles'] = 0
        comprobar_debian(app.ResultadoDebian(d,5000),apt_completo=True)
        with self.assertRaises(AssertionError):
            comprobar_respuesta('auditoria_seguridad','No hay actualizaciones pendientes.',self.resultado())

    def entorno(self, apt_presente, dpkg_presente=True):
        return dict(backend_seguridad=dict(backend='debian',estado='parcial'),dependencias={
            'auditoria_seguridad': {'dpkg-query':dict(estado='disponible' if dpkg_presente else 'ausente'),
                                   'python:apt_pkg':dict(estado='disponible' if apt_presente else 'ausente')}})

    def test_dependencia_apt_opcional_no_omite_dpkg(self):
        caso = integracion.IntegracionLocal('test_herramientas_locales')
        with patch.object(app,'entorno_ejecucion',return_value=self.entorno(False)):
            self.assertTrue(caso.dependencias_disponibles('auditoria_seguridad'))

    def ejecutar_cobertura_simulada(self, apt_presente=True, dpkg_presente=True, resultado=None):
        caso = integracion.IntegracionLocal('test_cobertura_apt_completa')
        estado = unittest.TestResult()
        with self.seleccionar(),patch.object(integracion.IntegracionLocal,'__unittest_skip__',False), \
             patch.object(app,'entorno_ejecucion',return_value=self.entorno(apt_presente,dpkg_presente)), \
             patch.object(app,'ejecutar_consulta',return_value=resultado) as adquirir, \
             contextlib.redirect_stdout(io.StringIO()):
            caso.run(estado)
        return estado,adquirir

    def test_cobertura_omitida_solo_por_dependencia_o_backend(self):
        for apt_presente,dpkg_presente in ((False,True),(True,False)):
            estado,adquirir = self.ejecutar_cobertura_simulada(apt_presente,dpkg_presente)
            self.assertTrue(estado.skipped)
            self.assertFalse(estado.errors or estado.failures)
            adquirir.assert_not_called()
            self.assertIn('python3-apt' if not apt_presente else 'dpkg',estado.skipped[-1][1])

    def test_cobertura_falla_realmente_si_adquisicion_falla_no_se_omite(self):
        for apt_estado in ('error','parcial','completo'):
            estado,adquirir = self.ejecutar_cobertura_simulada(resultado=self.resultado(apt_estado=apt_estado))
            adquirir.assert_called_once_with('auditoria_seguridad')
            self.assertFalse(estado.errors or estado.skipped)
            self.assertEqual(len(estado.failures),int(apt_estado != 'completo'))

    def test_general_valida_dpkg_sin_python3_apt_y_sin_omitir_auditoria(self):
        resultado = self.resultado(motivo='python3_apt_no_disponible')
        caso = integracion.IntegracionLocal('test_herramientas_locales')
        estado = unittest.TestResult()
        with self.seleccionar(),patch.object(integracion.IntegracionLocal,'__unittest_skip__',False), \
             patch.object(app,'TOOLS',{'auditoria_seguridad':app.TOOLS['auditoria_seguridad']}), \
             patch.object(app,'entorno_ejecucion',return_value=self.entorno(False)), \
             patch.object(app,'ejecutar_consulta',return_value=resultado) as adquirir, \
             contextlib.redirect_stdout(io.StringIO()) as consola:
            caso.run(estado)
        self.assertFalse(estado.errors or estado.failures or estado.skipped)
        adquirir.assert_called_once_with('auditoria_seguridad')
        self.assertIn('cobertura APT no confirmada',consola.getvalue())
        self.assertIn('python3_apt_no_disponible',consola.getvalue())

    def test_contrato_no_acepta_degradacion_generica_ni_advertencias_inventadas(self):
        for motivo in ('desconocido','avisos_no_interpretados'):
            d = self.datos(apt_estado='parcial')
            d['actualizaciones']['motivo'] = motivo
            with self.subTest(motivo=motivo),self.assertRaises(AssertionError):
                comprobar_debian(app.ResultadoDebian(d,5000))
        d = self.datos(apt_estado='parcial')
        d['actualizaciones']['candidatos'][0]['nombre_binario'] = 'inventado'
        with self.assertRaises(AssertionError):
            comprobar_debian(app.ResultadoDebian(d,5000))

    def test_indices_viejos_no_se_confunden_con_frescura_verificada(self):
        d = self.datos(apt_estado='completo')
        d['actualizaciones']['indices'].update(edad_max_s=700000,potencialmente_desactualizados=True)
        resultado = app.ResultadoDebian(d,5000)
        comprobar_debian(resultado,apt_completo=True)
        self.assertTrue(json.loads(resultado)['actualizaciones']['indices']['potencialmente_desactualizados'])
        d['actualizaciones']['indices']['frescura'] = 'verificada'
        with self.assertRaises(AssertionError):
            comprobar_debian(app.ResultadoDebian(d,5000),apt_completo=True)

    def test_avisos_reales_del_contrato_se_conservan_sin_afirmar_completitud(self):
        inventario = fixtures_dpkg.InventarioDebian().adquirir(fila(version='1:1.0-1'),stderr=b'aviso simulado')
        actualizaciones = fixtures_apt.AptLocal().adquirir(stderr=b'aviso simulado')
        with patch.object(deb,'consultar_inventario',return_value=inventario), \
             patch.object(apt,'consultar_actualizaciones',return_value=actualizaciones):
            resultado = app.ResultadoDebian(deb.consultar_auditoria(120),5000)
        comprobar_debian(resultado)
        vista = json.loads(resultado)
        self.assertEqual(vista['fuente']['motivo'],'avisos_no_interpretados')
        self.assertEqual(vista['actualizaciones']['motivo'],'avisos_no_interpretados')
        self.assertGreater(vista['fuente']['stderr_bytes'],0)
        self.assertGreater(vista['actualizaciones']['stderr_bytes'],0)
        with self.assertRaises(AssertionError):
            comprobar_debian(resultado,apt_completo=True)

    def test_cobertura_apt_omitida_en_fedora_no_adquiere(self):
        caso = integracion.IntegracionLocal('test_cobertura_apt_completa')
        estado = unittest.TestResult()
        with self.seleccionar('fedora'),patch.object(integracion.IntegracionLocal,'__unittest_skip__',False), \
             patch.object(app,'ejecutar_consulta') as adquirir:
            caso.run(estado)
        self.assertEqual(len(estado.skipped),1)
        self.assertFalse(estado.failures or estado.errors)
        adquirir.assert_not_called()

    def test_arranque_y_prompt_no_se_identifican_como_fedora_en_debian(self):
        for distro in ('debian','fedora'):
            with self.subTest(distro=distro),self.seleccionar(distro), \
                 patch.object(app.sys,'argv',['AsistenteLocal.py']), \
                 patch.object(app,'informar_entorno'),patch('builtins.input',side_effect=EOFError()), \
                 contextlib.redirect_stdout(io.StringIO()) as consola:
                app.main()
            self.assertIn('Asistente local de '+('Debian 13' if distro == 'debian' else 'Fedora'),consola.getvalue())


if __name__ == '__main__':
    unittest.main()
