"""Selección simulada, sin comandos del sistema ni conexiones HTTP."""
import contextlib
import io
import json
import time
import unittest
from unittest.mock import Mock, patch

import AsistenteLocal as app
import backend_seguridad as backend
from distribucion_linux import detectar_distribucion
from evidencia_local import comprobar
from test_contratos_fedora import local
import test_integracion_local as integracion


class SeleccionSeguridad(unittest.TestCase):
    def seleccionar(self, contenido):
        return patch.object(backend, 'detectar_distribucion',
                            return_value=detectar_distribucion(contenido=contenido))

    def test_seleccion(self):
        for contenido, esperado in [('ID=fedora\nVERSION_ID=44', ('fedora', 'disponible')),
            ('ID=debian\nVERSION_ID=13', ('debian', 'parcial')),
            ('ID=debian\nVERSION_ID=12', (None, 'no_soportado')),
            ('ID=ubuntu\nVERSION_ID=24.04\nID_LIKE=debian', (None, 'no_soportado')),
            ('invalido', (None, 'no_soportado'))]:
            with self.subTest(contenido=contenido), self.seleccionar(contenido):
                seleccion = backend.seleccionar_backend_seguridad()
                self.assertEqual((seleccion['backend'], seleccion['estado']), esperado)

    def test_no_fedora_no_ejecuta_ni_adquiere_incluso_externas_autorizadas(self):
        for contenido in ('ID=otra', 'invalido'):
            for permitir in (False, True):
                with self.subTest(contenido=contenido, externas=permitir), self.seleccionar(contenido), \
                     patch.object(app, 'ALLOW_EXTERNAL', permitir), \
                     patch.object(app, 'consultar_auditoria_seguridad') as audit, \
                     patch.object(app, 'consultar_correlacion') as corr, \
                     patch.object(app.subprocess, 'Popen', side_effect=AssertionError('Proceso real')), \
                     patch.object(app, 'abrir_http_local', side_effect=AssertionError('HTTP real')), \
                     patch.object(app.urllib.request, 'build_opener', side_effect=AssertionError('HTTP real')):
                    for nombre in app.HERRAMIENTAS_SEGURIDAD:
                        texto = app.ejecutar_consulta(nombre)
                        datos = json.loads(texto)
                        self.assertIn(datos['estado'], ('no_implementado', 'no_soportado'))
                        self.assertEqual(datos['estado_adquisicion'], 'no_realizada')
                        self.assertEqual(datos['herramienta'], nombre)
                        self.assertNotIn('recuentos', datos)
                        self.assertNotIn('resultados', datos)
                        self.assertNotIsInstance(texto, app.ResultadoAuditoria)
                        with self.assertRaises(AssertionError):
                            comprobar(nombre, texto)
                    audit.assert_not_called()
                    corr.assert_not_called()

    def test_fedora_conserva_salida_y_argumentos(self):
        deadline = time.monotonic()+120
        datos = local()
        esperado = app.ResultadoAuditoria(datos, app.MAX_OUTPUT)
        with self.seleccionar('ID=fedora\nVERSION_ID=44'), \
             patch.object(app, 'consultar_auditoria_seguridad', return_value=datos) as audit:
            resultado = app.ejecutar_consulta('auditoria_seguridad', deadline)
            self.assertIsInstance(resultado, app.ResultadoAuditoria)
            self.assertEqual(resultado, esperado)
            self.assertEqual(resultado.datos, esperado.datos)
            audit.assert_called_once_with(deadline)
        informe = {'resultados': [], 'total_resultados': 0}
        with self.seleccionar('ID=fedora\nVERSION_ID=44'), \
             patch.object(app, 'consultar_correlacion', return_value=informe) as corr, \
             patch.object(app, 'ALLOW_EXTERNAL', False):
            self.assertEqual(app.ejecutar_consulta('correlacion_seguridad', deadline),
                             app.presentar_correlacion(informe, app.MAX_OUTPUT))
            corr.assert_called_once_with(app.consultar_auditoria_seguridad,
                                        app.ejecutar_comando, False, deadline)

    def test_dependencias_backend_y_registro(self):
        originales = {n: list(t['commands']) for n,t in app.TOOLS.items()}
        for contenido, disponible in [('ID=fedora\nVERSION_ID=44', True),
                                      ('ID=debian\nVERSION_ID=13', False), ('ID=otra', False)]:
            with self.subTest(contenido=contenido), self.seleccionar(contenido), \
                 patch.object(app.shutil, 'which', return_value='/bin/simulado') as which:
                entorno = app.entorno_ejecucion()
                self.assertEqual(set(entorno['dependencias']), set(app.TOOLS))
                for nombre in app.HERRAMIENTAS_SEGURIDAD:
                    self.assertEqual(bool(entorno['dependencias'][nombre]), disponible or
                        (contenido == 'ID=debian\nVERSION_ID=13' and nombre == 'auditoria_seguridad'))
                if contenido == 'ID=debian\nVERSION_ID=13':
                    self.assertEqual(set(entorno['dependencias']['auditoria_seguridad']), {'dpkg-query', 'python:apt_pkg'})
                if not disponible:
                    self.assertFalse({'rpm', 'dnf', 'dnf5'} & {c.args[0] for c in which.call_args_list})
                self.assertEqual(entorno['dependencias']['disco']['df']['estado'], 'disponible')
        self.assertEqual(len(app.TOOLS), 14)
        self.assertEqual({n: t['commands'] for n,t in app.TOOLS.items()}, originales)

    def test_autorizacion_y_plazo_preceden_backend(self):
        with patch.object(app, 'seleccionar_backend_seguridad') as seleccionar, \
             patch.object(app, 'TOOLS', {}):
            self.assertIn('RECHAZADA', app.ejecutar_consulta('auditoria_seguridad'))
            seleccionar.assert_not_called()
        with patch.object(app, 'seleccionar_backend_seguridad') as seleccionar:
            with self.assertRaises(TimeoutError):
                app.ejecutar_consulta('auditoria_seguridad', time.monotonic()-1)
            seleccionar.assert_not_called()

    def test_integracion_omite_backend_y_continua_sin_exito_vacio(self):
        for metodo in ('test_herramientas_locales', 'test_modelo_herramientas_y_respuesta_final'):
            for solo_seguridad in (False, True):
                herramientas = {'correlacion_seguridad': app.TOOLS['correlacion_seguridad']}
                if not solo_seguridad:
                    herramientas['disco'] = app.TOOLS['disco']
                ejecutadas = []
                def ejecutar(nombre, *args):
                    ejecutadas.append(nombre)
                    return 'datos simulados'
                def preguntar(*args):
                    app.ejecutar_consulta(next(iter(app.TOOLS)))
                    print('Asistente: Respuesta simulada de longitud suficiente.')
                caso = integracion.IntegracionLocal(metodo)
                resultado = unittest.TestResult()
                with self.subTest(metodo=metodo, solo=solo_seguridad), \
                     self.seleccionar('ID=debian\nVERSION_ID=13'), \
                     patch.object(integracion.IntegracionLocal, '__unittest_skip__', False), \
                     patch.object(app, 'TOOLS', herramientas), \
                     patch.object(app.shutil, 'which', return_value='/bin/simulado'), \
                     patch.object(app, 'ejecutar_consulta', side_effect=ejecutar), \
                     patch.object(app, 'preguntar', side_effect=preguntar), \
                     patch.object(integracion, 'comprobar', return_value='evidencia'), \
                     patch.object(integracion, 'comprobar_respuesta'), \
                     patch.object(app.subprocess, 'Popen', side_effect=AssertionError('Proceso real')), \
                     patch.object(app, 'abrir_http_local', side_effect=AssertionError('HTTP real')), \
                     contextlib.redirect_stdout(io.StringIO()):
                    caso.run(resultado)
                self.assertEqual(ejecutadas, [] if solo_seguridad else ['disco'])
                self.assertEqual(len(resultado.skipped), 1)
                self.assertIn('no_implementado', resultado.skipped[0][1])
                self.assertEqual(len(resultado.failures), int(solo_seguridad))
                self.assertFalse(resultado.errors)
