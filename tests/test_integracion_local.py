"""Pruebas optativas: solo consultas locales de lectura; sin servicios externos.

ASISTENTE_PRUEBAS_REALES=1 python3 -B -m unittest discover -s tests -p test_integracion_local.py -v
"""
import contextlib
import io
import json
import os
import unittest
import urllib.request
from unittest.mock import patch

import AsistenteLocal as app
from evidencia_local import comprobar, comprobar_respuesta


@unittest.skipUnless(os.environ.get('ASISTENTE_PRUEBAS_REALES') == '1',
                     'Integración real desactivada; requiere ASISTENTE_PRUEBAS_REALES=1')
class IntegracionLocal(unittest.TestCase):
    def test_herramientas_locales(self):
        ejecutadas = 0
        with patch.object(app, 'ALLOW_EXTERNAL', False):
            self.assertNotIn('diagnostico_vpn', app.herramientas_disponibles())
            for nombre in app.herramientas_disponibles():
                if not self.dependencias_disponibles(nombre):
                    continue
                with self.subTest(herramienta=nombre):
                    resultado = app.ejecutar_consulta(nombre)
                    ejecutadas += 1
                    self.assertIsInstance(resultado, str)
                    self.assertTrue(resultado)
                    self.assertLessEqual(len(resultado), app.MAX_OUTPUT)
                    self.assertNotIn('ESTADO: RECHAZADA', resultado)
                    # Se comprueba el contrato, no se exige que el equipo esté sano
                    # ni que firewalld o systemd permitan todas las consultas.
                    estados = [linea for linea in resultado.splitlines()
                               if linea.startswith(('ESTADO:', 'CÓDIGO DE SALIDA:'))]
                    if not estados:
                        estados = [resultado.splitlines()[0]]
                    print(f"REAL {nombre}: {'; '.join(estados)}", flush=True)
                    print('CONTENIDO ' + nombre + ': ' + comprobar(nombre, resultado, nivel_debian='contrato'), flush=True)

        self.assertGreater(ejecutadas, 0, 'No se ha ejecutado ninguna herramienta')

    def dependencias_disponibles(self, nombre):
        entorno = app.entorno_ejecucion()
        backend = entorno.get('backend_seguridad')
        if nombre in app.HERRAMIENTAS_SEGURIDAD and backend and app.estado_herramienta(nombre, backend) != 'disponible':
            with self.subTest(herramienta=nombre):
                self.skipTest('Backend de seguridad: ' + app.estado_herramienta(nombre, backend))
            return False
        requisitos = entorno['dependencias'][nombre]
        faltantes = [f'{binario}: {dato["estado"]}'
                     for binario, dato in requisitos.items()
                     if dato['estado'] != 'disponible' and not (
                         backend and backend['backend'] == 'debian' and
                         nombre == 'auditoria_seguridad' and binario == 'python:apt_pkg')]
        if faltantes:
            # SkipTest afecta solo a este subtest; el llamador continúa el bucle.
            with self.subTest(herramienta=nombre):
                self.skipTest('Dependencias no disponibles: ' + '; '.join(faltantes))
            return False
        return True

    def test_cobertura_apt_completa(self):
        seleccion = app.seleccionar_backend_seguridad()
        if seleccion['backend'] != 'debian':
            self.skipTest('Cobertura APT específica de Debian 13')
        if not self.dependencias_disponibles('auditoria_seguridad'):
            self.skipTest('Inventario dpkg no disponible para contrastar cobertura APT')
        apt = app.entorno_ejecucion()['dependencias']['auditoria_seguridad']['python:apt_pkg']
        if apt['estado'] != 'disponible':
            self.skipTest('Cobertura APT omitida: python3-apt no disponible; dpkg se valida por separado')
        # Dependencias presentes no equivalen a cobertura. Cualquier fallo APT
        # hace fallar esta prueba estricta; no se convierte en skip ni xfail.
        with patch.object(app,'ALLOW_EXTERNAL',False):
            resultado = app.ejecutar_consulta('auditoria_seguridad')
        print(comprobar('auditoria_seguridad',resultado,nivel_debian='apt_completo'),flush=True)

    def test_modelo_disponible(self):
        url = 'http://127.0.0.1:1234/v1/models'
        with urllib.request.urlopen(url, timeout=10) as respuesta:
            datos = respuesta.read(app.MAX_HTTP_BYTES + 1)
        self.assertLessEqual(len(datos), app.MAX_HTTP_BYTES)
        modelos = json.loads(datos)
        self.assertIn(app.MODEL, [m['id'] for m in modelos['data']])

    def test_modelo_herramientas_y_respuesta_final(self):
        # Una petición por herramienta: el modelo debe ejecutar y usar sus datos.
        originales = app.TOOLS
        ejecutadas = 0
        for nombre, herramienta in originales.items():
            if herramienta.get('external'):
                continue
            if not self.dependencias_disponibles(nombre):
                continue
            with self.subTest(herramienta=nombre):
                original = app.ejecutar_consulta
                resultados = []
                def ejecutar(n, deadline=None):
                    nonlocal ejecutadas
                    dato = original(n, deadline)
                    ejecutadas += 1
                    evidencia = comprobar(n, dato, nivel_debian='contrato')
                    resultados.append((n, evidencia, dato))
                    return dato
                with patch.object(app, 'TOOLS', {nombre: herramienta}), \
                     patch.object(app, 'ALLOW_EXTERNAL', False), \
                     patch.object(app, 'ejecutar_consulta', side_effect=ejecutar), \
                     contextlib.redirect_stdout(io.StringIO()) as salida:
                    app.preguntar(f'Usa {nombre} y resume los datos observados en español '
                                  'en un máximo de tres frases, incluyendo un valor concreto '
                                  'de la salida. Explica una limitación; no deduzcas seguridad, '
                                  'conectividad o fugas sin pruebas. No consultes fuentes externas.')
                self.assertEqual([r[0] for r in resultados], [nombre])
                texto = salida.getvalue()
                self.assertIn('Asistente:', texto)
                self.assertNotIn('El modelo solicitó herramientas tras el límite', texto)
                final = texto.split('Asistente:', 1)[1].strip()
                self.assertGreater(len(final), 20)
                print(json.dumps({'herramienta': nombre, 'contenido': resultados[0][1],
                                  'respuesta_final': final}, ensure_ascii=False), flush=True)
                comprobar_respuesta(nombre, final, resultados[0][2])
                # La coherencia semántica se revisa además sobre estos resúmenes;
                # recibir texto o código cero por sí solo no la demuestra.

        self.assertGreater(ejecutadas, 0, 'No se ha ejecutado ninguna herramienta')


if __name__ == '__main__':
    unittest.main()
