"""Regresiones simuladas: no ejecutan herramientas ni contactan con LM Studio."""
import contextlib
import copy
import io
import json
import unittest
from unittest.mock import patch

import AsistenteLocal as app
import test_integracion_local as integracion
from evidencia_local import comprobar


def informe():
    return dict(herramienta='correlacion_seguridad', detalle_dnf5='correcto',
                inventario_completo=True,
                fuentes_locales={n: {'estado': 'correcta'} for n in
                                 ('uname', 'rpm', 'kernels', 'pendientes', 'instalados')},
                cisa_kev={'estado': 'no_autorizada'}, referencias=['fuente local'],
                alcance='Avisos locales', limitaciones=['Solo caché'],
                resultados=[], total_resultados=0, resultados_omitidos=0)


class ValidadorCorrelacion(unittest.TestCase):
    def test_cero_y_filas_validas(self):
        datos = informe()
        comprobar('correlacion_seguridad', json.dumps(datos))
        datos['resultados'] = [dict(aviso='FEDORA-2026-test', paquete='ejemplo',
            arquitectura='x86_64', instalada_evr='0:1-1.fc44',
            correctiva_nevra='ejemplo-1-2.fc44.x86_64', estado_local='no_determinado',
            cves=[{'id': 'CVE-2026-1234', 'en_kev': None}])]
        datos['total_resultados'] = 1
        comprobar('correlacion_seguridad', json.dumps(datos))
        datos['resultados'][0]['cves'][0]['en_kev'] = False
        with self.assertRaises(AssertionError):
            comprobar('correlacion_seguridad', json.dumps(datos))

    def test_datos_incompletos_no_son_exito(self):
        for campo, valor in [('detalle_dnf5', 'no_disponible_o_formato_invalido'),
                             ('inventario_completo', False), ('total_resultados', 1),
                             ('resultados_omitidos', 1), ('fuentes_locales', {}),
                             ('cisa_kev', {'estado': 'correcta'})]:
            datos = copy.deepcopy(informe())
            datos[campo] = valor
            with self.subTest(campo=campo), self.assertRaises(AssertionError):
                comprobar('correlacion_seguridad', json.dumps(datos))
        with self.assertRaises(ValueError):
            comprobar('correlacion_seguridad', 'no es JSON')


class InfraestructuraIntegracion(unittest.TestCase):
    def simular(self, metodo, faltantes=(), invalida=False, sin_llamada=False):
        herramientas = {n: {'commands': [[n]]} for n in ('primera', 'segunda')}
        dependencias = {n: {n: {'estado': 'ausente' if n in faltantes else 'disponible'}}
                        for n in herramientas}
        ejecutadas = []
        def ejecutar(nombre, *args):
            ejecutadas.append(nombre)
            return 'datos'
        def validar(nombre, resultado, *, nivel_debian):
            self.assertEqual(nivel_debian, 'contrato')
            if invalida and nombre == 'primera':
                raise AssertionError('Contenido inválido')
            return 'evidencia'
        def preguntar(*args):
            if not sin_llamada:
                app.ejecutar_consulta(next(iter(app.TOOLS)))
            print('Asistente: Respuesta simulada suficientemente larga.')
        caso = integracion.IntegracionLocal(metodo)
        resultado = unittest.TestResult()
        with patch.object(integracion.IntegracionLocal, '__unittest_skip__', False), \
             patch.object(app, 'TOOLS', herramientas), \
             patch.object(app, 'entorno_ejecucion', return_value={'dependencias': dependencias}), \
             patch.object(app, 'ejecutar_consulta', side_effect=ejecutar), \
             patch.object(app, 'preguntar', side_effect=preguntar), \
             patch.object(integracion, 'comprobar', side_effect=validar), \
             patch.object(integracion, 'comprobar_respuesta'), \
             patch.object(app.subprocess, 'Popen', side_effect=AssertionError('Proceso real prohibido')), \
             patch.object(app.urllib.request, 'urlopen', side_effect=AssertionError('HTTP real prohibido')), \
             contextlib.redirect_stdout(io.StringIO()):
            caso.run(resultado)
        return resultado, ejecutadas

    def test_dependencia_ausente_no_interrumpe_restantes(self):
        for metodo in ('test_herramientas_locales', 'test_modelo_herramientas_y_respuesta_final'):
            with self.subTest(metodo=metodo):
                resultado, ejecutadas = self.simular(metodo, faltantes=('primera',))
                self.assertEqual(ejecutadas, ['segunda'])
                self.assertEqual(len(resultado.skipped), 1)
                self.assertFalse(resultado.failures or resultado.errors)

    def test_todas_ausentes_no_es_satisfactorio(self):
        for metodo in ('test_herramientas_locales', 'test_modelo_herramientas_y_respuesta_final'):
            with self.subTest(metodo=metodo):
                resultado, ejecutadas = self.simular(metodo, faltantes=('primera', 'segunda'))
                self.assertEqual(ejecutadas, [])
                self.assertEqual(len(resultado.skipped), 2)
                self.assertEqual(len(resultado.failures), 1)
                self.assertFalse(resultado.errors)

    def test_fallo_validacion_no_se_omite_y_continua(self):
        for metodo in ('test_herramientas_locales', 'test_modelo_herramientas_y_respuesta_final'):
            with self.subTest(metodo=metodo):
                resultado, ejecutadas = self.simular(metodo, invalida=True)
                self.assertEqual(ejecutadas, ['primera', 'segunda'])
                self.assertEqual(len(resultado.failures), 1)
                self.assertFalse(resultado.skipped or resultado.errors)

    def test_modelo_sin_ejecutar_herramientas_falla(self):
        resultado, ejecutadas = self.simular('test_modelo_herramientas_y_respuesta_final', sin_llamada=True)
        self.assertEqual(ejecutadas, [])
        self.assertTrue(resultado.failures)
        self.assertFalse(resultado.skipped or resultado.errors)
