import unittest
from evidencia_local import comprobar, comprobar_respuesta


class EvidenciaContenido(unittest.TestCase):
    def test_codigo_cero_no_es_validacion(self):
        for nombre in ('disco', 'memoria', 'sistema', 'servicios_fallidos',
                       'puertos', 'conexiones', 'cortafuegos', 'vpn', 'interfaces_red'):
            error = ValueError if nombre == 'interfaces_red' else AssertionError
            with self.subTest(herramienta=nombre), self.assertRaises(error):
                comprobar(nombre, 'ESTADO: CORRECTA\nCÓDIGO DE SALIDA: 0\n')

    def test_trafico_inconsistente_rechazado(self):
        texto = ('Intervalo real: 5.00 segundos\n'
                 '  RX: 100 bytes | 999.00 B/s | 0.008 Mbit/s\n'
                 '  TX: 100 bytes | 20.00 B/s | 0.000 Mbit/s')
        with self.assertRaises(AssertionError):
            comprobar('trafico_red', texto)

    def test_salida_truncada_no_se_declara_completa(self):
        with self.assertRaises(AssertionError):
            comprobar('memoria', '[RESULTADO TRUNCADO: faltan datos]')


class RegresionesInterpretacion(unittest.TestCase):
    def test_afirmaciones_observadas_sin_evidencia(self):
        casos = [('memoria', '11 MiB, lo que indica que no hay actividad de swap en este momento.'),
                 ('puertos', 'El puerto 631 (CUPS) está escuchando.'),
                 ('interfaces_red', 'La interfaz Wi-Fi está apagada.'),
                 ('listar_documentos', 'No podemos afirmar nada sobre contenido oculto.')]
        for nombre, texto in casos:
            with self.subTest(herramienta=nombre), self.assertRaises(AssertionError):
                comprobar_respuesta(nombre, texto, 'Datos sin esa evidencia')

    def test_limites_correctamente_explicados(self):
        comprobar_respuesta('memoria', 'Hay 11 MiB de swap ocupada; la lectura no mide actividad.', '')
        comprobar_respuesta('puertos', 'El puerto 631 escucha; servicio no identificado.', '')
