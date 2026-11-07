import contextlib
import io
import sys
import unittest
from unittest.mock import Mock, patch

import AsistenteLocal as app
import control_verificado as control
from interfaces_red import ResultadoInterfaces
from test_interfaces_red import datos
from test_memoria_verificada import normalizar as datos_memoria


class CodigosVerificados(unittest.TestCase):
    def test_constantes_y_estados_actuales(self):
        self.assertEqual((control.EXITO, control.FALLO, control.USO_INVALIDO,
                          control.PARCIAL, control.INTERRUMPIDO), (0, 1, 2, 3, 130))
        self.assertEqual([control.codigo_salida(s) for s in
                          ('completo', 'parcial', 'omitido_por_limite', 'error')], [0, 3, 3, 1])
        with self.assertRaises(KeyError):
            control.codigo_salida('nuevo')

    def test_argparse_conserva_codigo_de_uso_sin_acciones(self):
        with patch.object(sys, 'argv', ['AsistenteLocal.py', '--interfaces-verificadas', '--memoria-verificada']), \
             patch.object(app, 'ejecutar_interfaces_verificadas') as interfaces, \
             patch.object(app, 'ejecutar_memoria_verificada') as memoria, \
             contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            app.main()
        self.assertEqual(error.exception.code, control.USO_INVALIDO)
        interfaces.assert_not_called()
        memoria.assert_not_called()


class PlazosCompartidos(unittest.TestCase):
    def setUp(self):
        # Una regresión que intente usar red o comandos reales falla la prueba.
        self.modelo = self.enterContext(patch.object(app, 'consultar_modelo', side_effect=AssertionError('No modelo')))
        self.http = self.enterContext(patch.object(app, 'abrir_http_local', side_effect=AssertionError('No HTTP')))
        self.comandos = self.enterContext(patch.object(app, 'ejecutar_comando', side_effect=AssertionError('No comandos reales')))

    def tearDown(self):
        self.modelo.assert_not_called()
        self.http.assert_not_called()
        self.comandos.assert_not_called()

    def casos(self):
        return (
            ('interfaces', app.ejecutar_interfaces_verificadas, 'ejecutar_consulta', 'informe_verificado',
             ResultadoInterfaces(datos(), app.MAX_OUTPUT)),
            ('memoria', app.ejecutar_memoria_verificada, 'consultar_memoria_verificada', 'informe_memoria',
             datos_memoria()),
        )

    def test_estados_se_traducen_igual_sin_homogeneizar_resultados(self):
        for nombre, ejecutar, adquirir, presentar, resultado in self.casos():
            for estado, codigo in (('completo', 0), ('parcial', 3), ('error', 1), ('omitido_por_limite', 3)):
                with self.subTest(modo=nombre, estado=estado), \
                     patch.object(app, adquirir, return_value=resultado) as fuente, \
                     patch.object(app, presentar, return_value=('INFORME SIMULADO', estado)) as informe, \
                     contextlib.redirect_stdout(io.StringIO()) as salida:
                    self.assertEqual(ejecutar(), codigo)
                fuente.assert_called_once()
                informe.assert_called_once_with(resultado.datos if nombre == 'interfaces' else resultado,
                                                limite=app.MAX_OUTPUT)
                self.assertEqual(salida.getvalue(), 'INFORME SIMULADO\n')

    def test_vencimiento_antes_de_adquirir_no_inicia_acciones(self):
        for nombre, ejecutar, adquirir, presentar, _ in self.casos():
            with self.subTest(modo=nombre), patch.object(app, 'MAX_SECONDS', 0), \
                 patch.object(app.time, 'monotonic', return_value=100), \
                 patch.object(app, adquirir) as fuente, patch.object(app, presentar) as informe, \
                 contextlib.redirect_stdout(io.StringIO()) as salida:
                self.assertEqual(ejecutar(), 1)
            fuente.assert_not_called()
            informe.assert_not_called()
            self.assertIn('tiempo agotado', salida.getvalue())

    def test_vencimiento_tras_adquirir_no_presenta_ni_publica_informe(self):
        for nombre, ejecutar, adquirir, presentar, resultado in self.casos():
            reloj = [100.0]
            def adquirir_tarde(*args):
                reloj[0] = 220
                return resultado
            with self.subTest(modo=nombre), \
                 patch.object(app.time, 'monotonic', side_effect=lambda: reloj[0]), \
                 patch.object(app, adquirir, side_effect=adquirir_tarde) as fuente, \
                 patch.object(app, presentar) as informe, contextlib.redirect_stdout(io.StringIO()) as salida:
                self.assertEqual(ejecutar(), 1)
            fuente.assert_called_once()
            informe.assert_not_called()
            self.assertIn('tiempo agotado', salida.getvalue())
            self.assertNotIn('Informe determinista', salida.getvalue())

    def test_vencimiento_antes_de_publicar_no_muestra_datos_tardios(self):
        for nombre, ejecutar, adquirir, presentar, resultado in self.casos():
            reloj = [100.0]
            def presentar_tarde(*args, **kwargs):
                reloj[0] = 220
                return 'DATOS_TARDIOS', 'completo'
            with self.subTest(modo=nombre), \
                 patch.object(app.time, 'monotonic', side_effect=lambda: reloj[0]), \
                 patch.object(app, adquirir, return_value=resultado) as fuente, \
                 patch.object(app, presentar, side_effect=presentar_tarde) as informe, \
                 contextlib.redirect_stdout(io.StringIO()) as salida:
                self.assertEqual(ejecutar(), 1)
            fuente.assert_called_once()
            informe.assert_called_once()
            self.assertNotIn('DATOS_TARDIOS', salida.getvalue())
            self.assertIn('tiempo agotado', salida.getvalue())

    def test_mismo_deadline_en_los_tres_puntos_sin_renovacion(self):
        for nombre, ejecutar, adquirir, presentar, resultado in self.casos():
            reloj = [100.0]
            comprobaciones = []
            restante = app.restante
            def comprobar(deadline):
                comprobaciones.append(deadline)
                return restante(deadline)
            def adquirir_datos(*args):
                reloj[0] = 140
                return resultado
            def presentar_datos(*args, **kwargs):
                reloj[0] = 219
                return 'INFORME', 'completo'
            with self.subTest(modo=nombre), \
                 patch.object(app.time, 'monotonic', side_effect=lambda: reloj[0]), \
                 patch.object(app, 'restante', side_effect=comprobar), \
                 patch.object(app, adquirir, side_effect=adquirir_datos) as fuente, \
                 patch.object(app, presentar, side_effect=presentar_datos), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(ejecutar(), 0)
            self.assertEqual(comprobaciones, [220, 220, 220])
            self.assertEqual(fuente.call_args.args[-1], 220)

    def test_interrupcion_adquisicion_o_presentacion_130_sin_reintentos(self):
        for nombre, ejecutar, adquirir, presentar, resultado in self.casos():
            for fase in ('adquirir', 'presentar'):
                with self.subTest(modo=nombre, fase=fase), \
                     patch.object(app, adquirir, side_effect=KeyboardInterrupt() if fase == 'adquirir' else None,
                                  return_value=resultado) as fuente, \
                     patch.object(app, presentar, side_effect=KeyboardInterrupt()) as informe, \
                     contextlib.redirect_stdout(io.StringIO()) as salida, \
                     contextlib.redirect_stderr(io.StringIO()) as errores:
                    self.assertEqual(ejecutar(), 130)
                fuente.assert_called_once()
                self.assertEqual(informe.call_count, 0 if fase == 'adquirir' else 1)
                self.assertIn('interrumpida', errores.getvalue())
                self.assertEqual(salida.getvalue(), '')

    def test_errores_controlados_1_sin_publicar_texto_de_excepcion(self):
        for nombre, ejecutar, adquirir, _, _ in self.casos():
            for error in (TimeoutError('SECRETO'), OSError('SECRETO'), ValueError('SECRETO'),
                          TypeError('SECRETO'), KeyError('SECRETO')):
                with self.subTest(modo=nombre, error=type(error).__name__), \
                     patch.object(app, adquirir, side_effect=error) as fuente, \
                     contextlib.redirect_stdout(io.StringIO()) as salida:
                    self.assertEqual(ejecutar(), 1)
                fuente.assert_called_once()
                self.assertNotIn('SECRETO', salida.getvalue())

    def test_estado_desconocido_no_publica_texto_antes_de_fallar(self):
        for nombre, ejecutar, adquirir, presentar, resultado in self.casos():
            with self.subTest(modo=nombre), patch.object(app, adquirir, return_value=resultado), \
                 patch.object(app, presentar, return_value=('NO_PUBLICAR', 'estado_desconocido')), \
                 contextlib.redirect_stdout(io.StringIO()) as salida:
                self.assertEqual(ejecutar(), 1)
            self.assertNotIn('NO_PUBLICAR', salida.getvalue())
