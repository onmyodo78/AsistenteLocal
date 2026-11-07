import contextlib
import copy
import io
import json
import sys
import unittest
from unittest.mock import patch

import AsistenteLocal as app
from interfaces_red import ResultadoInterfaces, informe_verificado
from test_interfaces_red import IP, NM, datos, fuente


class PresentacionVerificada(unittest.TestCase):
    def test_informe_reutiliza_hechos_sin_reinterpretar(self):
        texto, estado = informe_verificado(datos())
        self.assertEqual(estado, 'completo')
        self.assertIn('administrativo=UP; operativo="DOWN"; NetworkManager="disconnected"', texto)
        self.assertIn('Radio: desconocida. Conectividad: no comprobada.', texto)
        self.assertIn('Clasificación física/virtual: no determinada.', texto)
        self.assertIn('bytes=12000', texto)
        self.assertIn('packets=80', texto)
        self.assertNotIn('apagada', texto)
        self.assertNotIn('interfaces físicas', texto)
        self.assertNotIn('conectividad confirmada', texto)
        self.assertNotIn('"contadores":', texto)

    def test_contadores_desconocidos_no_son_ceros(self):
        desconocidos = datos('[{"ifname":"x"}]', 'x:ethernet:unavailable:')
        texto, estado = informe_verificado(desconocidos)
        self.assertEqual(estado, 'parcial')
        self.assertIn('bytes=desconocido', texto)
        self.assertNotIn('bytes=0', texto)
        self.assertIn('administrativo=desconocido', texto)

    def test_cero_medido_conservado(self):
        texto, _ = informe_verificado(datos())
        self.assertIn('bytes=0', texto)

    def test_parcial_explicito_y_sin_falsa_causa(self):
        from interfaces_red import normalizar
        d = normalizar({'ip': fuente(IP), 'nmcli': fuente('', 'permiso_denegado')})
        texto, estado = informe_verificado(d)
        self.assertEqual(estado, 'parcial')
        self.assertIn('resultado parcial', texto)
        self.assertIn('nmcli=permiso_denegado', texto)
        self.assertIn('no deducir ausencia', texto)
        self.assertIn('NetworkManager=desconocido', texto)

    def test_omision_de_datos_no_parece_exito(self):
        reducido = ResultadoInterfaces(datos(), app.MAX_OUTPUT).ajustar(app.MIN_JSON)
        texto, estado = informe_verificado(reducido.datos)
        self.assertEqual(estado, 'omitido_por_limite')
        self.assertIn('no es un listado vacío', texto)

    def test_presupuesto_de_presentacion_sin_recorte_enganoso(self):
        texto, estado = informe_verificado(datos(), limite=100)
        self.assertEqual(estado, 'omitido_por_limite')
        self.assertLessEqual(len(texto), 100)
        self.assertIn('no permite afirmar ausencia', texto)
        with self.assertRaises(ValueError):
            informe_verificado(datos(), limite=0)

    def test_estado_desconocido_rechazado(self):
        d = datos()
        d['estado'] = 'nuevo'
        with self.assertRaises(ValueError):
            informe_verificado(d)

    def test_fuentes_fallidas_no_publican_cantidad_cero(self):
        from interfaces_red import normalizar
        d = normalizar({'ip': fuente('', 'tiempo_agotado'), 'nmcli': fuente('', 'error_comando')})
        texto, estado = informe_verificado(d)
        self.assertEqual(estado, 'error')
        self.assertIn('cantidad de interfaces desconocida', texto)
        self.assertNotIn('Registros observados entre fuentes: 0', texto)

    def test_datos_no_se_mutan(self):
        d = datos()
        original = copy.deepcopy(d)
        informe_verificado(d)
        self.assertEqual(d, original)

    def test_vista_breve_limita_registros_y_escapa_controles(self):
        d = datos()
        d['interfaces'][0]['nombre'] = 'nombre\x1b\n\u202e'
        d['interfaces'] *= 4
        texto, estado = informe_verificado(d)
        self.assertEqual(estado, 'parcial')
        self.assertIn('Presentación parcial', texto)
        self.assertIn('se muestran seis', texto)
        self.assertNotIn('\x1b', texto)
        self.assertNotIn('\u202e', texto)
        self.assertIn('\\n', texto)
        self.assertLessEqual(len(texto), app.MAX_OUTPUT)


class ModalidadVerificada(unittest.TestCase):
    def main_con_resultado(self, d):
        with patch.object(sys, 'argv', ['AsistenteLocal.py', '--interfaces-verificadas']), \
             patch.object(app, 'ejecutar_consulta', return_value=ResultadoInterfaces(d, app.MAX_OUTPUT)) as consulta, \
             patch.object(app, 'consultar_modelo', side_effect=AssertionError('No autorizado')) as modelo, \
             patch.object(app, 'abrir_http_local', side_effect=AssertionError('No HTTP')) as http, \
             patch('builtins.input', side_effect=AssertionError('No interacción')) as entrada, \
             contextlib.redirect_stdout(io.StringIO()) as salida:
            codigo = app.main()
        consulta.assert_called_once()
        self.assertEqual(consulta.call_args.args[0], 'interfaces_red')
        self.assertLessEqual(consulta.call_args.args[1] - app.time.monotonic(), app.MAX_SECONDS)
        modelo.assert_not_called()
        http.assert_not_called()
        entrada.assert_not_called()
        return codigo, salida.getvalue()

    def test_exito_cero_y_sin_modelo(self):
        codigo, texto = self.main_con_resultado(datos())
        self.assertEqual(codigo, 0)
        self.assertIn('Informe determinista de interfaces', texto)
        self.assertNotIn('Interpretación del modelo', texto)
        self.assertNotIn('Asistente:', texto)
        self.assertNotIn('Escribe', texto)

    def test_parcial_tres(self):
        codigo, texto = self.main_con_resultado(datos('[{"ifname":"x"}]', ''))
        self.assertEqual(codigo, 3)
        self.assertIn('resultado parcial', texto)

    def test_fallo_uno(self):
        from interfaces_red import normalizar
        d = normalizar({'ip': fuente('', 'ejecutable_o_interprete_ausente'),
                        'nmcli': fuente('', 'permiso_denegado')})
        codigo, texto = self.main_con_resultado(d)
        self.assertEqual(codigo, 1)
        self.assertIn('resultado error', texto)

    def test_omision_tres(self):
        d = ResultadoInterfaces(datos(), app.MAX_OUTPUT).ajustar(app.MIN_JSON).datos
        codigo, texto = self.main_con_resultado(d)
        self.assertEqual(codigo, 3)
        self.assertIn('datos omitidos', texto)

    def test_errores_de_adquisicion_no_publican_excepciones(self):
        for error in (TimeoutError('PRIVADO'), OSError('PRIVADO'), ValueError('PRIVADO')):
            with self.subTest(error=type(error).__name__), \
                 patch.object(app, 'ejecutar_consulta', side_effect=error) as consulta, \
                 patch.object(app, 'consultar_modelo') as modelo, contextlib.redirect_stdout(io.StringIO()) as salida:
                self.assertEqual(app.ejecutar_interfaces_verificadas(), 1)
                self.assertNotIn('PRIVADO', salida.getvalue())
                self.assertIn('no se confirma', salida.getvalue())
                consulta.assert_called_once()
                modelo.assert_not_called()

    def test_resultado_no_estructurado_no_se_publica(self):
        with patch.object(app, 'ejecutar_consulta', return_value='La Wi-Fi está apagada'), \
             contextlib.redirect_stdout(io.StringIO()) as salida:
            self.assertEqual(app.ejecutar_interfaces_verificadas(), 1)
        self.assertNotIn('apagada', salida.getvalue())

    def test_interrupcion_130(self):
        with patch.object(app, 'ejecutar_consulta', side_effect=KeyboardInterrupt()), \
             contextlib.redirect_stderr(io.StringIO()) as salida:
            self.assertEqual(app.ejecutar_interfaces_verificadas(), 130)
        self.assertIn('interrumpida', salida.getvalue())

    def test_flag_externo_incompatible_no_ejecuta_nada(self):
        with patch.object(sys, 'argv', ['AsistenteLocal.py', '--interfaces-verificadas', '--permitir-consultas-externas']), \
             patch.object(app, 'ejecutar_consulta') as consulta, patch.object(app, 'consultar_modelo') as modelo, \
             contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            app.main()
        self.assertEqual(error.exception.code, 2)
        consulta.assert_not_called()
        modelo.assert_not_called()

    def test_sin_flag_conserva_conversacion(self):
        with patch.object(sys, 'argv', ['AsistenteLocal.py']), \
             patch('builtins.input', side_effect=['interfaces_red', 'salir']), \
             patch.object(app, 'preguntar') as preguntar, \
             patch.object(app, 'ejecutar_interfaces_verificadas') as verificada, \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertIsNone(app.main())
        preguntar.assert_called_once_with('interfaces_red')
        verificada.assert_not_called()

    def test_ruta_completa_con_adquisicion_simulada_solo_dos_comandos(self):
        with patch.object(sys, 'argv', ['AsistenteLocal.py', '--interfaces-verificadas']), \
             patch.object(app, 'ejecutar_comando', side_effect=[(0, IP, '', False), (0, NM, '', False)]) as comando, \
             patch.object(app, 'abrir_http_local', side_effect=AssertionError('No HTTP')) as http, \
             patch.object(app, 'consultar_modelo', return_value={'content': 'Wi-Fi apagada'}) as modelo, \
             contextlib.redirect_stdout(io.StringIO()) as salida:
            self.assertEqual(app.main(), 0)
        self.assertEqual([c.args[0] for c in comando.call_args_list], app.TOOLS['interfaces_red']['commands'])
        self.assertTrue(all(0 < c.args[1] <= 15 for c in comando.call_args_list))
        self.assertNotIn('apagada', salida.getvalue())
        self.assertIn('bytes=12000', salida.getvalue())
        http.assert_not_called()
        modelo.assert_not_called()

    def test_fallo_parcial_en_ruta_completa(self):
        with patch.object(app, 'ejecutar_comando', side_effect=[(0, IP, '', False), PermissionError()]) as comando, \
             patch.object(app, 'consultar_modelo') as modelo, contextlib.redirect_stdout(io.StringIO()) as salida:
            self.assertEqual(app.ejecutar_interfaces_verificadas(), 3)
        self.assertEqual(comando.call_count, 2)
        self.assertIn('nmcli=permiso_denegado', salida.getvalue())
        self.assertIn('bytes=12000', salida.getvalue())
        modelo.assert_not_called()
