"""Autonomía operativa con barreras de procesos, red y administración reales."""
import contextlib
import io
import unittest
from unittest.mock import Mock, patch

import AsistenteLocal as app
import operaciones_locales as locales
from motor_consultas import Plan, planificar, ContextoFactual
from memoria import normalizar_memoria
from servicios import normalizar_servicios


class Clasificacion(unittest.TestCase):
    def test_operaciones(self):
        for texto, nombres in (
            ('Comprueba la memoria', ('memoria',)),
            ('Revisa RAM y disco', ('memoria', 'disco')),
            ('Consulta interfaces de red', ('interfaces_red',)),
            ('Verifica la VPN local', ('vpn',)),
            ('Lista servicios fallidos', ('servicios_fallidos',)),
            ('Comprueba servicios fallidos', ('servicios_fallidos',)),
            ('Comprueba mi IP pública', ('ip_publica',)),
        ):
            with self.subTest(texto=texto):
                self.assertEqual(planificar(texto).nombres, nombres)

    def test_conceptuales(self):
        for texto in ('Qué es la memoria swap', 'Cómo funciona una VPN', 'Qué son interfaces de red', 'Cómo puedo comprobar la memoria', 'Cómo verificar VPN', 'Explícame cómo se puede comprobar memoria', 'Qué herramientas permiten comprobar disco', 'Es posible comprobar memoria'):
            self.assertEqual(planificar(texto).tipo, 'conceptual')

    def test_ambiguas_sin_adquisicion(self):
        for texto in ('Mi VPN va mal', 'Comprueba servicios',
                      'Comprueba recursos y amplía el diagnóstico si procede',
                      'Comprueba memoria o disco', 'Si falla la VPN comprueba memoria',
                      'Actualiza el sistema', 'Reinicia servicios',
                      'Comprueba conexiones de la VPN', 'Comprueba memoria disco', 'Comprueba memoria y ejecuta id', 'Comprueba memoria con sudo',
                      'Comprueba memoria usando comando id', 'Reutiliza la memoria anterior', 'Comprueba memoria y actualizaciones',
                      'No compruebes memoria y disco'):
            with self.subTest(texto=texto):
                p = planificar(texto)
                self.assertFalse(p.nombres)
                self.assertEqual(p.tipo, 'ambigua')

    def test_exclusiones_y_mixtas(self):
        for texto, nombres in (
            ('Comprueba memoria, sin consultar la VPN', ('memoria',)),
            ('Comprueba memoria y no consultes disco', ('memoria',)),
            ('No consultes VPN y comprueba memoria', ('memoria',)),
            ('Qué es la RAM y comprueba disco', ('disco',)),
            ('Comprueba disco y explica qué es swap', ('disco',)),
            ('Comprueba memoria y memoria', ('memoria',)),
        ):
            with self.subTest(texto=texto):
                self.assertEqual(planificar(texto).nombres, nombres)
        self.assertFalse(planificar('No compruebes memoria').nombres)


class Coordinador(unittest.TestCase):
    def ejecutar(self, nombres=('memoria',), **opciones):
        self.adquirir = Mock(return_value=('Informe validado', 'completo'))
        parametros = dict(catalogo=app.TOOLS, adquirir=self.adquirir,
                          comprobar=lambda fin: 10, sondear=lambda n, c: 'disponible')
        parametros.update(opciones)
        return locales.ejecutar_plan(Plan(nombres, local=True), 10, **parametros)

    def test_separacion_y_unica_adquisicion(self):
        r = self.ejecutar(('memoria', 'memoria'))
        self.adquirir.assert_called_once()
        self.assertEqual(len(r), 1)
        self.assertEqual((r[0]['capacidad'], r[0]['autorizacion'], r[0]['ejecucion'], r[0]['verificacion']),
                         ('disponible', 'permitida_lectura_local', 'finalizada', 'completo'))

    def test_bloqueadas_desconocidas_y_ausencia(self):
        for nombres, opciones in ((('ip_publica', 'diagnostico_vpn', 'terminal'), {}),
                                   (('memoria',), {'sondear': lambda n, c: 'no_disponible'})):
            r = self.ejecutar(nombres, **opciones)
            self.adquirir.assert_not_called()
            self.assertTrue(all(x['ejecucion'] == 'no_iniciada' for x in r))
            self.assertTrue(all(x['autorizacion'] == 'denegada' for x in r))

    def test_presupuestos(self):
        for opciones in ({'llamadas': 0}, {'total': 0}, {'limite': 100}):
            r = self.ejecutar(**opciones)
            self.adquirir.assert_not_called()
            self.assertEqual(r[0]['motivo'], 'presupuesto_agotado')

    def test_plazo_antes_y_despues(self):
        comprobar = Mock(side_effect=TimeoutError('PRIVADO'))
        r = self.ejecutar(comprobar=comprobar)
        self.adquirir.assert_not_called()
        self.assertEqual(r[0]['ejecucion'], 'no_iniciada')
        comprobar = Mock(side_effect=[10, TimeoutError('PRIVADO')])
        r = self.ejecutar(comprobar=comprobar)
        self.adquirir.assert_called_once()
        self.assertEqual(r[0]['ejecucion'], 'tiempo_agotado')
        self.assertNotIn('Informe validado', str(r))
        self.assertNotIn('PRIVADO', str(r))

    def test_errores_y_continuacion_parcial(self):
        adquirir = Mock(side_effect=[PermissionError('PRIVADO'), ('parcial', 'parcial')])
        r = self.ejecutar(('memoria', 'disco'), adquirir=adquirir)
        self.assertEqual(adquirir.call_count, 2)
        self.assertEqual([x['verificacion'] for x in r], ['no_verificable', 'parcial'])
        self.assertNotIn('PRIVADO', str(r))

    def test_cancelacion_no_continua(self):
        adquirir = Mock(side_effect=KeyboardInterrupt())
        r = self.ejecutar(('memoria', 'disco'), adquirir=adquirir)
        adquirir.assert_called_once()
        self.assertEqual(r[0]['ejecucion'], 'cancelada')

    def test_contrato_invalido_y_excesivo(self):
        for valor in (('x', 'inventado'), ('x' * 19000, 'completo'), (None, 'completo')):
            r = self.ejecutar(adquirir=Mock(return_value=valor))
            self.assertEqual(r[0]['verificacion'], 'no_verificable')
            self.assertEqual(r[0]['ejecucion'], 'fallida')

    def test_capacidad_parcial_interfaces(self):
        with patch.object(locales.shutil, 'which', side_effect=[None, '/nmcli']):
            self.assertEqual(locales.capacidad('interfaces_red', app.TOOLS), 'disponible')
        with patch.object(locales.shutil, 'which', return_value=None):
            self.assertEqual(locales.capacidad('vpn', app.TOOLS), 'no_disponible')


class Integracion(unittest.TestCase):
    def setUp(self):
        self.pila = contextlib.ExitStack()
        self.addCleanup(self.pila.close)
        self.salida = self.pila.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.pila.enter_context(patch.object(app.subprocess, 'Popen', side_effect=AssertionError('Proceso real')))
        self.pila.enter_context(patch.object(app, 'abrir_http_local', side_effect=AssertionError('HTTP real')))
        self.pila.enter_context(patch.object(app.urllib.request, 'urlopen', side_effect=AssertionError('Red real')))
        self.modelo = self.pila.enter_context(patch.object(app, 'consultar_modelo', side_effect=AssertionError('Modelo no necesario')))
        self.pila.enter_context(patch.object(locales.shutil, 'which', return_value='/doble'))

    def test_memoria_no_depende_de_respuesta_del_modelo(self):
        fuente = dict(estado='correcta', codigo=0, stdout='MemTotal: 100 kB\nMemAvailable: 40 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n', avisos=False)
        with patch.object(app, 'consultar_memoria_verificada', return_value=normalizar_memoria(fuente)) as adquirir:
            r = app.preguntar('Comprueba memoria')
        adquirir.assert_called_once()
        self.modelo.assert_not_called()
        self.assertEqual(r[0]['verificacion'], 'completo')
        self.assertIn('102400 B', self.salida.getvalue())
        self.assertNotIn('Modelo |', self.salida.getvalue())

    def test_ambigua_negada_y_administrativa(self):
        with patch.object(app, 'ejecutar_comando') as ejecutar:
            for texto in ('Mi VPN va mal', 'No compruebes memoria', 'Actualiza el sistema'):
                app.preguntar(texto)
        ejecutar.assert_not_called()
        self.modelo.assert_not_called()
        self.assertIn('Comprobación no realizada', self.salida.getvalue())

    def test_externa_bloqueada_incluso_flag_heredado(self):
        with patch.object(app, 'ALLOW_EXTERNAL', True), patch.object(app, 'ejecutar_comando') as ejecutar:
            r = app.preguntar('Comprueba mi IP pública')
        ejecutar.assert_not_called()
        self.modelo.assert_not_called()
        self.assertEqual(r[0]['autorizacion'], 'denegada')
        self.assertIn('no requiere privilegios', self.salida.getvalue())

    def test_conceptual_rechaza_herramientas_del_modelo(self):
        self.modelo.side_effect = None
        self.modelo.return_value = {'choices': [{'message': {'role': 'assistant', 'content': 'He comprobado todo con sudo',
            'tool_calls': [{'id': 'x', 'type': 'function', 'function': {'name': 'memoria', 'arguments': '{}'}}]}}]}
        with patch.object(app, 'ejecutar_comando') as ejecutar:
            app.preguntar('Qué es la memoria')
        ejecutar.assert_not_called()
        self.assertFalse(self.modelo.call_args.kwargs['permitir_herramientas'])
        self.assertTrue(self.modelo.call_args.kwargs['omitir_tools'])
        self.assertNotIn('He comprobado', self.salida.getvalue())

    def test_servicios_sin_descripciones_errores_ni_historial(self):
        resultado = normalizar_servicios(dict(estado='correcta', codigo=0, stdout='demo.service loaded failed failed PRIVADO\n'))
        contexto = ContextoFactual()
        coleccion = Mock()
        with patch.object(app, 'consultar_servicios_verificados', return_value=resultado):
            app.preguntar('Comprueba servicios fallidos', coleccion=coleccion, contexto=contexto)
        self.assertNotIn('PRIVADO', self.salida.getvalue())
        self.assertIn('demo.service', self.salida.getvalue())
        self.assertEqual(contexto.consultar(), {})
        self.assertFalse(coleccion.mock_calls)

    def test_vpn_solo_comando_fijo_y_privacidad(self):
        with patch.object(app, 'ejecutar_comando', return_value=(0, 'PRIVADO:wireguard:connected:SECRETO\n', '', False)) as ejecutar:
            r = app.preguntar('Comprueba VPN local')
        self.assertEqual(ejecutar.call_args.args[0], app.TOOLS['interfaces_red']['commands'][1])
        self.assertLessEqual(ejecutar.call_args.args[1], 15)
        self.assertNotIn('PRIVADO', str(r))
        self.assertNotIn('SECRETO', self.salida.getvalue())
        self.assertIn('connected', self.salida.getvalue())
        self.assertEqual(r[0]['verificacion'], 'parcial')

    def test_vpn_error_no_interpreta_prefijo(self):
        with patch.object(app, 'ejecutar_comando', return_value=(1, 'tun0:wireguard:connected:PRIVADO\n', 'SECRETO', False)):
            r = app.preguntar('Comprueba VPN')
        self.assertEqual(r[0]['verificacion'], 'error')
        self.assertNotIn('connected', self.salida.getvalue())
        self.assertNotIn('SECRETO', str(r))

    def test_disco_reutiliza_adquisicion_sin_salida_bruta(self):
        datos = dict(montajes=[dict(ruta='/', disponible_bytes=10, total_bytes=20)], fuente='correcta', integridad='no_comprobada')
        with patch.object(locales, 'consultar_disco', return_value=(datos, 'completo')) as adquirir:
            app.preguntar('Comprueba disco')
        adquirir.assert_called_once()
        self.assertIn('disponibles=10 B', self.salida.getvalue())

    def test_interfaces_reutiliza_parser_y_conserva_parcial(self):
        with patch.object(app, 'ejecutar_comando', side_effect=[
                FileNotFoundError('PRIVADO'), (0, 'eth0:ethernet:connected:SECRETO\n', '', False)]) as ejecutar:
            r = app.preguntar('Comprueba interfaces')
        self.assertEqual(ejecutar.call_count, 2)
        self.assertEqual([c.args[0] for c in ejecutar.call_args_list], app.TOOLS['interfaces_red']['commands'])
        self.assertEqual(r[0]['verificacion'], 'parcial')
        self.assertNotIn('PRIVADO', str(r))
        self.assertNotIn('SECRETO', self.salida.getvalue())

    def test_modelo_incorrecto_no_interviene_en_lectura_operativa(self):
        self.modelo.side_effect = None
        self.modelo.return_value = {'choices': [{'message': {'role': 'assistant',
            'content': 'He comprobado todo: usa sudo y todos los valores son cero.'}}]}
        with patch.object(app, 'consultar_servicios_verificados', return_value=normalizar_servicios(
                dict(estado='correcta', codigo=0, stdout=''))):
            app.preguntar('Comprueba servicios fallidos')
        self.modelo.assert_not_called()
        self.assertNotIn('usa sudo', self.salida.getvalue())
        self.assertIn('Servicios fallidos observados: 0', self.salida.getvalue())

    def test_plazo_antes_de_publicar_descarta_informe(self):
        r = dict(operacion='memoria', capacidad='disponible', autorizacion='permitida_lectura_local',
                 ejecucion='finalizada', verificacion='completo', motivo='resultado_de_adquisicion', informe='DATO_TARDIO')
        with patch.object(locales, 'ejecutar_plan', return_value=[r]), \
             patch.object(app, 'restante', side_effect=TimeoutError()):
            resultado = app.preguntar('Comprueba memoria')
        self.assertNotIn('DATO_TARDIO', self.salida.getvalue())
        self.assertNotIn('DATO_TARDIO', str(resultado))
        self.assertEqual(resultado[0]['verificacion'], 'no_verificable')

    def test_otras_herramientas_conservan_acceso_explicito_sin_modelo(self):
        for nombre in ('sistema', 'puertos', 'conexiones', 'cortafuegos', 'trafico_red', 'listar_documentos'):
            with self.subTest(nombre=nombre), patch.object(app, 'ejecutar_consulta', return_value='DATO') as ejecutar:
                r = app.preguntar(nombre)
            ejecutar.assert_called_once()
            self.assertEqual(ejecutar.call_args.args[0], nombre)
            self.assertEqual(r[0]['verificacion'], 'no_verificable')
        self.modelo.assert_not_called()

    def test_errores_del_lector_sin_sudo_ni_datos_originales(self):
        for error in (PermissionError('PRIVADO'), FileNotFoundError('PRIVADO'), TimeoutError('PRIVADO')):
            with self.subTest(error=type(error)), patch.object(app, 'ejecutar_comando', side_effect=error) as ejecutar:
                r = app.preguntar('Comprueba memoria')
            ejecutar.assert_called_once()
            self.assertEqual(r[0]['verificacion'], 'error')
            self.assertNotIn('PRIVADO', str(r))
            self.assertNotIn('sudo', str(ejecutar.call_args))

    def test_disco_comando_y_rutas_fijos_sin_datos_originales(self):
        from types import SimpleNamespace
        with patch.object(app, 'ejecutar_comando', return_value=(0, 'PRIVADO', '', False)) as ejecutar, \
             patch('autonomia_herramientas.os.stat', return_value=SimpleNamespace(st_dev=1)) as stat, \
             patch('autonomia_herramientas.os.statvfs', return_value=SimpleNamespace(f_bavail=2, f_frsize=1024, f_blocks=4)):
            r = app.preguntar('Comprueba disco')
        ejecutar.assert_called_once()
        self.assertEqual(ejecutar.call_args.args[0], ['df', '-h'])
        self.assertEqual([c.args[0] for c in stat.call_args_list], ['/', '/usr', '/var', '/tmp'])
        self.assertIn('disponibles=2048 B', r[0]['informe'])
        self.assertNotIn('PRIVADO', str(r))

    def test_limite_global_no_inicia(self):
        with patch.object(app, 'MAX_TOTAL_OUTPUT', 0), patch.object(app, 'consultar_memoria_verificada') as adquirir:
            r = app.preguntar('Comprueba memoria')
        adquirir.assert_not_called()
        self.assertEqual(r[0]['motivo'], 'presupuesto_agotado')


if __name__ == '__main__':
    unittest.main()
