"""Diagnósticos simulados; toda adquisición de systemd está sustituida por mocks."""
import contextlib
import copy
import errno
import io
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

import AsistenteLocal as app
import servicios
from resultado_verificado import ResultadoVerificado

TEXTO = (Path(__file__).parent / 'fixtures/servicios_fallidos.txt').read_text()


def fuente(texto=TEXTO, estado='correcta', codigo=0):
    return {'estado': estado, 'codigo': codigo, 'stdout': texto}


def resultado(texto=TEXTO, **kw):
    return servicios.normalizar_servicios(fuente(texto, **kw))


class ParserServicios(unittest.TestCase):
    def test_fixture_nombres_instancias_escapes_y_estados(self):
        unidades = servicios.parsear_servicios(TEXTO)
        self.assertEqual([u['nombre'] for u in unidades],
                         [r'ruta\x2dprueba.service', 'trabajo@instancia.service', 'zeta.service'])
        self.assertEqual(unidades[0]['LoadState'], 'not-found')
        self.assertTrue(all(u['ActiveState'] == 'failed' for u in unidades))
        self.assertTrue(all(set(u) == {'nombre', 'LoadState', 'ActiveState', 'SubState'} for u in unidades))
        self.assertNotIn('DESCRIPCION_PRIVADA', str(unidades))
        self.assertNotIn('/home/', str(unidades))

    def test_vacio_valido(self):
        for texto in ('', '\n\t\n '):
            self.assertEqual(servicios.parsear_servicios(texto), [])

    def test_orden_determinista(self):
        self.assertEqual(servicios.parsear_servicios(TEXTO),
                         servicios.parsear_servicios('\n'.join(reversed(TEXTO.splitlines()))))

    def test_cargas_admitidas_y_subestado_nuevo_seguro(self):
        for carga in servicios.ESTADOS_CARGA:
            u = servicios.parsear_servicios(f'a.service {carga} failed nuevo-estado-2 desc')[0]
            self.assertEqual(u['LoadState'], carga)
            self.assertEqual(u['SubState'], 'nuevo-estado-2')

    def test_inactive_active_y_transiciones_no_son_failed(self):
        for activo in ('active', 'inactive', 'activating', 'deactivating', 'disabled', 'FAILED', 'futuro'):
            with self.subTest(activo=activo), self.assertRaises(servicios.FuenteInvalida):
                servicios.parsear_servicios(f'a.service loaded {activo} failed desc')

    def test_nombres_invalidos_y_tipos_ajenos(self):
        for nombre in ('a.socket', 'a.timer', 'a.target', '/a.service', 'á.service',
                       'a@.service', '@instancia.service', '.service', 'a@@b.service', r'a\q.service',
                       r'a\xzz.service', 'a;comando.service', 'a.service;otro', 'a'*248+'.service'):
            with self.subTest(nombre=nombre), self.assertRaises(servicios.FuenteInvalida):
                servicios.parsear_servicios(f'{nombre} loaded failed failed desc')

    def test_longitud_nombre_255(self):
        nombre = 'a'*247 + '.service'
        self.assertEqual(len(nombre), 255)
        self.assertEqual(servicios.parsear_servicios(f'{nombre} loaded failed failed desc')[0]['nombre'], nombre)

    def test_duplicados_rechazan_bloque_sin_fragmentos_en_error(self):
        linea = 'secreto.service loaded failed failed DESCRIPCION_PRIVADA\n'
        with self.assertRaises(servicios.FuenteInvalida) as error:
            servicios.parsear_servicios(linea*2)
        self.assertNotIn('secreto', str(error.exception))
        self.assertNotIn('DESCRIPCION', str(error.exception))

    def test_columnas_cabeceras_estados_y_controles_invalidos(self):
        for texto in ('UNIT LOAD ACTIVE SUB DESCRIPTION', 'a.service loaded failed',
                      'a.service disabled failed failed desc', 'a.service loaded failed BAD desc',
                      'a.service loaded failed a/b desc', 'a.service loaded failed '+'a'*65+' desc',
                      '● a.service loaded failed failed desc',
                      'a.service loaded failed failed desc\x1b[0m',
                      'a.service loaded failed failed desc\u202e',
                      'a.service loaded failed failed desc\x00'):
            with self.subTest(texto=texto), self.assertRaises(servicios.FuenteInvalida):
                servicios.parsear_servicios(texto)

    def test_limites_500_501_y_parametros(self):
        texto = ''.join(f'a{i}.service loaded failed failed desc\n' for i in range(500))
        self.assertEqual(len(servicios.parsear_servicios(texto)), 500)
        with self.assertRaises(servicios.FuenteInvalida) as error:
            servicios.parsear_servicios(texto+'extra.service loaded failed failed desc\n')
        self.assertEqual(error.exception.codigo, 'limite_unidades')
        for texto, limite in ((None, 500), ('', -1), ('', True), ('', 1.5)):
            with self.assertRaises(servicios.FuenteInvalida):
                servicios.parsear_servicios(texto, limite)


class NormalizacionServicios(unittest.TestCase):
    def test_contrato_recuentos_y_alcance(self):
        d = resultado().a_dict()
        self.assertEqual((d['version'], d['herramienta'], d['estado_adquisicion'],
                          d['estado_presentacion']), (1, 'servicios', 'completo', 'pendiente'))
        self.assertEqual(d['datos']['total_unidades'], 3)
        self.assertEqual(d['datos']['recuentos'], {'LoadState': {'not-found': 1, 'loaded': 2},
                         'ActiveState': {'failed': 3}, 'SubState': {'failed': 3}})
        self.assertEqual(d['alcance']['gestor'], 'sistema')
        self.assertEqual(d['alcance']['UnitFileState'], 'no_solicitado')
        self.assertEqual(d['alcance']['usuarios'], 'no_consultados')
        self.assertEqual(d['incidencias'], [])

    def test_cero_conocido(self):
        d = resultado('').a_dict()
        self.assertEqual(d['datos']['total_unidades'], 0)
        self.assertEqual(d['estado_adquisicion'], 'completo')

    def test_fuentes_fallidas_desconocido_no_prefijo(self):
        for estado in servicios.ESTADOS_FUENTE - {'correcta'}:
            d = resultado(estado=estado).a_dict()
            self.assertEqual(d['estado_adquisicion'], 'error')
            self.assertIsNone(d['datos']['total_unidades'])
            self.assertIsNone(d['datos']['recuentos'])
            self.assertEqual(d['datos']['unidades'], [])

    def test_formato_invalido_descarta_bloque_entero(self):
        d = resultado(TEXTO+'SECRETO\n').a_dict()
        self.assertEqual(d['fuentes']['systemctl_sistema']['estado'], 'formato_invalido')
        self.assertIsNone(d['datos']['total_unidades'])
        self.assertNotIn('SECRETO', str(d))

    def test_limite_unidades_desconocido(self):
        texto = ''.join(f'a{i}.service loaded failed failed desc\n' for i in range(501))
        d = resultado(texto).a_dict()
        self.assertEqual(d['fuentes']['systemctl_sistema']['estado'], 'limite_unidades')
        self.assertIsNone(d['datos']['total_unidades'])

    def test_no_muta_fuente_ni_retiene_descripciones_errores(self):
        f = fuente()
        f['stderr'] = 'ERROR_PRIVADO'
        antes = copy.deepcopy(f)
        r = servicios.normalizar_servicios(f)
        self.assertEqual(f, antes)
        for privado in ('DESCRIPCION_PRIVADA', '/home/', '/ruta/', 'ERROR_PRIVADO', 'stdout', 'stderr'):
            self.assertNotIn(privado, r.a_json())
        copia = r.a_dict()
        copia['datos']['unidades'].clear()
        self.assertEqual(len(r.a_dict()['datos']['unidades']), 3)

    def test_estado_fuente_ajeno_no_se_publica(self):
        r = resultado(estado='ERROR_PRIVADO')
        self.assertEqual(r.a_dict()['fuentes']['systemctl_sistema']['estado'], 'error_sistema')
        self.assertNotIn('ERROR_PRIVADO', r.a_json())


class InformeServicios(unittest.TestCase):
    def test_nombres_visibles_y_privacidad(self):
        r = resultado()
        texto, final = servicios.informe_servicios(r)
        self.assertEqual(final.estado_presentacion, 'completo')
        for nombre in ('zeta.service', 'trabajo@instancia.service', r'ruta\x2dprueba.service'):
            self.assertIn(nombre, texto)
        for secreto in ('DESCRIPCION_PRIVADA', '/home/privado', '/ruta/oculta', 'ruta-prueba.service'):
            self.assertNotIn(secreto, texto)
            self.assertNotIn(secreto, final.a_json())
        self.assertIn('UnitFileState: no solicitado', texto)
        self.assertIn('no transaccional', texto)
        self.assertEqual(r.estado_presentacion, 'pendiente')
        self.assertEqual(servicios.informe_servicios(r)[0], texto)

    def test_vacio_no_afirma_salud(self):
        texto, p = servicios.informe_servicios(resultado(''))
        self.assertEqual(p.estado_presentacion, 'completo')
        self.assertIn('Servicios fallidos observados: 0.', texto)
        self.assertIn('no garantiza salud general', texto)

    def test_error_no_se_presenta_como_cero(self):
        texto, p = servicios.informe_servicios(resultado(estado='permiso_denegado'))
        self.assertEqual(p.estado_presentacion, 'error')
        self.assertIn('Servicios fallidos observados: desconocido.', texto)
        self.assertNotIn('observados: 0', texto)

    def test_limite_20_no_cambia_recuentos(self):
        r = resultado(''.join(f'a{i:03}.service loaded failed failed desc\n' for i in range(25)))
        texto, p = servicios.informe_servicios(r)
        self.assertEqual(p.a_dict()['estado_adquisicion'], 'completo')
        self.assertEqual(p.estado_presentacion, 'parcial')
        self.assertEqual(p.a_dict()['datos'], r.a_dict()['datos'])
        self.assertIn('Vista breve: 20 de 25', texto)
        self.assertEqual(texto.count('ActiveState=failed;'), 20)
        self.assertIn('failed=25', texto)

    def test_20_filas_es_completo(self):
        r = resultado(''.join(f'a{i}.service loaded failed failed desc\n' for i in range(20)))
        self.assertEqual(servicios.informe_servicios(r)[1].estado_presentacion, 'completo')

    def test_tamano_18000_y_omision(self):
        texto = ''.join(f'a{i:03}'+'b'*243+'.service loaded failed failed desc\n' for i in range(21))
        informe, p = servicios.informe_servicios(resultado(texto))
        self.assertLessEqual(len(informe), 18000)
        self.assertEqual(p.estado_presentacion, 'parcial')
        informe, p = servicios.informe_servicios(resultado(), limite=100)
        self.assertLessEqual(len(informe), 100)
        self.assertEqual(p.estado_presentacion, 'omitido_por_limite')
        self.assertIn('no permite concluir ausencia', informe)
        with self.assertRaises(ValueError):
            servicios.informe_servicios(resultado(), limite=0)

    def test_herramienta_ajena_rechazada(self):
        d = resultado().a_dict()
        d['herramienta'] = 'memoria'
        with self.assertRaises(ValueError):
            servicios.informe_servicios(ResultadoVerificado(d))


class ModalidadServicios(unittest.TestCase):
    def ejecutar(self, efecto=(0, TEXTO, '', False), argumentos=()):
        with patch.object(sys, 'argv', ['AsistenteLocal.py', '--servicios-verificados', *argumentos]), \
             patch.object(app, 'ejecutar_comando', side_effect=[efecto]) as comando, \
             patch.object(app, 'consultar_modelo', side_effect=AssertionError('No modelo')) as modelo, \
             patch.object(app.urllib.request, 'urlopen', side_effect=AssertionError('No HTTP')) as http, \
             patch('builtins.input', side_effect=AssertionError('No interacción')) as entrada, \
             contextlib.redirect_stdout(io.StringIO()) as salida:
            codigo = app.main()
        modelo.assert_not_called()
        http.assert_not_called()
        entrada.assert_not_called()
        return codigo, salida.getvalue(), comando

    def test_consulta_unica_exacta_y_fallos_no_cambian_exito_diagnostico(self):
        codigo, texto, comando = self.ejecutar()
        self.assertEqual(codigo, 0)
        comando.assert_called_once()
        self.assertEqual(comando.call_args.args[0], ['systemctl', '--system', '--no-pager',
            '--no-ask-password', '--plain', '--no-legend', '--full', 'list-units', '--type=service', '--state=failed'])
        self.assertTrue(0 < comando.call_args.args[1] <= 15)
        self.assertIn('observados: 3.', texto)
        self.assertNotIn('DESCRIPCION_PRIVADA', texto)

    def test_cero_y_parcial_codigos(self):
        self.assertEqual(self.ejecutar((0, '', '', False))[0], 0)
        bloque = ''.join(f'a{i}.service loaded failed failed desc\n' for i in range(21))
        self.assertEqual(self.ejecutar((0, bloque, '', False))[0], 3)
        with patch.object(app, 'MAX_OUTPUT', 100):
            self.assertEqual(self.ejecutar()[0], 3)

    def test_errores_consulta_timeout_y_permisos_sin_reintentos(self):
        for error, estado in ((FileNotFoundError('PRIVADO'), 'ejecutable_ausente'),
                              (PermissionError('PRIVADO'), 'permiso_denegado'),
                              (OSError(errno.EPERM, 'PRIVADO'), 'permiso_denegado'),
                              (OSError('PRIVADO'), 'error_sistema'),
                              (TimeoutError('PRIVADO'), 'tiempo_agotado'),
                              (subprocess.TimeoutExpired(['PRIVADO'], 15), 'tiempo_agotado')):
            codigo, texto, comando = self.ejecutar(error)
            self.assertEqual(codigo, 1)
            comando.assert_called_once()
            self.assertIn(estado, texto)
            self.assertIn('observados: desconocido', texto)
            self.assertNotIn('PRIVADO', texto)

    def test_dbus_ausente_y_stderr_no_se_interpretan(self):
        for efecto, estado in (((1, TEXTO, 'Failed to connect to bus: PRIVADO', False), 'error_comando'),
                               ((0, TEXTO, 'PRIVADO', False), 'avisos_no_interpretados'),
                               ((0, TEXTO, '', True), 'truncada')):
            codigo, texto, comando = self.ejecutar(efecto)
            self.assertEqual(codigo, 1)
            self.assertIn(estado, texto)
            self.assertNotIn('PRIVADO', texto)
            self.assertNotIn('zeta.service', texto)
            comando.assert_called_once()

    def test_cli_incompatibles_sin_acciones(self):
        for flag in ('--interfaces-verificadas', '--memoria-verificada', '--conexiones-verificadas',
                     '--puertos-verificados', '--permitir-consultas-externas'):
            with contextlib.redirect_stderr(io.StringIO()), \
                 patch.object(app, 'consultar_servicios_verificados') as adquirir, \
                 self.assertRaises(SystemExit) as error:
                self.ejecutar(argumentos=(flag,))
            self.assertEqual(error.exception.code, 2)
            adquirir.assert_not_called()

    def test_plazo_agotado_no_inicia_comandos(self):
        with patch.object(app, 'MAX_SECONDS', 0):
            codigo, texto, comando = self.ejecutar()
        self.assertEqual(codigo, 1)
        comando.assert_not_called()
        self.assertIn('tiempo agotado', texto)

    def test_presupuesto_restante_limita_comando(self):
        with patch.object(app.time, 'monotonic', return_value=100), \
             patch.object(app, 'ejecutar_comando', return_value=(0, TEXTO, '', False)) as comando:
            app.consultar_servicios_verificados(deadline=102)
        self.assertEqual(comando.call_args.args[1], 2)

    def test_interrupcion_adquisicion_y_presentacion_130(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(self.ejecutar(KeyboardInterrupt())[0], 130)
            with patch.object(app, 'informe_servicios', side_effect=KeyboardInterrupt()):
                self.assertEqual(self.ejecutar()[0], 130)

    def test_plazo_compartido_y_vencimiento_no_publica(self):
        for fase in ('adquirir', 'presentar'):
            reloj = [100.0]
            def adquirir(deadline):
                self.assertEqual(deadline, 220)
                if fase == 'adquirir':
                    reloj[0] = 221
                return resultado()
            def presentar(*args, **kw):
                reloj[0] = 221
                return 'DATOS_TARDIOS', resultado().con_presentacion('completo')
            with patch.object(app.time, 'monotonic', side_effect=lambda: reloj[0]), \
                 patch.object(app, 'consultar_servicios_verificados', side_effect=adquirir), \
                 patch.object(app, 'informe_servicios', side_effect=presentar) as informe, \
                 patch.object(app, 'ejecutar_comando', side_effect=AssertionError('No real')), \
                 contextlib.redirect_stdout(io.StringIO()) as salida:
                self.assertEqual(app.ejecutar_servicios_verificados(), 1)
            self.assertNotIn('DATOS_TARDIOS', salida.getvalue())
            self.assertEqual(informe.call_count, 0 if fase == 'adquirir' else 1)

    def test_timeout_despues_del_comando_descarta_datos(self):
        reloj = [100.0]
        def lento(*args):
            reloj[0] = 103
            return 0, TEXTO, '', False
        with patch.object(app.time, 'monotonic', side_effect=lambda: reloj[0]), \
             patch.object(app, 'ejecutar_comando', side_effect=lento) as comando:
            d = app.consultar_servicios_verificados(deadline=102).a_dict()
        comando.assert_called_once()
        self.assertIsNone(d['datos']['total_unidades'])
        self.assertEqual(d['fuentes']['systemctl_sistema']['estado'], 'tiempo_agotado')

    def test_conversacion_y_herramienta_sin_cambios(self):
        with patch.object(sys, 'argv', ['AsistenteLocal.py']), \
             patch('builtins.input', side_effect=['servicios_fallidos', 'salir']), \
             patch.object(app, 'preguntar') as preguntar, \
             patch.object(app, 'ejecutar_servicios_verificados') as ejecutar, \
             contextlib.redirect_stdout(io.StringIO()):
            app.main()
        preguntar.assert_called_once_with('servicios_fallidos')
        ejecutar.assert_not_called()
        self.assertEqual(app.TOOLS['servicios_fallidos']['commands'], [['systemctl', '--failed', '--no-pager']])
