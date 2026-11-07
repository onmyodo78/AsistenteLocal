import contextlib
import copy
import io
from pathlib import Path
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import AsistenteLocal as app
import memoria

TEXTO = (Path(__file__).parent / 'fixtures/meminfo.txt').read_text()


def fuente(texto=TEXTO, estado='correcta', avisos=False):
    return {'estado': estado, 'codigo': 0, 'stdout': texto, 'avisos': avisos}


def normalizar(texto=TEXTO, **opciones):
    return memoria.normalizar_memoria(fuente(texto, **opciones))


class NormalizacionMemoria(unittest.TestCase):
    def test_valores_exactos_y_formulas(self):
        d = normalizar()
        self.assertEqual(d['estado'], 'completo')
        self.assertEqual(d['ram'], {'total_bytes': 32768*1024, 'disponible_estimada_bytes': 16384*1024,
                                    'utilizada_estimada_bytes': 16384*1024, 'libre_bytes': 4096*1024})
        self.assertEqual(d['swap'], {'total_bytes': 8192*1024, 'libre_bytes': 6144*1024,
                                    'ocupada_bytes': 2048*1024})
        self.assertEqual(d['unidad_normalizada'], 'bytes')
        self.assertEqual(d['actividad_intercambio'], {'estado': 'no_medida', 'entrada_bytes_s': None,
                                                     'salida_bytes_s': None})

    def test_memavailable_ausente_no_se_sustituye_por_libre(self):
        d = normalizar(TEXTO.replace('MemAvailable:   16384 kB\n', ''))
        self.assertEqual(d['estado'], 'parcial')
        self.assertIsNone(d['ram']['disponible_estimada_bytes'])
        self.assertIsNone(d['ram']['utilizada_estimada_bytes'])
        self.assertEqual(d['ram']['libre_bytes'], 4096*1024)
        self.assertEqual(d['swap']['ocupada_bytes'], 2048*1024)

    def test_memfree_opcional_no_impide_exito(self):
        d = normalizar(TEXTO.replace('MemFree:         4096 kB\n', ''))
        self.assertEqual(d['estado'], 'completo')
        self.assertIsNone(d['ram']['libre_bytes'])

    def test_campos_duplicados_no_usan_ultimo_valor(self):
        d = normalizar(TEXTO + 'MemAvailable: 0 kB\nMemAvailable: 1 kB\n')
        self.assertEqual(d['estado'], 'parcial')
        self.assertIsNone(d['ram']['disponible_estimada_bytes'])
        self.assertIsNone(d['ram']['utilizada_estimada_bytes'])
        self.assertEqual(d['problemas_campos']['MemAvailable'], 'campo duplicado')

    def test_valores_y_unidades_invalidos(self):
        for valor in ('-1 kB', '+1 kB', '1.5 kB', 'NaN kB', '1 MB', '1', '١ kB', '0 kB extra'):
            with self.subTest(valor=valor):
                d = normalizar(TEXTO.replace('MemAvailable:   16384 kB', 'MemAvailable: ' + valor))
                self.assertEqual(d['estado'], 'parcial')
                self.assertIsNone(d['ram']['disponible_estimada_bytes'])
                self.assertIsNone(d['ram']['utilizada_estimada_bytes'])
                self.assertEqual(d['ram']['total_bytes'], 32768*1024)

    def test_incoherencias_no_se_recortan_a_cero(self):
        for campo, linea, dato in (('MemAvailable', 'MemAvailable:   16384 kB', 'disponible_estimada_bytes'),
                                   ('MemFree', 'MemFree:         4096 kB', 'libre_bytes')):
            with self.subTest(campo=campo):
                d = normalizar(TEXTO.replace(linea, campo + ': 99999 kB'))
                self.assertEqual(d['estado'], 'parcial')
                self.assertIsNone(d['ram'][dato])
        d = normalizar(TEXTO.replace('SwapFree:        6144 kB', 'SwapFree: 99999 kB'))
        self.assertEqual(d['estado'], 'parcial')
        self.assertIsNone(d['swap']['libre_bytes'])
        self.assertIsNone(d['swap']['ocupada_bytes'])
        self.assertEqual(d['ram']['utilizada_estimada_bytes'], 16384*1024)

    def test_swap_cero_medida_no_es_actividad_cero(self):
        d = normalizar(TEXTO.replace('SwapTotal:       8192 kB', 'SwapTotal: 0 kB').replace('SwapFree:        6144 kB', 'SwapFree: 0 kB'))
        self.assertEqual(d['estado'], 'completo')
        self.assertEqual(d['swap'], {'total_bytes': 0, 'libre_bytes': 0, 'ocupada_bytes': 0})
        self.assertEqual(d['actividad_intercambio']['estado'], 'no_medida')
        self.assertIsNone(d['actividad_intercambio']['entrada_bytes_s'])

    def test_swap_ausente_no_es_cero(self):
        texto = '\n'.join(l for l in TEXTO.splitlines() if not l.startswith('Swap'))
        d = normalizar(texto)
        self.assertEqual(d['estado'], 'parcial')
        self.assertTrue(all(v is None for v in d['swap'].values()))
        self.assertEqual(d['ram']['total_bytes'], 32768*1024)

    def test_ram_ausente_preserva_swap(self):
        texto = '\n'.join(l for l in TEXTO.splitlines() if l.startswith('Swap'))
        d = normalizar(texto)
        self.assertEqual(d['estado'], 'parcial')
        self.assertTrue(all(v is None for v in d['ram'].values()))
        self.assertEqual(d['swap']['ocupada_bytes'], 2048*1024)

    def test_sin_datos_utilizables_es_error(self):
        for texto in ('', 'foo: 100 kB', 'MemTotal sin formato'):
            with self.subTest(texto=texto):
                d = normalizar(texto)
                self.assertEqual(d['estado'], 'error')
                self.assertTrue(all(v is None for v in d['ram'].values()))
                self.assertTrue(all(v is None for v in d['swap'].values()))

    def test_fuente_fallida_descarta_prefijo_valido(self):
        for estado in ('truncada', 'tiempo_agotado', 'permiso_denegado', 'error_lector'):
            with self.subTest(estado=estado):
                d = normalizar(estado=estado)
                self.assertEqual(d['estado'], 'error')
                self.assertTrue(all(v is None for v in d['ram'].values()))
                self.assertTrue(all(v is None for v in d['swap'].values()))

    def test_avisos_o_lineas_malformadas_son_parciales(self):
        self.assertEqual(normalizar(avisos=True)['estado'], 'parcial')
        self.assertEqual(normalizar(TEXTO + '\nlinea malformada')['estado'], 'parcial')

    def test_datos_adicionales_no_requeridos_no_se_interpretan(self):
        d = normalizar(TEXTO + 'HugePages_Free: 0\nOtro: SECRETO\n')
        self.assertEqual(d['estado'], 'completo')
        self.assertNotIn('SECRETO', str(d))

    def test_no_muta_fuente(self):
        f = fuente()
        original = copy.deepcopy(f)
        memoria.normalizar_memoria(f)
        self.assertEqual(f, original)


class InformeMemoria(unittest.TestCase):
    def test_informe_sin_inferencias_de_actividad(self):
        texto, estado = memoria.informe_memoria(normalizar())
        self.assertEqual(estado, 'completo')
        self.assertIn('33554432 B', texto)
        self.assertIn('0.03 GiB, aprox.', texto)
        self.assertIn('utilizada estimada (MemTotal - MemAvailable)', texto)
        self.assertIn('Swap ocupada (SwapTotal - SwapFree): 2097152 B', texto)
        self.assertIn('Actividad de intercambio: no_medida', texto)
        self.assertIn('no demuestra actividad', texto)
        self.assertNotIn('no hay actividad de swap', texto)
        self.assertNotIn('swap está inactiva', texto)
        self.assertNotIn('RAM suficiente', texto)
        self.assertNotIn('bytes_s=0', texto)

    def test_desconocidos_no_se_muestran_como_cero(self):
        texto, estado = memoria.informe_memoria(normalizar('SwapTotal: 100 kB'))
        self.assertEqual(estado, 'parcial')
        self.assertIn('RAM total visible para el kernel: desconocido', texto)
        self.assertIn('Swap ocupada (SwapTotal - SwapFree): desconocido', texto)
        self.assertNotIn('Swap ocupada (SwapTotal - SwapFree): 0', texto)

    def test_omision_por_tamano_y_estado_desconocido(self):
        texto, estado = memoria.informe_memoria(normalizar(), limite=100)
        self.assertEqual(estado, 'omitido_por_limite')
        self.assertLessEqual(len(texto), 100)
        self.assertIn('omitido', texto)
        with self.assertRaises(ValueError):
            memoria.informe_memoria(normalizar(), limite=0)
        d = normalizar()
        d['estado'] = 'otro'
        with self.assertRaises(ValueError):
            memoria.informe_memoria(d)


class RedondeoGiB(unittest.TestCase):
    def test_limites_decimales(self):
        casos = ((0, '0.00'), (5368709, '0.00'), (5368710, '0.01'),
                 (1068373114, '0.99'), (1068373115, '1.00'),
                 (8584565882, '7.99'), (8584565883, '8.00'))
        for valor, esperado in casos:
            with self.subTest(bytes=valor):
                self.assertEqual(memoria._cantidad(valor), f'{valor} B ({esperado} GiB, aprox.)')

    def test_empates_exactos_redondean_hacia_arriba(self):
        gib = 1024**3
        for valor, esperado in ((gib//8-1, '0.12'), (gib//8, '0.13'),
                                (gib//8+1, '0.13'), (gib+gib//8, '1.13')):
            with self.subTest(bytes=valor):
                self.assertEqual(memoria._cantidad(valor), f'{valor} B ({esperado} GiB, aprox.)')

    def test_regresiones_de_la_muestra_anterior(self):
        for valor, esperado in ((8589930496, '8.00'), (33497853952, '31.20'),
                                (876244992, '0.82'), (320036864, '0.30')):
            with self.subTest(bytes=valor):
                self.assertEqual(memoria._cantidad(valor), f'{valor} B ({esperado} GiB, aprox.)')

    def test_precision_grande_y_desconocido(self):
        entero = 2**60 + 1
        valor = entero * 1024**3 + 1024**3//8
        self.assertEqual(memoria._cantidad(valor), f'{valor} B ({entero}.13 GiB, aprox.)')
        self.assertEqual(memoria._cantidad(None), 'desconocido')

    def test_presentacion_no_muta_bytes_formulas_ni_estado(self):
        d = normalizar()
        original = copy.deepcopy(d)
        texto, estado = memoria.informe_memoria(d)
        self.assertEqual(d, original)
        self.assertEqual(estado, original['estado'])
        for grupo in ('ram', 'swap'):
            for valor in d[grupo].values():
                self.assertIn(str(valor) + ' B', texto)
        self.assertEqual(d['ram']['utilizada_estimada_bytes'],
                         d['ram']['total_bytes'] - d['ram']['disponible_estimada_bytes'])
        self.assertEqual(d['swap']['ocupada_bytes'], d['swap']['total_bytes'] - d['swap']['libre_bytes'])


class LectorMeminfo(unittest.TestCase):
    def test_comando_fijo_sin_ruta_del_usuario(self):
        comando = memoria.comando_meminfo('/python/ficticio', 65536)
        self.assertEqual(comando[:3], ['/python/ficticio', '-B', '-c'])
        self.assertEqual(comando[3], memoria.LECTOR_MEMINFO)
        self.assertEqual(comando[4], '65536')
        for limite in (0, -1, True):
            with self.assertRaises(ValueError):
                memoria.comando_meminfo('python', limite)

    def test_lector_solo_abre_meminfo_y_acota_lectura(self):
        salida = io.BytesIO()
        archivo = io.BytesIO(b'x' * 100)
        with patch('builtins.open', return_value=archivo) as abrir, \
             patch.object(sys, 'argv', ['-c', '10']), \
             patch.object(sys, 'stdout', SimpleNamespace(buffer=salida)):
            exec(memoria.LECTOR_MEMINFO, {})
        abrir.assert_called_once_with('/proc/meminfo', 'rb')
        self.assertEqual(salida.getvalue(), b'x' * 11)
        self.assertTrue(archivo.closed)

    def test_lector_clasifica_errores_sin_volcar_contenido(self):
        for error, codigo in ((FileNotFoundError('SECRETO'), 66), (PermissionError('SECRETO'), 77), (OSError('SECRETO'), 74)):
            salida = io.BytesIO()
            with self.subTest(codigo=codigo), patch('builtins.open', side_effect=error), \
                 patch.object(sys, 'argv', ['-c', '65536']), \
                 patch.object(sys, 'stdout', SimpleNamespace(buffer=salida)), self.assertRaises(SystemExit) as capturado:
                exec(memoria.LECTOR_MEMINFO, {})
            self.assertEqual(capturado.exception.code, codigo)
            self.assertEqual(salida.getvalue(), b'')


class ModalidadMemoria(unittest.TestCase):
    def ejecutar(self, respuesta=(0, TEXTO, '', False)):
        with patch.object(sys, 'argv', ['AsistenteLocal.py', '--memoria-verificada']), \
             patch.object(app, 'ejecutar_comando', return_value=respuesta) as ejecutar, \
             patch.object(app, 'consultar_modelo', side_effect=AssertionError('No modelo')) as modelo, \
             patch.object(app, 'abrir_http_local', side_effect=AssertionError('No HTTP')) as http, \
             patch.object(app, 'ejecutar_consulta', side_effect=AssertionError('No otras herramientas')) as consulta, \
             patch('builtins.input', side_effect=AssertionError('No interacción')) as entrada, \
             contextlib.redirect_stdout(io.StringIO()) as salida:
            codigo = app.main()
        ejecutar.assert_called_once()
        self.assertEqual(ejecutar.call_args.args[0], memoria.comando_meminfo(sys.executable, app.MAX_COMMAND_BYTES))
        self.assertTrue(0 < ejecutar.call_args.args[1] <= 15)
        modelo.assert_not_called()
        http.assert_not_called()
        consulta.assert_not_called()
        entrada.assert_not_called()
        return codigo, salida.getvalue()

    def test_exito_0_sin_lm_studio(self):
        codigo, texto = self.ejecutar()
        self.assertEqual(codigo, 0)
        self.assertIn('Informe determinista de memoria', texto)
        self.assertIn('Actividad de intercambio: no_medida', texto)

    def test_parcial_3(self):
        codigo, texto = self.ejecutar((0, TEXTO.replace('MemAvailable:   16384 kB\n', ''), '', False))
        self.assertEqual(codigo, 3)
        self.assertIn('Resultado: parcial', texto)

    def test_fuentes_fallidas_1_y_sin_prefijo_interpretado(self):
        for codigo in (66, 77, 74, 2):
            with self.subTest(codigo=codigo):
                retorno, texto = self.ejecutar((codigo, TEXTO, 'SECRETO', False))
                self.assertEqual(retorno, 1)
                self.assertNotIn('33554432 B', texto)
                self.assertNotIn('SECRETO', texto)

    def test_captura_truncada_1(self):
        codigo, texto = self.ejecutar((0, TEXTO, '', True))
        self.assertEqual(codigo, 1)
        self.assertIn('lectura=truncada', texto)
        self.assertNotIn('33554432 B', texto)

    def test_avisos_del_lector_3(self):
        codigo, texto = self.ejecutar((0, TEXTO, 'SECRETO', False))
        self.assertEqual(codigo, 3)
        self.assertNotIn('SECRETO', texto)

    def test_errores_timeout_y_permisos_1(self):
        for error, estado in ((TimeoutError(), 'tiempo_agotado'), (FileNotFoundError(), 'lector_ausente'),
                              (PermissionError(), 'permiso_denegado'), (OSError(), 'error_lectura')):
            with self.subTest(error=type(error).__name__), \
                 patch.object(app, 'ejecutar_comando', side_effect=error) as ejecutar, \
                 contextlib.redirect_stdout(io.StringIO()) as salida:
                self.assertEqual(app.ejecutar_memoria_verificada(), 1)
                self.assertIn('lectura='+estado, salida.getvalue())
                ejecutar.assert_called_once()

    def test_deadline_agotado_no_inicia_lector(self):
        with patch.object(app, 'ejecutar_comando') as ejecutar:
            d = app.consultar_memoria_verificada(app.time.monotonic()-1)
        ejecutar.assert_not_called()
        self.assertEqual(d['estado'], 'error')
        self.assertEqual(d['fuente']['estado'], 'tiempo_agotado')

    def test_presupuesto_restante_acota_timeout(self):
        with patch.object(app.time, 'monotonic', return_value=100), \
             patch.object(app, 'ejecutar_comando', return_value=(0, TEXTO, '', False)) as ejecutar:
            d = app.consultar_memoria_verificada(deadline=102)
        self.assertEqual(ejecutar.call_args.args[1], 2)
        self.assertEqual(d['estado'], 'completo')

    def test_global_expirado_descarta_resultado_tardio(self):
        reloj = [100.0]
        def adquirir(*args):
            reloj[0] = 106
            return (0, TEXTO, '', False)
        with patch.object(app.time, 'monotonic', side_effect=lambda: reloj[0]), \
             patch.object(app, 'ejecutar_comando', side_effect=adquirir):
            d = app.consultar_memoria_verificada(deadline=105)
        self.assertEqual(d['estado'], 'error')
        self.assertEqual(d['fuente']['estado'], 'tiempo_agotado')
        self.assertIsNone(d['ram']['total_bytes'])

    def test_global_expirado_durante_presentacion_no_publica_datos(self):
        reloj = [100.0]
        def presentar(*args, **kwargs):
            reloj[0] = 221
            return ('DATOS_TARDIOS', 'completo')
        with patch.object(app.time, 'monotonic', side_effect=lambda: reloj[0]), \
             patch.object(app, 'consultar_memoria_verificada', return_value=normalizar()), \
             patch.object(app, 'informe_memoria', side_effect=presentar), \
             contextlib.redirect_stdout(io.StringIO()) as salida:
            self.assertEqual(app.ejecutar_memoria_verificada(), 1)
        self.assertNotIn('DATOS_TARDIOS', salida.getvalue())
        self.assertIn('tiempo agotado', salida.getvalue())

    def test_interrupcion_130(self):
        with patch.object(app, 'ejecutar_comando', side_effect=KeyboardInterrupt()), \
             contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(app.ejecutar_memoria_verificada(), 130)

    def test_omision_de_presentacion_3(self):
        with patch.object(app, 'consultar_memoria_verificada', return_value=normalizar()), \
             patch.object(app, 'MAX_OUTPUT', 100), contextlib.redirect_stdout(io.StringIO()) as salida:
            self.assertEqual(app.ejecutar_memoria_verificada(), 3)
        self.assertIn('omitido', salida.getvalue())

    def test_flags_incompatibles_2(self):
        for flag in ('--interfaces-verificadas', '--permitir-consultas-externas'):
            with self.subTest(flag=flag), \
                 patch.object(sys, 'argv', ['AsistenteLocal.py', '--memoria-verificada', flag]), \
                 patch.object(app, 'ejecutar_comando') as ejecutar, \
                 contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                app.main()
            self.assertEqual(error.exception.code, 2)
            ejecutar.assert_not_called()

    def test_conversacion_sigue_usando_free_h(self):
        self.assertEqual(app.TOOLS['memoria']['commands'], [['free', '-h']])
        with patch.object(sys, 'argv', ['AsistenteLocal.py']), \
             patch('builtins.input', side_effect=['memoria', 'salir']), \
             patch.object(app, 'preguntar') as preguntar, \
             patch.object(app, 'ejecutar_memoria_verificada') as verificada, \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertIsNone(app.main())
        preguntar.assert_called_once_with('memoria')
        verificada.assert_not_called()

    def test_interfaces_verificadas_conserva_ruta(self):
        with patch.object(sys, 'argv', ['AsistenteLocal.py', '--interfaces-verificadas']), \
             patch.object(app, 'ejecutar_interfaces_verificadas', return_value=3) as interfaces, \
             patch.object(app, 'ejecutar_memoria_verificada') as memoria_verificada:
            self.assertEqual(app.main(), 3)
        interfaces.assert_called_once()
        memoria_verificada.assert_not_called()
