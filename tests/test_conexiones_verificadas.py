import contextlib
import copy
import io
import ipaddress
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

import AsistenteLocal as app
import conexiones as sockets
from control_verificado import codigo_salida
from resultado_verificado import ResultadoVerificado

CARPETA = Path(__file__).parent / 'fixtures'
TEXTOS = {nombre: (CARPETA / ('sockets_' + nombre + '.txt')).read_text()
          for nombre, _, _, _ in sockets.FUENTES}


def fuentes(textos=None):
    textos = TEXTOS if textos is None else textos
    return {nombre: {'estado': 'correcta', 'codigo': 0, 'stdout': textos[nombre]}
            for nombre, _, _, _ in sockets.FUENTES}


class ParserSockets(unittest.TestCase):
    def test_protocolo_familia_estados_colas_y_sin_procesos(self):
        for nombre, protocolo, familia, _ in sockets.FUENTES:
            with self.subTest(fuente=nombre):
                registros = sockets.parsear_fuente(TEXTOS[nombre], protocolo, familia)
                self.assertTrue(registros)
                for r in registros:
                    self.assertEqual((r['protocolo'], r['familia']), (protocolo, familia))
                    self.assertIs(type(r['cola_recepcion']), int)
                    self.assertEqual(r['procesos'], {'estado': 'no_solicitados', 'valores': None})
        tcp = sockets.parsear_fuente(TEXTOS['tcp4'], 'tcp', 'ipv4')
        self.assertEqual([r['estado'] for r in tcp], ['LISTEN', 'ESTAB', 'ESTAB', 'TIME-WAIT'])
        self.assertEqual(tcp[1]['cola_envio'], 24)

    def test_direcciones_ipv4_ipv6_y_mapeadas(self):
        for entrada, familia, direccion, puerto in (
            ('192.0.2.1:0', 'ipv4', '192.0.2.1', 0),
            ('[2001:db8::1]:65535', 'ipv6', '2001:db8::1', 65535),
            ('2001:db8::1:80', 'ipv6', '2001:db8::1', 80),
            ('[::ffff:192.0.2.1]:443', 'ipv6', '::ffff:c000:201', 443)):
            with self.subTest(entrada=entrada):
                d = sockets.extremo(entrada, familia)
                self.assertEqual(ipaddress.ip_address(d['direccion']), ipaddress.ip_address(direccion))
                self.assertEqual(d['puerto'], puerto)
                self.assertEqual(ipaddress.ip_address(d['direccion']).version, 4 if familia == 'ipv4' else 6)

    def test_zona_ipv6_literal_no_resuelta(self):
        for zona in ('demo0', '15', 'vlan.10'):
            d = sockets.extremo('[fe80::1%' + zona + ']:443', 'ipv6')
            self.assertEqual(d['zona'], zona)
            self.assertEqual(d['direccion'], 'fe80::1')

    def test_comodines_no_se_convierten_en_cero(self):
        for familia in ('ipv4', 'ipv6'):
            d = sockets.extremo('*:*', familia)
            self.assertIsNone(d['direccion'])
            self.assertIsNone(d['puerto'])
            self.assertEqual((d['tipo_direccion'], d['tipo_puerto']), ('comodin', 'comodin'))
        d = sockets.extremo('0.0.0.0:0', 'ipv4')
        self.assertEqual((d['direccion'], d['puerto']), ('0.0.0.0', 0))

    def test_extremos_invalidos_rechazados_sin_exponer_entrada(self):
        casos = [('servidor.secreto:443', 'ipv4'), ('192.0.2.1:65536', 'ipv4'),
                 ('192.0.2.1:-1', 'ipv4'), ('192.0.2.1:https', 'ipv4'),
                 ('192.0.2.1:١', 'ipv4'), ('[::1]80', 'ipv6'), ('[::1]:80]', 'ipv6'),
                 ('[::1]:', 'ipv6'), ('192.0.2.1:80', 'ipv6'), ('[::1]:80', 'ipv4'),
                 ('192.0.2.1%:80', 'ipv4'), ('[fe80::1%]:80', 'ipv6'),
                 ('[fe80::1%a%b]:80', 'ipv6'), ('[fe80::1%secreto/otro]:80', 'ipv6'),
                 ('[fe80::1%\x1b]:80', 'ipv6'), ('[*]:80', 'ipv6')]
        for entrada, familia in casos:
            with self.subTest(entrada=entrada), self.assertRaises(sockets.FuenteInvalida) as error:
                sockets.extremo(entrada, familia)
            self.assertNotIn(entrada, str(error.exception))

    def test_filas_invalidas_descartan_todo_el_bloque(self):
        invalidas = ['FUTURO 0 0 *:* *:*', 'ESTAB -1 0 *:* *:*',
                     'ESTAB 0.5 0 *:* *:*', 'ESTAB 0 18446744073709551616 *:* *:*',
                     'ESTAB 0 0 *:*', 'State Recv-Q Send-Q Local Peer',
                     'ESTAB 0 0 *:* *:* users:(("PROCESO_SECRETO",pid=1,fd=2))']
        for fila in invalidas:
            with self.subTest(fila=fila), self.assertRaises(sockets.FuenteInvalida):
                sockets.parsear_fuente(TEXTOS['tcp4'] + fila, 'tcp', 'ipv4')
        with self.assertRaises(sockets.FuenteInvalida):
            sockets.parsear_fuente('LISTEN 0 0 *:* *:*', 'udp', 'ipv4')

    def test_controles_y_unicode_no_se_normalizan_silenciosamente(self):
        for entrada in ('ESTAB\x1b 0 0 *:* *:*', 'ESTAB 0 0 *:* *:*\u202e',
                        'ESTAB 0\x1f 0 *:* *:*'):
            with self.subTest(entrada=entrada), self.assertRaises(sockets.FuenteInvalida):
                sockets.parsear_fuente(entrada, 'tcp', 'ipv4')

    def test_salida_vacia_y_limite_registros(self):
        self.assertEqual(sockets.parsear_fuente('\n  \n', 'tcp', 'ipv4'), [])
        linea = 'ESTAB 0 0 192.0.2.1:1 198.51.100.1:2\n'
        self.assertEqual(len(sockets.parsear_fuente(linea*500, 'tcp', 'ipv4')), 500)
        with self.assertRaises(sockets.FuenteInvalida) as error:
            sockets.parsear_fuente(linea*501, 'tcp', 'ipv4')
        self.assertEqual(error.exception.codigo, 'limite_registros')

    def test_parametros_de_parser_invalidos(self):
        for texto, protocolo, familia in ((None, 'tcp', 'ipv4'), ('', 'unix', 'ipv4'), ('', 'tcp', 'otra')):
            with self.assertRaises(sockets.FuenteInvalida):
                sockets.parsear_fuente(texto, protocolo, familia)


class NormalizacionSockets(unittest.TestCase):
    def test_contrato_y_conteos_exactos_sin_deduplicar(self):
        d = sockets.normalizar_conexiones(fuentes()).a_dict()
        self.assertEqual(d['estado_adquisicion'], 'completo')
        self.assertEqual(d['estado_presentacion'], 'pendiente')
        self.assertEqual(d['herramienta'], 'conexiones')
        self.assertEqual(d['datos']['total_registros'], 10)
        self.assertEqual(d['datos']['recuentos_por_fuente']['tcp4'],
                         {'total': 4, 'por_estado': {'LISTEN': 1, 'ESTAB': 2, 'TIME-WAIT': 1}})
        self.assertEqual(d['datos']['recuentos_por_fuente']['udp4']['por_estado'], {'UNCONN': 1, 'ESTAB': 1})
        self.assertEqual(len({r['id'] for r in d['datos']['registros']}), 10)

    def test_todas_vacias_es_completo_y_cero_medido(self):
        d = sockets.normalizar_conexiones(fuentes({n: '' for n in TEXTOS})).a_dict()
        self.assertEqual(d['estado_adquisicion'], 'completo')
        self.assertEqual(d['datos']['total_registros'], 0)
        self.assertTrue(all(c['total'] == 0 for c in d['datos']['recuentos_por_fuente'].values()))

    def test_fuente_truncada_o_fallida_no_utiliza_prefijo_valido(self):
        for estado in ('truncada', 'error_comando', 'permiso_denegado', 'tiempo_agotado', 'avisos_no_interpretados'):
            f = fuentes()
            f['tcp4']['estado'] = estado
            with self.subTest(estado=estado):
                d = sockets.normalizar_conexiones(f).a_dict()
                self.assertEqual(d['estado_adquisicion'], 'parcial')
                self.assertIsNone(d['datos']['total_registros'])
                self.assertIsNone(d['datos']['recuentos_por_fuente']['tcp4'])
                self.assertFalse(any(r['fuente'] == 'tcp4' for r in d['datos']['registros']))
                self.assertEqual(len(d['datos']['registros']), 6)

    def test_fila_invalida_no_deja_registros_de_la_fuente(self):
        f = fuentes()
        f['tcp4']['stdout'] += 'ESTADO_PRIVADO 0 0 IP_PRIVADA:1 IP_PRIVADA:2\n'
        d = sockets.normalizar_conexiones(f).a_dict()
        self.assertEqual(d['fuentes']['tcp4']['estado'], 'formato_invalido')
        self.assertIsNone(d['datos']['recuentos_por_fuente']['tcp4'])
        self.assertNotIn('PRIVAD', str(d))

    def test_limite_de_adquisicion_separa_fuentes(self):
        f = fuentes()
        f['udp6']['stdout'] = 'UNCONN 0 0 *:* *:*\n'*501
        d = sockets.normalizar_conexiones(f).a_dict()
        self.assertEqual(d['fuentes']['udp6']['estado'], 'limite_registros')
        self.assertIsNone(d['datos']['recuentos_por_fuente']['udp6'])
        self.assertEqual(len(d['datos']['registros']), 9)

    def test_sin_fuentes_utilizables_es_error_y_no_cero(self):
        f = fuentes()
        for fuente in f.values():
            fuente['estado'] = 'ejecutable_ausente'
        d = sockets.normalizar_conexiones(f).a_dict()
        self.assertEqual(d['estado_adquisicion'], 'error')
        self.assertIsNone(d['datos']['total_registros'])
        self.assertTrue(all(c is None for c in d['datos']['recuentos_por_fuente'].values()))
        self.assertEqual(len(d['incidencias']), 4)

    def test_no_muta_fuentes_y_no_guarda_stdout(self):
        f = fuentes()
        original = copy.deepcopy(f)
        d = sockets.normalizar_conexiones(f).a_dict()
        self.assertEqual(f, original)
        self.assertTrue(all('stdout' not in m for m in d['fuentes'].values()))
        self.assertEqual(d['alcance']['procesos'], 'no_solicitados')


class PresentacionSockets(unittest.TestCase):
    def test_informe_determinista_y_privacidad(self):
        r = sockets.normalizar_conexiones(fuentes())
        texto, final = sockets.informe_conexiones(r)
        self.assertEqual(final.estado_presentacion, 'completo')
        self.assertIn('TCP LISTEN=1, ESTAB=2, otros=1', texto)
        self.assertIn('registros de sockets observados, no clientes', texto)
        self.assertIn('UDP no representa una sesión TCP', texto)
        self.assertIn('Procesos: no solicitados', texto)
        self.assertIn('Conectividad: no comprobada', texto)
        self.assertIn('local=loopback', texto)
        for secreto in ('192.0.2.', '198.51.100.', '203.0.113.', 'fe80::', 'demo0', '::ffff', '::1'):
            self.assertNotIn(secreto, texto)
        self.assertNotIn('puerto=443', texto)  # Solo aparece como puerto remoto en el fixture.
        self.assertIn('198.51.100.20', r.a_json())  # Interno sensible, sin anonimización fingida.

    def test_fuente_parcial_no_publica_total_incompleto(self):
        f = fuentes(); f['tcp4']['estado'] = 'truncada'
        texto, final = sockets.informe_conexiones(sockets.normalizar_conexiones(f))
        self.assertEqual(final.estado_presentacion, 'parcial')
        self.assertIn('tcp4: fuente=truncada; recuento desconocido.', texto)
        self.assertIn('Total de las cuatro fuentes: desconocido.', texto)

    def test_vista_limitada_no_altera_adquisicion_ni_conteos(self):
        f = fuentes(); f['tcp4']['stdout'] = 'ESTAB 0 0 192.0.2.1:10 198.51.100.1:20\n'*25
        r = sockets.normalizar_conexiones(f)
        texto, final = sockets.informe_conexiones(r)
        self.assertEqual(final.a_dict()['estado_adquisicion'], 'completo')
        self.assertEqual(final.estado_presentacion, 'parcial')
        self.assertIn('tcp4: 25 registros', texto)
        self.assertIn('Vista breve: 20 de 31', texto)
        self.assertEqual(texto.count('remoto=oculto por privacidad.'), 20)
        self.assertEqual(control_codigo(final), 3)

    def test_limite_de_tamano_no_produce_recorte(self):
        texto, final = sockets.informe_conexiones(sockets.normalizar_conexiones(fuentes()), limite=100)
        self.assertLessEqual(len(texto), 100)
        self.assertEqual(final.estado_presentacion, 'omitido_por_limite')
        self.assertIn('no permite concluir ausencia', texto)
        with self.assertRaises(ValueError):
            sockets.informe_conexiones(sockets.normalizar_conexiones(fuentes()), limite=0)

    def test_estado_error_no_se_convierte_en_cero(self):
        f = fuentes()
        for fuente in f.values():fuente['estado'] = 'error_comando'
        texto, final = sockets.informe_conexiones(sockets.normalizar_conexiones(f))
        self.assertEqual(control_codigo(final), 1)
        self.assertIn('Total de las cuatro fuentes: desconocido.', texto)
        self.assertNotIn('0 registros', texto)


def control_codigo(resultado):
    return codigo_salida(resultado.estado_presentacion)


class ModalidadConexiones(unittest.TestCase):
    def ejecutar(self, efectos):
        with patch.object(sys, 'argv', ['AsistenteLocal.py', '--conexiones-verificadas']), \
             patch.object(app, 'ejecutar_comando', side_effect=efectos) as comando, \
             patch.object(app, 'consultar_modelo', side_effect=AssertionError('No modelo')) as modelo, \
             patch.object(app, 'abrir_http_local', side_effect=AssertionError('No HTTP')) as http, \
             patch('builtins.input', side_effect=AssertionError('No interacción')) as entrada, \
             contextlib.redirect_stdout(io.StringIO()) as salida:
            codigo = app.main()
        modelo.assert_not_called(); http.assert_not_called(); entrada.assert_not_called()
        return codigo, salida.getvalue(), comando

    def correctas(self):
        return [(0, TEXTOS[nombre], '', False) for nombre, _, _, _ in sockets.FUENTES]

    def test_cuatro_comandos_fijos_sin_dns_procesos_o_herramientas_reales(self):
        codigo, texto, comando = self.ejecutar(self.correctas())
        self.assertEqual(codigo, 0)
        self.assertEqual([c.args[0] for c in comando.call_args_list], [list(f[3]) for f in sockets.FUENTES])
        self.assertTrue(all(0 < c.args[1] <= 15 for c in comando.call_args_list))
        self.assertTrue(all('-n' in c.args[0] and '-p' not in c.args[0] for c in comando.call_args_list))
        self.assertIn('Total de las cuatro fuentes: 10.', texto)

    def test_fallo_parcial_de_fuente_3(self):
        efectos = self.correctas(); efectos[0] = PermissionError('SECRETO')
        codigo, texto, comando = self.ejecutar(efectos)
        self.assertEqual(codigo, 3)
        self.assertEqual(comando.call_count, 4)
        self.assertIn('tcp4: fuente=permiso_denegado', texto)
        self.assertNotIn('SECRETO', texto)

    def test_fuentes_ausentes_1(self):
        codigo, texto, comando = self.ejecutar([FileNotFoundError('SECRETO')]*4)
        self.assertEqual(codigo, 1)
        self.assertEqual(comando.call_count, 4)
        self.assertIn('recuento desconocido', texto)
        self.assertNotIn('SECRETO', texto)

    def test_stderr_o_codigo_no_cero_no_se_interpretan(self):
        for salida in ((0, TEXTOS['tcp4'], 'IP_SECRETA PROCESO_SECRETO', False),
                       (1, TEXTOS['tcp4'], 'IP_SECRETA PROCESO_SECRETO', False),
                       (0, TEXTOS['tcp4'], '', True)):
            efectos = self.correctas(); efectos[0] = salida
            codigo, texto, _ = self.ejecutar(efectos)
            self.assertEqual(codigo, 3)
            self.assertNotIn('SECRETO', texto)
            self.assertIn('recuento desconocido', texto)

    def test_limite_de_registros_y_presentacion_separados(self):
        efectos = self.correctas(); efectos[0] = (0, 'ESTAB 0 0 *:* *:*\n'*501, '', False)
        codigo, texto, _ = self.ejecutar(efectos)
        self.assertEqual(codigo, 3)
        self.assertIn('fuente=limite_registros', texto)

    def test_deadline_agotado_no_inicia_comandos(self):
        with patch.object(app, 'ejecutar_comando') as ejecutar:
            r = app.consultar_conexiones_verificadas(app.time.monotonic()-1)
        ejecutar.assert_not_called()
        self.assertEqual(r.a_dict()['estado_adquisicion'], 'error')

    def test_plazo_agotado_entre_fuentes_no_inicia_mas_comandos(self):
        reloj = [100.0]
        def primero(*args):
            reloj[0] = 106
            return 0, TEXTOS['tcp4'], '', False
        with patch.object(app.time, 'monotonic', side_effect=lambda: reloj[0]), \
             patch.object(app, 'ejecutar_comando', side_effect=primero) as ejecutar:
            r = app.consultar_conexiones_verificadas(deadline=105)
        self.assertEqual(ejecutar.call_count, 1)
        self.assertEqual(r.a_dict()['estado_adquisicion'], 'error')
        self.assertTrue(all(c is None for c in r.a_dict()['datos']['recuentos_por_fuente'].values()))

    def test_presupuesto_restante_limita_las_cuatro_operaciones(self):
        with patch.object(app.time, 'monotonic', return_value=100), \
             patch.object(app, 'ejecutar_comando', side_effect=self.correctas()) as ejecutar:
            app.consultar_conexiones_verificadas(deadline=102)
        self.assertTrue(all(c.args[1] == 2 for c in ejecutar.call_args_list))

    def test_interrupcion_130(self):
        with patch.object(app, 'ejecutar_comando', side_effect=KeyboardInterrupt()), \
             contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(app.ejecutar_conexiones_verificadas(), 130)

    def test_flags_incompatibles_2_sin_acciones(self):
        for flag in ('--interfaces-verificadas', '--memoria-verificada', '--permitir-consultas-externas'):
            with self.subTest(flag=flag), \
                 patch.object(sys, 'argv', ['AsistenteLocal.py', '--conexiones-verificadas', flag]), \
                 patch.object(app, 'ejecutar_comando') as ejecutar, \
                 contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                app.main()
            self.assertEqual(error.exception.code, 2)
            ejecutar.assert_not_called()

    def test_conversacion_y_comandos_anteriores_no_cambian(self):
        self.assertEqual(app.TOOLS['conexiones']['commands'], [['ss', '-tnp', 'state', 'established'], ['ss', '-uanp']])
        self.assertEqual(app.TOOLS['puertos']['commands'], [['ss', '-lntp'], ['ss', '-lnup']])
        with patch.object(sys, 'argv', ['AsistenteLocal.py']), \
             patch('builtins.input', side_effect=['conexiones', 'salir']), \
             patch.object(app, 'preguntar') as preguntar, \
             patch.object(app, 'ejecutar_conexiones_verificadas') as verificada, \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertIsNone(app.main())
        preguntar.assert_called_once_with('conexiones')
        verificada.assert_not_called()


class CalificadoresExtremos(unittest.TestCase):
    def test_variantes_validas_y_limites_calificador(self):
        for zona in ('demo0', '15', 'vlan.10', 'demo_1-2', 'a'*64):
            for entrada, familia, direccion in (
                (f'192.0.2.1%{zona}:0', 'ipv4', '192.0.2.1'),
                (f'[fe80::1%{zona}]:65535', 'ipv6', 'fe80::1'),
                (f'[fe80::1]%{zona}:65535', 'ipv6', 'fe80::1'),
                (f'fe80::1%{zona}:*', 'ipv6', 'fe80::1')):
                with self.subTest(entrada=entrada):
                    d = sockets.extremo(entrada, familia)
                    self.assertEqual(d['direccion'], direccion)
                    self.assertEqual(d['zona'], zona)
                    self.assertEqual(d['puerto'], None if entrada.endswith('*') else (0 if familia == 'ipv4' else 65535))

    def test_rechazo_calificadores_y_residuos(self):
        for zona in ('', 'a'*65, 'a%b', 'a/b', 'a:b', 'a b', 'á', 'a]'):
            for entrada, familia in ((f'192.0.2.1%{zona}:80', 'ipv4'),
                                     (f'[fe80::1%{zona}]:80', 'ipv6'),
                                     (f'[fe80::1]%{zona}:80', 'ipv6')):
                with self.subTest(entrada=entrada), self.assertRaises(sockets.FuenteInvalida):
                    sockets.extremo(entrada, familia)
        for entrada, familia in (
            ('[fe80::1%a]%b:80', 'ipv6'), ('[fe80::1]%a:80resto', 'ipv6'),
            ('[fe80::1]%a:80:90', 'ipv6'), ('[fe80::1]%a', 'ipv6'),
            ('[fe80::1]%a:65536', 'ipv6'), ('[fe80::1]%a:-1', 'ipv6'),
            ('[fe80::1]%a::80', 'ipv6'), ('[fe80::1%a:80', 'ipv6'),
            ('[fe80::1]]%a:80', 'ipv6'), ('[192.0.2.1]%a:80', 'ipv4'),
            ('192.0.2.1%a:80resto', 'ipv4'), ('192.0.2.999%a:80', 'ipv4'),
            ('*%a:80', 'ipv4'), ('[*]%a:80', 'ipv6')):
            with self.subTest(entrada=entrada), self.assertRaises(sockets.FuenteInvalida):
                sockets.extremo(entrada, familia)

    def bloques(self):
        return {familia: (CARPETA / f'sockets_calificadores_{familia}.txt').read_text()
                for familia in ('ipv4', 'ipv6')}

    def test_fixtures_recuentos_duplicados_y_privacidad(self):
        bloques = self.bloques()
        textos = {nombre: bloques[familia] for nombre, _, familia, _ in sockets.FUENTES}
        resultado = sockets.normalizar_conexiones(fuentes(textos))
        d = resultado.a_dict()
        self.assertEqual(d['estado_adquisicion'], 'completo')
        self.assertEqual(d['datos']['total_registros'], 10)
        for nombre, _, familia, _ in sockets.FUENTES:
            n = 2 if familia == 'ipv4' else 3
            self.assertEqual(d['datos']['recuentos_por_fuente'][nombre], {'total': n, 'por_estado': {'ESTAB': n}})
        texto, presentado = sockets.informe_conexiones(resultado)
        self.assertEqual(codigo_salida(presentado.estado_presentacion), 0)
        for privado in ('demo0', '192.0.2.10', '198.51.100.20', 'fe80::1', 'fe80::2'):
            self.assertNotIn(privado, texto)
        self.assertNotIn('puerto=443', texto)

    def test_fuente_con_calificador_invalido_se_descarta_entera(self):
        textos = dict(TEXTOS)
        textos['tcp4'] = self.bloques()['ipv4'] + 'ESTAB 0 0 192.0.2.1%:80 *:*\n'
        resultado = sockets.normalizar_conexiones(fuentes(textos)).a_dict()
        self.assertEqual(resultado['estado_adquisicion'], 'parcial')
        self.assertIsNone(resultado['datos']['recuentos_por_fuente']['tcp4'])
        self.assertIsNone(resultado['datos']['total_registros'])
        self.assertFalse(any(r['fuente'] == 'tcp4' for r in resultado['datos']['registros']))
