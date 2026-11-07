"""Pruebas de la vista especializada; nunca adquieren sockets reales."""
import contextlib
import copy
import io
import sys
import unittest
from unittest.mock import patch

import AsistenteLocal as app
import conexiones
import puertos
from resultado_verificado import ResultadoVerificado
from test_conexiones_verificadas import TEXTOS, fuentes


def original(f=None):
    return conexiones.normalizar_conexiones(fuentes() if f is None else f)


def derivado(f=None):
    return puertos.derivar_puertos(original(f))


class DerivacionPuertos(unittest.TestCase):
    def test_contrato_seleccion_e_invariantes_por_fuente(self):
        origen = original().a_dict()
        d = derivado().a_dict()
        self.assertEqual((d['herramienta'], d['version'], d['estado_adquisicion'],
                          d['estado_presentacion']), ('puertos', 1, 'completo', 'pendiente'))
        self.assertEqual(d['datos']['total_registros'], 5)
        for nombre, protocolo, _, _ in conexiones.FUENTES:
            o = origen['datos']['recuentos_por_fuente'][nombre]
            c = d['datos']['recuentos_por_fuente'][nombre]
            esperado = o['por_estado'].get('LISTEN', 0) if protocolo == 'tcp' else o['total']
            self.assertEqual(c['total'], esperado)
            self.assertEqual(c['excluidos'], o['total'] - esperado)
            self.assertEqual(sum(c['por_estado'].values()), esperado)
            if protocolo == 'udp':
                self.assertEqual(c['por_estado'], o['por_estado'])
        self.assertEqual(d['datos']['recuentos_por_fuente']['udp4']['por_estado'],
                         {'UNCONN': 1, 'ESTAB': 1})
        self.assertEqual(d['datos']['recuentos_origen_por_fuente'], origen['datos']['recuentos_por_fuente'])
        por_id = {r['id']: r for r in origen['datos']['registros']}
        for r in d['datos']['registros']:
            self.assertEqual(set(r), {'id', 'fuente', 'protocolo', 'familia', 'estado', 'local'})
            for k, v in r.items():
                self.assertEqual(v, por_id[r['id']][k])
        self.assertNotIn('remoto', d['datos']['registros'][0])
        self.assertNotIn('cola_recepcion', d['datos']['registros'][0])

    def test_no_muta_original_ni_copias(self):
        r = original()
        antes = r.a_json()
        p = puertos.derivar_puertos(r)
        d = p.a_dict()
        d['datos']['registros'][0]['local']['puerto'] = 999
        self.assertEqual(r.a_json(), antes)
        self.assertEqual(p.a_dict()['datos']['registros'][0]['local']['puerto'], 8080)

    def test_fuentes_validas_vacias_cero_conocido(self):
        f = fuentes({n: '' for n in TEXTOS})
        d = derivado(f).a_dict()
        self.assertEqual(d['estado_adquisicion'], 'completo')
        self.assertEqual(d['datos']['total_registros'], 0)
        self.assertTrue(all(c['total'] == 0 for c in d['datos']['recuentos_por_fuente'].values()))

    def test_tcp_valido_sin_listen_cero_seleccionado(self):
        f = fuentes()
        f['tcp4']['stdout'] = 'ESTAB 0 0 *:* *:*\nTIME-WAIT 0 0 *:* *:*\n'
        c = derivado(f).a_dict()['datos']['recuentos_por_fuente']['tcp4']
        self.assertEqual(c, {'total': 0, 'por_estado': {}, 'excluidos': 2})

    def test_fallos_recuento_desconocido_no_cero(self):
        for estado in conexiones.ESTADOS_FUENTE - {'correcta'}:
            f = fuentes()
            f['tcp4']['estado'] = estado
            d = derivado(f).a_dict()
            with self.subTest(estado=estado):
                self.assertEqual(d['estado_adquisicion'], 'parcial')
                self.assertIsNone(d['datos']['recuentos_por_fuente']['tcp4'])
                self.assertIsNone(d['datos']['total_registros'])
                self.assertFalse(any(r['fuente'] == 'tcp4' for r in d['datos']['registros']))

    def test_todas_fallidas_error(self):
        f = fuentes()
        for v in f.values():
            v['estado'] = 'ejecutable_ausente'
        texto, p = puertos.informe_puertos(derivado(f))
        self.assertEqual(p.estado_presentacion, 'error')
        self.assertIn('Total seleccionado de las cuatro fuentes: desconocido.', texto)
        self.assertNotIn('0 registros', texto)

    def test_duplicados_puertos_compartidos_cero_y_comodin(self):
        textos = {n: '' for n in TEXTOS}
        textos['tcp4'] = 'LISTEN 0 0 0.0.0.0:5353 *:*\n' * 2
        textos['tcp6'] = 'LISTEN 0 0 [::]:5353 *:*\nLISTEN 0 0 [::]:0 *:*\n'
        textos['udp4'] = 'UNCONN 0 0 *:5353 *:*\nUNCONN 0 0 *:* *:*\n'
        r = derivado(fuentes(textos))
        self.assertEqual(r.a_dict()['datos']['total_registros'], 6)
        self.assertEqual(len({v['id'] for v in r.a_dict()['datos']['registros']}), 6)
        texto, _ = puertos.informe_puertos(r)
        self.assertEqual(texto.count('puerto=5353'), 4)
        self.assertIn('puerto=0', texto)
        self.assertIn('puerto=*', texto)

    def test_limites_500_y_501_antes_del_filtrado(self):
        for cantidad in (500, 501):
            f = fuentes()
            f['tcp4']['stdout'] = 'ESTAB 0 0 *:* *:*\n' * cantidad
            d = derivado(f).a_dict()
            c = d['datos']['recuentos_por_fuente']['tcp4']
            if cantidad == 500:
                self.assertEqual(c['total'], 0)
                self.assertEqual(c['excluidos'], 500)
            else:
                self.assertIsNone(c)
                self.assertEqual(d['fuentes']['tcp4']['estado'], 'limite_registros')

    def test_estados_y_calificadores_invalidos_descartan_fuente(self):
        for fila in ('LISTEN 0 0 *:80 *:*\n',
                     'UNCONN 0 0 192.0.2.1%:80 *:*\n',
                     'FUTURO 0 0 *:80 *:*\n'):
            f = fuentes()
            f['udp4']['stdout'] += fila
            d = derivado(f).a_dict()
            self.assertIsNone(d['datos']['recuentos_por_fuente']['udp4'])
            self.assertEqual(d['fuentes']['udp4']['estado'], 'formato_invalido')

    def test_rechaza_herramientas_ajenas(self):
        d = original().a_dict()
        d['herramienta'] = 'memoria'
        with self.assertRaises(ValueError):
            puertos.derivar_puertos(ResultadoVerificado(d))
        with self.assertRaises(ValueError):
            puertos.informe_puertos(original())

    def test_no_arrastra_incidencias_de_presentacion_anterior(self):
        r = original().con_presentacion('parcial')
        p = puertos.derivar_puertos(r).a_dict()
        self.assertEqual(p['estado_presentacion'], 'pendiente')
        self.assertEqual(p['incidencias'], [])


class PresentacionPuertos(unittest.TestCase):
    def test_determinismo_privacidad_y_puertos_locales(self):
        p = derivado()
        antes = p.a_json()
        texto, final = puertos.informe_puertos(p)
        self.assertEqual(puertos.informe_puertos(p)[0], texto)
        self.assertEqual(final.estado_presentacion, 'completo')
        self.assertEqual(p.a_json(), antes)
        self.assertIn('puerto=8080', texto)
        self.assertIn('puerto=45000', texto)
        self.assertIn('local=loopback', texto)
        self.assertIn('Conectividad: no comprobada', texto)
        for secreto in ('192.0.2.', '198.51.100.', '203.0.113.', 'fe80::', 'demo0', '::1', 'puerto=443', 'puerto=5555'):
            self.assertNotIn(secreto, texto)
        self.assertIn('192.0.2.10', p.a_json())
        self.assertNotIn('198.51.100.', p.a_json())

    def test_calificadores_y_mapeadas_con_fixture(self):
        from pathlib import Path
        bloque = (Path(__file__).parent / 'fixtures' / 'puertos_locales.txt').read_text()
        f = fuentes()
        f['tcp6']['stdout'] = bloque
        p = derivado(f)
        texto, _ = puertos.informe_puertos(p)
        for secreto in ('fe80::', 'demo0', '192.0.2.', '::ffff', '%'):
            self.assertNotIn(secreto, texto)
        self.assertEqual(p.a_dict()['datos']['recuentos_por_fuente']['tcp6']['total'], 4)
        for r in p.a_dict()['datos']['registros']:
            self.assertEqual(puertos._local_visible(r['local']), conexiones._local_visible(r['local']))

    def test_limite_despues_del_filtrado_no_altera_recuentos(self):
        f = fuentes()
        f['tcp4']['stdout'] = 'ESTAB 0 0 *:123 *:*\n'*30 + 'LISTEN 0 0 *:80 *:*\n'*25
        p = derivado(f)
        texto, final = puertos.informe_puertos(p)
        self.assertEqual(final.a_dict()['estado_adquisicion'], 'completo')
        self.assertEqual(final.estado_presentacion, 'parcial')
        self.assertEqual(final.a_dict()['datos'], p.a_dict()['datos'])
        self.assertIn('tcp4: 25 registros seleccionados; LISTEN=25; excluidos=30.', texto)
        self.assertIn('Vista breve: 20 de 29', texto)
        self.assertEqual(texto.count('estado=LISTEN; local='), 20)
        self.assertNotIn('puerto=123', texto)

    def test_pocos_seleccionados_presentacion_completa(self):
        f = fuentes()
        f['tcp4']['stdout'] = 'ESTAB 0 0 *:* *:*\n'*100
        _, final = puertos.informe_puertos(derivado(f))
        self.assertEqual(final.estado_presentacion, 'completo')

    def test_tamano_omitido_sin_recorte_y_limite_imposible(self):
        texto, p = puertos.informe_puertos(derivado(), limite=100)
        self.assertLessEqual(len(texto), 100)
        self.assertEqual(p.estado_presentacion, 'omitido_por_limite')
        self.assertIn('no permite concluir ausencia', texto)
        with self.assertRaises(ValueError):
            puertos.informe_puertos(derivado(), limite=0)

    def test_incidencias_sin_datos_de_entrada(self):
        f = fuentes()
        f['tcp4']['stdout'] += 'SECRETO IP_PRIVADA%demo0:80\n'
        texto, p = puertos.informe_puertos(derivado(f))
        self.assertEqual(p.estado_presentacion, 'parcial')
        self.assertIn('recuento desconocido', texto)
        for s in ('SECRETO', 'IP_PRIVADA', 'demo0'):
            self.assertNotIn(s, texto)
            self.assertNotIn(s, str(p.a_dict()['incidencias']))


class ModalidadPuertos(unittest.TestCase):
    def ejecutar(self, efectos=None, argumentos=()):
        if efectos is None:
            efectos = [(0, TEXTOS[n], '', False) for n, _, _, _ in conexiones.FUENTES]
        with patch.object(sys, 'argv', ['AsistenteLocal.py', '--puertos-verificados', *argumentos]), \
             patch.object(app, 'ejecutar_comando', side_effect=efectos) as comandos, \
             patch.object(app, 'consultar_conexiones_verificadas', wraps=app.consultar_conexiones_verificadas) as adquirir, \
             patch.object(app, 'consultar_modelo', side_effect=AssertionError('No modelo')) as modelo, \
             patch.object(app.urllib.request, 'urlopen', side_effect=AssertionError('No HTTP')) as http, \
             patch('builtins.input', side_effect=AssertionError('No interacción')) as entrada, \
             contextlib.redirect_stdout(io.StringIO()) as salida:
            codigo = app.main()
        modelo.assert_not_called()
        http.assert_not_called()
        entrada.assert_not_called()
        return codigo, salida.getvalue(), comandos, adquirir

    def test_una_adquisicion_cuatro_comandos_fijos(self):
        codigo, texto, comandos, adquirir = self.ejecutar()
        self.assertEqual(codigo, 0)
        adquirir.assert_called_once()
        self.assertEqual([c.args[0] for c in comandos.call_args_list], [list(f[3]) for f in conexiones.FUENTES])
        self.assertTrue(all(0 < c.args[1] <= 15 for c in comandos.call_args_list))
        self.assertIn('Total seleccionado de las cuatro fuentes: 5.', texto)

    def test_parcial_y_error_con_excepciones_privadas(self):
        efectos = [(0, TEXTOS[n], '', False) for n, _, _, _ in conexiones.FUENTES]
        efectos[0] = PermissionError('SECRETO')
        codigo, texto, _, _ = self.ejecutar(efectos)
        self.assertEqual(codigo, 3)
        self.assertNotIn('SECRETO', texto)
        codigo, texto, _, _ = self.ejecutar([FileNotFoundError('SECRETO')]*4)
        self.assertEqual(codigo, 1)
        self.assertNotIn('SECRETO', texto)

    def test_stderr_truncado_y_codigo_no_cero(self):
        for fallo in ((0, TEXTOS['tcp4'], 'SECRETO', False),
                      (0, TEXTOS['tcp4'], '', True), (1, TEXTOS['tcp4'], '', False)):
            efectos = [(0, TEXTOS[n], '', False) for n, _, _, _ in conexiones.FUENTES]
            efectos[0] = fallo
            codigo, texto, _, _ = self.ejecutar(efectos)
            self.assertEqual(codigo, 3)
            self.assertNotIn('SECRETO', texto)
            self.assertIn('recuento desconocido', texto)

    def test_interrupcion_130(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(self.ejecutar([KeyboardInterrupt()])[0], 130)

    def test_flags_excluyentes_sin_adquisicion(self):
        for flag in ('--interfaces-verificadas', '--memoria-verificada',
                     '--conexiones-verificadas', '--permitir-consultas-externas'):
            with contextlib.redirect_stderr(io.StringIO()), \
                 patch.object(app, 'consultar_conexiones_verificadas') as adquirir, \
                 self.assertRaises(SystemExit) as error:
                self.ejecutar(argumentos=(flag,))
            self.assertEqual(error.exception.code, 2)
            adquirir.assert_not_called()

    def test_plazo_global_agotado_no_adquiere(self):
        with patch.object(app, 'MAX_SECONDS', 0):
            codigo, texto, comandos, adquirir = self.ejecutar()
        self.assertEqual(codigo, 1)
        comandos.assert_not_called()
        adquirir.assert_not_called()
        self.assertIn('tiempo agotado', texto)

    def test_deadline_compartido_y_presupuesto_restante(self):
        with patch.object(app.time, 'monotonic', return_value=100):
            codigo, _, comandos, adquirir = self.ejecutar()
        self.assertEqual(codigo, 0)
        adquirir.assert_called_once_with(220)
        self.assertTrue(all(c.args[1] == 15 for c in comandos.call_args_list))

    def test_vencimiento_tras_adquirir_o_presentar_no_publica(self):
        for fase in ('adquirir', 'presentar'):
            reloj = [100.0]
            def tardio(*args, **kwargs):
                reloj[0] = 221
                return original() if fase == 'adquirir' else ('DATOS_TARDIOS', derivado().con_presentacion('completo'))
            with patch.object(app.time, 'monotonic', side_effect=lambda: reloj[0]), \
                 patch.object(app, 'consultar_conexiones_verificadas',
                              side_effect=tardio if fase == 'adquirir' else None, return_value=original()), \
                 patch.object(app, 'informe_puertos',
                              side_effect=tardio if fase == 'presentar' else None), \
                 patch.object(app, 'ejecutar_comando', side_effect=AssertionError('No real')), \
                 contextlib.redirect_stdout(io.StringIO()) as salida:
                self.assertEqual(app.ejecutar_puertos_verificados(), 1)
            self.assertNotIn('DATOS_TARDIOS', salida.getvalue())
            self.assertNotIn('Informe determinista', salida.getvalue())

    def test_presentacion_omitida_codigo_3(self):
        with patch.object(app, 'MAX_OUTPUT', 100):
            self.assertEqual(self.ejecutar()[0], 3)

    def test_conversacion_sin_nueva_ruta(self):
        comandos = copy.deepcopy(app.TOOLS)
        with patch.object(sys, 'argv', ['AsistenteLocal.py']), \
             patch('builtins.input', side_effect=['puertos', 'salir']), \
             patch.object(app, 'preguntar') as preguntar, \
             patch.object(app, 'ejecutar_puertos_verificados') as ejecutar, \
             contextlib.redirect_stdout(io.StringIO()):
            app.main()
        preguntar.assert_called_once_with('puertos')
        ejecutar.assert_not_called()
        self.assertEqual(app.TOOLS, comandos)
        self.assertEqual(app.TOOLS['puertos']['commands'], [['ss', '-lntp'], ['ss', '-lnup']])
