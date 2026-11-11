# El protocolo assistant/tool se prueba directamente; el router público se cubre en test_operaciones_locales.
import contextlib
import copy
import io
import json
from pathlib import Path
import time
import unittest
from unittest.mock import patch

import AsistenteLocal as app
from interfaces_red import normalizar, resumen, ResultadoInterfaces, MIN_JSON

FIXTURES = Path(__file__).parent / 'fixtures'
IP = (FIXTURES / 'interfaces_ip.json').read_text()
NM = (FIXTURES / 'interfaces_nm.txt').read_text()


def fuente(texto, estado='correcta'):
    return {'estado': estado, 'codigo': 0, 'stdout': texto, 'stderr': ''}


def datos(ip=IP, nm=NM):
    return normalizar({'ip': fuente(ip), 'nmcli': fuente(nm)})


def respuesta(llamadas=None, texto=None):
    return {'choices': [{'message': {'role': 'assistant', 'content': texto,
                                    'tool_calls': llamadas or []}}]}


def llamada(nombre='interfaces_red', ident='a'):
    return {'id': ident, 'type': 'function', 'function': {'name': nombre, 'arguments': '{}'}}


class InterfacesNormalizacion(unittest.TestCase):
    def test_estados_separados_sin_deducir_radio(self):
        resultado = datos()
        self.assertEqual(resultado['estado'], 'completo')
        lo, cable, wifi = resultado['interfaces']
        self.assertEqual((cable['administrativo'], cable['operativo']), ('UP', 'DOWN'))
        self.assertEqual((wifi['administrativo'], wifi['operativo']), ('DOWN', 'DOWN'))
        self.assertEqual(lo['operativo'], 'UNKNOWN')
        for interfaz in resultado['interfaces']:
            self.assertEqual(interfaz['radio'], 'desconocida')
            self.assertEqual(interfaz['conectividad'], 'no_comprobada')
        self.assertEqual(cable['networkmanager']['estado_observado'], 'disconnected')
        self.assertEqual(resultado['alcance']['interfaces_enumeradas_ip'], 3)
        self.assertNotIn('apagada', resumen(resultado))
        self.assertIn('no equivale a interfaces activas', resumen(resultado))

    def test_ausentes_no_se_convierten_en_down_o_cero(self):
        resultado = datos('[{"ifname":"x"}]', 'x:ethernet::')
        interfaz = resultado['interfaces'][0]
        self.assertEqual(resultado['estado'], 'parcial')
        self.assertEqual(interfaz['administrativo'], 'desconocido')
        self.assertEqual(interfaz['operativo'], 'desconocido')
        self.assertIsNone(interfaz['contadores']['rx']['bytes'])
        self.assertIsNone(interfaz['networkmanager']['estado_observado'])
        self.assertIsNone(interfaz['networkmanager']['conexion_observada'])

    def test_ceros_medidos_y_contadores_acumulados(self):
        resultado = datos()
        self.assertEqual(resultado['interfaces'][0]['contadores']['rx']['bytes'], 0)
        self.assertEqual(resultado['interfaces'][1]['contadores']['rx']['bytes'], 12000)
        self.assertIn('acumulados, no velocidades', resumen(resultado))

    def test_contadores_invalidos_y_banderas_invalidas(self):
        for invalido in (False, -1, '0', 2.5, None):
            with self.subTest(valor=invalido):
                filas = json.loads(IP)
                filas[0]['stats64']['rx']['bytes'] = invalido
                filas[0]['flags'] = None
                resultado = datos(json.dumps(filas))
                self.assertIsNone(resultado['interfaces'][0]['contadores']['rx']['bytes'])
                self.assertEqual(resultado['interfaces'][0]['administrativo'], 'desconocido')
                self.assertEqual(resultado['estado'], 'parcial')

    def test_estados_operativos_no_se_reinterpretan(self):
        for estado in ('DORMANT', 'UNKNOWN', 'NUEVO_ESTADO'):
            with self.subTest(estado=estado):
                filas = json.loads(IP)
                filas[0]['operstate'] = estado
                resultado = datos(json.dumps(filas))
                self.assertEqual(resultado['interfaces'][0]['operativo'], estado)
                self.assertEqual(resultado['interfaces'][0]['conectividad'], 'no_comprobada')

    def test_contadores_stats_compatibles_sin_stats64(self):
        filas = json.loads(IP)
        for fila in filas:
            fila['stats'] = fila.pop('stats64')
        resultado = datos(json.dumps(filas))
        self.assertEqual(resultado['estado'], 'completo')
        self.assertEqual(resultado['interfaces'][1]['contadores']['rx']['bytes'], 12000)

    def test_escapes_networkmanager(self):
        cable = datos()['interfaces'][1]
        self.assertEqual(cable['networkmanager']['conexion_observada'], 'Perfil: oficina\\prueba')

    def test_formato_invalido_descarta_toda_fuente(self):
        for invalido in ('{', '{}', '[{"ifname":"x"}, {}]',
                         '[{"ifname":"x"}, {"ifname":"x"}]'):
            with self.subTest(ip=invalido):
                resultado = datos(invalido)
                self.assertEqual(resultado['fuentes']['ip']['estado'], 'formato_invalido')
                self.assertIsNone(resultado['alcance']['interfaces_enumeradas_ip'])
                self.assertEqual(resultado['estado'], 'parcial')
                self.assertTrue(all(i['administrativo'] == 'desconocido'
                                    for i in resultado['interfaces']))

    def test_json_ambiguo_o_no_estandar_rechazado(self):
        for invalido in ('[{"ifname":"x","ifname":"y"}]',
                         '[{"ifname":"x","extra":NaN}]'):
            with self.subTest(ip=invalido):
                resultado = datos(invalido)
                self.assertEqual(resultado['fuentes']['ip']['estado'], 'formato_invalido')
                self.assertIsNone(resultado['alcance']['interfaces_enumeradas_ip'])

    def test_nm_invalido_descarta_toda_fuente(self):
        for nm in ('lo:loopback:up:lo\nfila incorrecta', 'x:wifi:up:escape\\',
                   'x:wifi:up:uno\nx:wifi:down:dos'):
            with self.subTest(nm=nm):
                resultado = datos(nm=nm)
                self.assertEqual(resultado['fuentes']['nmcli']['estado'], 'formato_invalido')
                self.assertTrue(all(i['networkmanager'] is None for i in resultado['interfaces']))

    def test_fuente_truncada_no_se_parsea_aunque_json_valido(self):
        resultado = normalizar({'ip': fuente(IP, 'truncada'), 'nmcli': fuente(NM)})
        self.assertEqual(resultado['estado'], 'parcial')
        self.assertIsNone(resultado['alcance']['interfaces_enumeradas_ip'])
        self.assertTrue(all(i['contadores']['rx']['bytes'] is None for i in resultado['interfaces']))

    def test_ambas_fuentes_fallidas_no_equivale_a_listado_vacio(self):
        resultado = normalizar({'ip': fuente(IP, 'error_comando'),
                               'nmcli': fuente(NM, 'permiso_denegado')})
        self.assertEqual(resultado['estado'], 'error')
        self.assertEqual(resultado['interfaces'], [])
        self.assertIsNone(resultado['alcance']['interfaces_enumeradas_ip'])
        self.assertIn('no deducir ausencia', resumen(resultado))
        self.assertIn('cantidad de interfaces desconocida', resumen(resultado))
        self.assertNotIn('Registros observados entre fuentes: 0', resumen(resultado))

    def test_listado_vacio_real(self):
        resultado = datos('[]', '')
        self.assertEqual(resultado['estado'], 'completo')
        self.assertEqual(resultado['alcance']['interfaces_enumeradas_ip'], 0)

    def test_fuentes_distintas_no_son_instantanea_atomica(self):
        resultado = datos(nm=NM + 'nuevo:wifi:unavailable:\n')
        self.assertEqual(resultado['estado'], 'parcial')
        self.assertEqual(resultado['alcance']['interfaces_enumeradas_ip'], 3)
        self.assertEqual(len(resultado['interfaces']), 4)
        self.assertEqual(resultado['interfaces'][-1]['administrativo'], 'desconocido')

    def test_normalizacion_no_muta_entradas(self):
        fuentes = {'ip': fuente(IP), 'nmcli': fuente(NM)}
        originales = copy.deepcopy(fuentes)
        normalizar(fuentes)
        self.assertEqual(fuentes, originales)

    def test_serializacion_siempre_integra_y_omision_explicita(self):
        resultado = ResultadoInterfaces(datos(), app.MAX_OUTPUT)
        self.assertEqual(json.loads(resultado)['estado'], 'completo')
        reducido = resultado.ajustar(MIN_JSON)
        self.assertLessEqual(len(reducido), MIN_JSON)
        self.assertEqual(json.loads(reducido)['estado'], 'omitido_por_limite')
        self.assertIn('no es un listado vacío', resumen(reducido.datos))
        with self.assertRaises(ValueError):
            resultado.ajustar(MIN_JSON - 1)

    def test_resumen_breve_escapa_controles_y_limita_registros(self):
        filas = json.loads(IP)
        filas[0]['ifname'] = 'nombre\n\x1b\u202e'
        resultado = datos(json.dumps(filas), '')
        texto = resumen(resultado)
        self.assertNotIn('\x1b', texto)
        self.assertNotIn('\u202e', texto)
        self.assertIn('\\n', texto)
        grandes = datos(json.dumps([{'ifname': 'x' * 100 + str(i)} for i in range(100)]), '')
        self.assertLess(len(resumen(grandes)), 2000)
        self.assertIn('se muestran seis', resumen(grandes))


class InterfacesAplicacion(unittest.TestCase):
    def ejecutar(self, efectos):
        with patch.object(app, 'ejecutar_comando', side_effect=efectos) as comando:
            resultado = app.ejecutar_consulta('interfaces_red')
        return resultado, comando

    def test_comandos_fijos_y_limites(self):
        resultado, comando = self.ejecutar([(0, IP, '', False), (0, NM, '', False)])
        self.assertIsInstance(resultado, ResultadoInterfaces)
        self.assertEqual(comando.call_args_list[0].args[0], ['ip', '-j', '-s', 'link', 'show'])
        self.assertIn('--escape', comando.call_args_list[1].args[0])
        self.assertTrue(all(c.args[1] <= 15 for c in comando.call_args_list))
        self.assertLessEqual(len(resultado), app.MAX_OUTPUT)

    def test_fallos_parciales_nm_conserva_ip(self):
        for fallo, estado in [(FileNotFoundError(), 'ejecutable_o_interprete_ausente'),
                              (PermissionError(), 'permiso_denegado'),
                              (TimeoutError(), 'tiempo_agotado')]:
            with self.subTest(fallo=type(fallo).__name__):
                resultado, _ = self.ejecutar([(0, IP, '', False), fallo])
                dato = json.loads(resultado)
                self.assertEqual(dato['estado'], 'parcial')
                self.assertEqual(dato['fuentes']['nmcli']['estado'], estado)
                self.assertEqual(dato['interfaces'][1]['contadores']['rx']['bytes'], 12000)

    def test_ip_falla_nm_conserva_solo_lo_observado(self):
        resultado, comando = self.ejecutar([PermissionError(), (0, NM, '', False)])
        dato = json.loads(resultado)
        self.assertEqual(comando.call_count, 2)
        self.assertIsNone(dato['alcance']['interfaces_enumeradas_ip'])
        self.assertIsNone(dato['interfaces'][0]['contadores']['rx']['bytes'])

    def test_no_interpreta_salida_truncada_o_codigo_no_cero(self):
        for codigo, truncado, estado in [(0, True, 'truncada'), (1, False, 'error_comando')]:
            with self.subTest(estado=estado):
                resultado, _ = self.ejecutar([(codigo, IP, '', truncado), (0, NM, '', False)])
                self.assertEqual(json.loads(resultado)['fuentes']['ip']['estado'], estado)
                self.assertIsNone(json.loads(resultado)['interfaces'][0]['contadores']['rx']['bytes'])

    def test_avisos_no_se_presentan_como_completo(self):
        resultado, _ = self.ejecutar([(0, IP, 'aviso' * 1000, False), (0, NM, '', False)])
        dato = json.loads(resultado)
        self.assertEqual(dato['estado'], 'parcial')
        self.assertTrue(dato['fuentes']['ip']['avisos_recortados'])
        self.assertEqual(len(dato['fuentes']['ip']['stderr']), 500)

    def test_deadline_no_inicia_procesos_fuera_de_plazo(self):
        with patch.object(app, 'ejecutar_comando') as comando, self.assertRaises(TimeoutError):
            app.ejecutar_consulta('interfaces_red', time.monotonic() - 1)
        comando.assert_not_called()

    def test_deadline_entre_fuentes_no_inicia_segundo_comando(self):
        with patch.object(app, 'restante', side_effect=[10, 1, TimeoutError()]), \
             patch.object(app, 'ejecutar_comando', return_value=(0, IP, '', False)) as comando:
            resultado = json.loads(app.ejecutar_consulta('interfaces_red'))
        self.assertEqual(comando.call_count, 1)
        self.assertEqual(resultado['fuentes']['nmcli']['estado'], 'tiempo_agotado')
        self.assertEqual(resultado['estado'], 'parcial')

    def test_hechos_visibles_aunque_falle_respuesta_del_modelo(self):
        with patch.object(app, 'consultar_modelo', side_effect=[respuesta([llamada()]), TimeoutError()]), \
             patch.object(app, 'ejecutar_consulta', return_value=ResultadoInterfaces(datos(), app.MAX_OUTPUT)), \
             contextlib.redirect_stdout(io.StringIO()) as salida:
            app._preguntar_con_herramientas('interfaces')
        self.assertIn('Hechos de interfaces_red', salida.getvalue())
        self.assertIn('Radio: desconocida', salida.getvalue())
        self.assertIn('interpretación de LM Studio no está disponible', salida.getvalue())

    def conversar(self, resultado, final='La Wi-Fi está apagada.'):
        respuestas = [respuesta([llamada()]), respuesta(texto=final)]
        with patch.object(app, 'consultar_modelo', side_effect=respuestas) as modelo, \
             patch.object(app, 'ejecutar_consulta', return_value=resultado), \
             contextlib.redirect_stdout(io.StringIO()) as salida:
            app._preguntar_con_herramientas('Revisa interfaces')
        mensajes = modelo.call_args.args[0]
        contenido = next(m['content'] for m in mensajes if m['role'] == 'tool')
        return salida.getvalue(), contenido

    def test_modelo_recibe_json_y_no_puede_cambiar_hechos(self):
        resultado = ResultadoInterfaces(datos(), app.MAX_OUTPUT)
        salida, contenido = self.conversar(resultado)
        self.assertEqual(json.loads(contenido), resultado.datos)
        bloque, interpretacion = salida.split('Interpretación del modelo', 1)
        self.assertIn('Hechos de interfaces_red (calculados por Python)', bloque)
        self.assertIn('administrativo=UP; operativo="DOWN"', bloque)
        self.assertIn('Radio: desconocida', bloque)
        self.assertNotIn('apagada', bloque)
        self.assertIn('apagada', interpretacion)
        self.assertIn('no verificada', interpretacion)
        self.assertNotIn('"contadores":', salida)

    def test_presupuesto_restante_reemplaza_json_no_lo_corta(self):
        with patch.object(app, 'MAX_TOTAL_OUTPUT', MIN_JSON):
            salida, contenido = self.conversar(ResultadoInterfaces(datos(), app.MAX_OUTPUT))
        self.assertEqual(json.loads(contenido)['estado'], 'omitido_por_limite')
        self.assertIn('datos omitidos por presupuesto', salida)
        self.assertNotIn('administrativo=UP', salida)

    def test_presupuesto_insuficiente_no_ejecuta(self):
        with patch.object(app, 'MAX_TOTAL_OUTPUT', MIN_JSON - 1), \
             patch.object(app, 'consultar_modelo', side_effect=[respuesta([llamada()]), respuesta(texto='Fin')]), \
             patch.object(app, 'ejecutar_consulta') as consulta, contextlib.redirect_stdout(io.StringIO()):
            app._preguntar_con_herramientas('interfaces')
        consulta.assert_not_called()

    def test_gran_resultado_se_omite_antes_de_entregarse(self):
        filas = json.dumps([{'ifname': 'x' * 120 + str(i)} for i in range(200)])
        resultado, _ = self.ejecutar([(0, filas, '', False), (0, '', '', False)])
        self.assertLessEqual(len(resultado), app.MAX_OUTPUT)
        self.assertEqual(json.loads(resultado)['estado'], 'omitido_por_limite')

    def test_limite_global_compartido_con_otras_herramientas(self):
        limite_total = 6000
        respuestas = [respuesta([llamada('disco', '1'), llamada(ident='2')]), respuesta(texto='Fin')]
        with patch.object(app, 'MAX_TOTAL_OUTPUT', limite_total), \
             patch.object(app, 'consultar_modelo', side_effect=respuestas) as modelo, \
             patch.object(app, 'ejecutar_consulta', side_effect=[
                 'd' * 5500, ResultadoInterfaces(datos(), app.MAX_OUTPUT)]), \
             contextlib.redirect_stdout(io.StringIO()):
            app._preguntar_con_herramientas('disco e interfaces')
        contenidos = [m['content'] for m in modelo.call_args.args[0] if m['role'] == 'tool']
        self.assertLessEqual(sum(map(len, contenidos)), limite_total)
        self.assertEqual(json.loads(contenidos[1])['estado'], 'omitido_por_limite')

    def test_avisos_de_integracion_adaptados_al_nuevo_formato(self):
        from evidencia_local import comprobar
        self.assertIn('3 interfaces', comprobar('interfaces_red', ResultadoInterfaces(datos(), app.MAX_OUTPUT)))
        parcial = datos('[{"ifname":"x"}]', '')
        with self.assertRaises(AssertionError):
            comprobar('interfaces_red', ResultadoInterfaces(parcial, app.MAX_OUTPUT))

    def test_otras_herramientas_conservan_presentacion(self):
        with patch.object(app, 'consultar_modelo', side_effect=[respuesta([llamada('disco')]), respuesta(texto='Fin')]), \
             patch.object(app, 'ejecutar_consulta', return_value='Informe disco'), \
             contextlib.redirect_stdout(io.StringIO()) as salida:
            app._preguntar_con_herramientas('disco')
        self.assertNotIn('Hechos de interfaces_red', salida.getvalue())
        self.assertIn('Interpretación del modelo', salida.getvalue())
        self.assertIn('Herramienta | Informe disco', salida.getvalue())
        self.assertIn('Asistente: Fin', salida.getvalue())
