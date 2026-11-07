import contextlib
import copy
import io
import json
import unittest
from unittest.mock import patch

import AsistenteLocal as app
import resultado_verificado as contrato
import control_verificado as control
from interfaces_red import ResultadoInterfaces, OMITIDO, informe_verificado
from memoria import informe_memoria
from test_interfaces_red import datos, fuente, IP, NM
from test_memoria_verificada import normalizar as datos_memoria


class ContratoComun(unittest.TestCase):
    def originales(self):
        return ((contrato.adaptar_interfaces, datos()), (contrato.adaptar_memoria, datos_memoria()))

    def test_ocho_campos_y_dominios_independientes(self):
        i = contrato.adaptar_interfaces(datos()).a_dict()
        m = contrato.adaptar_memoria(datos_memoria()).a_dict()
        for d in (i, m):
            self.assertEqual(set(d), set(contrato.CAMPOS))
            self.assertEqual(d['version'], 1)
            self.assertEqual(d['estado_adquisicion'], 'completo')
            self.assertEqual(d['estado_presentacion'], 'pendiente')
        self.assertEqual(i['datos']['interfaces'], datos()['interfaces'])
        self.assertNotIn('ram', i['datos'])
        self.assertEqual(m['datos']['ram'], datos_memoria()['ram'])
        self.assertEqual(m['datos']['swap'], datos_memoria()['swap'])
        self.assertEqual(m['datos']['actividad_intercambio']['estado'], 'no_medida')
        self.assertNotIn('interfaces', m['datos'])

    def test_roundtrip_exacto_campos_orden_y_extensiones(self):
        for adaptar, original in self.originales():
            with self.subTest(herramienta=original['herramienta']):
                original['extension'] = {'futuro': [None, False, 0, 'á']}
                restaurado = contrato.formato_anterior(adaptar(original))
                self.assertEqual(restaurado, original)
                self.assertEqual(list(restaurado), list(original))
                self.assertEqual(json.dumps(restaurado), json.dumps(original))

    def test_original_y_copias_no_mutan_instantanea(self):
        for adaptar, original in self.originales():
            with self.subTest(herramienta=original['herramienta']):
                esperado = copy.deepcopy(original)
                r = adaptar(original)
                instantanea = r.a_json()
                original.clear()
                copia = r.a_dict()
                copia['datos'].clear()
                copia['fuentes'].clear()
                copia['incidencias'].append({'codigo': 'inventado'})
                self.assertEqual(r.a_json(), instantanea)
                self.assertEqual(contrato.formato_anterior(r), esperado)
                self.assertIsNot(r.a_dict(), r.a_dict())
                with self.assertRaises(AttributeError):
                    r._json = 'mutado'
                with self.assertRaises(AttributeError):
                    del r._json

    def test_presentacion_crea_nueva_instantanea_sin_cambiar_adquisicion(self):
        r = contrato.adaptar_interfaces(datos())
        presentado = r.con_presentacion('parcial')
        self.assertEqual(r.estado_presentacion, 'pendiente')
        self.assertEqual(presentado.estado_presentacion, 'parcial')
        self.assertEqual(presentado.a_dict()['estado_adquisicion'], 'completo')
        self.assertEqual(presentado.a_dict()['datos'], r.a_dict()['datos'])
        self.assertTrue(any(i['fase'] == 'presentacion' and i['codigo'] == 'parcial'
                            for i in presentado.a_dict()['incidencias']))
        self.assertEqual(contrato.formato_anterior(presentado), datos())

    def test_incidentes_memoria_no_pierden_detalle_orden_ni_campos(self):
        original = datos_memoria('MemTotal: 10 kB\nMemAvailable: 20 kB\nSwapTotal: 1 MB\n')
        original['avisos'] = ['primero', 'segundo', 'primero']
        r = contrato.adaptar_memoria(original)
        self.assertEqual(r.a_dict()['estado_adquisicion'], 'parcial')
        incidencias = r.a_dict()['incidencias']
        self.assertEqual([i['detalle'] for i in incidencias if i['codigo'] == 'aviso'], original['avisos'])
        self.assertEqual({i['campo']: i['detalle'] for i in incidencias if i['codigo'] == 'campo_no_utilizable'},
                         original['problemas_campos'])
        self.assertEqual(contrato.formato_anterior(r), original)
        self.assertEqual(list(contrato.formato_anterior(r)['problemas_campos']), list(original['problemas_campos']))

    def test_incidentes_y_fuentes_de_interfaces(self):
        from interfaces_red import normalizar
        original = normalizar({'ip': fuente(IP), 'nmcli': fuente(NM, 'permiso_denegado')})
        r = contrato.adaptar_interfaces(original)
        d = r.a_dict()
        self.assertEqual(d['estado_adquisicion'], 'parcial')
        self.assertEqual(d['fuentes'], original['fuentes'])
        self.assertTrue(any(i.get('fuente') == 'nmcli' and i['fase'] == 'adquisicion' for i in d['incidencias']))
        self.assertEqual(contrato.formato_anterior(r), original)

    def test_omision_previa_no_inventa_adquisicion_completa(self):
        r = contrato.adaptar_interfaces(dict(OMITIDO))
        self.assertEqual(r.a_dict()['estado_adquisicion'], 'desconocido')
        self.assertEqual(r.estado_presentacion, 'pendiente')
        self.assertEqual(contrato.formato_anterior(r), OMITIDO)
        presentado = r.con_presentacion('omitido_por_limite')
        self.assertEqual(presentado.a_dict()['estado_adquisicion'], 'desconocido')
        self.assertEqual(control.codigo_salida(presentado.estado_presentacion), 3)

    def test_fallos_conservan_datos_desconocidos(self):
        from interfaces_red import normalizar
        originales = [
            (contrato.adaptar_interfaces, normalizar({'ip': fuente('', 'tiempo_agotado'),
                                                     'nmcli': fuente('', 'error_comando')})),
            (contrato.adaptar_memoria, datos_memoria('', estado='permiso_denegado')),
        ]
        for adaptar, original in originales:
            with self.subTest(herramienta=original['herramienta']):
                r = adaptar(original)
                self.assertEqual(r.a_dict()['estado_adquisicion'], 'error')
                presentado = r.con_presentacion('error')
                self.assertEqual(control.codigo_salida(presentado.estado_presentacion), 1)
                self.assertEqual(contrato.formato_anterior(presentado), original)

    def test_campos_ausentes_se_conservan_como_ausentes(self):
        for adaptar, original in self.originales():
            with self.subTest(herramienta=original['herramienta']):
                original.pop('avisos', None)
                original.pop('limitaciones', None)
                self.assertEqual(contrato.formato_anterior(adaptar(original)), original)

    def test_adaptadores_rechazan_formatos_ajenos_sin_transformarlos(self):
        for adaptar, original in self.originales():
            for campo, valor in (('version', 2), ('herramienta', 'otra'), ('estado', 'otro')):
                caso = copy.deepcopy(original)
                caso[campo] = valor
                esperado = copy.deepcopy(caso)
                with self.subTest(campo=campo), self.assertRaises(ValueError):
                    adaptar(caso)
                self.assertEqual(caso, esperado)

    def test_validacion_de_version_estados_y_campos(self):
        base = contrato.adaptar_memoria(datos_memoria()).a_dict()
        for clave, valor in (('version', 2), ('version', True), ('herramienta', 'otra'),
                             ('estado_adquisicion', 'inventado'), ('estado_presentacion', 'inventado'),
                             ('fuentes', []), ('datos', []), ('incidencias', {}), ('alcance', [])):
            d = copy.deepcopy(base)
            d[clave] = valor
            with self.subTest(campo=clave, valor=valor), self.assertRaises((ValueError, TypeError)):
                contrato.ResultadoVerificado(d)
        for cambio in ('ausente', 'extra'):
            d = copy.deepcopy(base)
            if cambio == 'ausente':
                del d['version']
            else:
                d['extra'] = 'no admitido'
            with self.assertRaises(ValueError):
                contrato.ResultadoVerificado(d)

    def test_tipos_json_que_perderian_informacion_se_rechazan(self):
        base = contrato.adaptar_memoria(datos_memoria()).a_dict()
        for valor in ((1, 2), {1: 'clave numérica'}, float('nan'), float('inf')):
            d = copy.deepcopy(base)
            d['datos']['extra'] = valor
            with self.subTest(tipo=type(valor).__name__), self.assertRaises((TypeError, ValueError)):
                contrato.ResultadoVerificado(d)

    def test_incidencia_malformada_se_rechaza(self):
        base = contrato.adaptar_memoria(datos_memoria()).a_dict()
        for incidencia in ({}, {'fase': 'otra', 'codigo': 'x', 'detalle': 'y'},
                           {'fase': 'adquisicion', 'codigo': 1, 'detalle': 'y'}):
            base['incidencias'] = [incidencia]
            with self.assertRaises(ValueError):
                contrato.ResultadoVerificado(base)

    def test_serializacion_solo_en_creacion_o_cambio_de_fase(self):
        documento = contrato.adaptar_memoria(datos_memoria()).a_dict()
        original = json.dumps
        with patch.object(contrato.json, 'dumps', wraps=original) as serializar:
            r = contrato.ResultadoVerificado(documento)
            self.assertEqual(serializar.call_count, 1)
            r.a_dict(); r.a_json(); r.estado_presentacion
            self.assertEqual(serializar.call_count, 1)
            p = r.con_presentacion('completo')
            p.a_json(); p.a_dict()
            self.assertIs(p.con_presentacion('completo'), p)
            self.assertEqual(serializar.call_count, 2)
        for estado in ('pendiente', 'otro'):
            with self.assertRaises(ValueError):
                r.con_presentacion(estado)


class CompatibilidadTextual(unittest.TestCase):
    def test_datos_de_resultado_interfaces_son_copia_independiente(self):
        original = datos()
        r = ResultadoInterfaces(original, app.MAX_OUTPUT)
        esperado = str(r)
        original['interfaces'].clear()
        copia = r.datos
        copia['interfaces'].clear()
        self.assertTrue(r.datos['interfaces'])
        self.assertEqual(str(r), esperado)
        self.assertEqual(r.datos, json.loads(r))
        with self.assertRaises(AttributeError):
            r.datos = {}

    def test_constructor_y_ajustar_conservan_json_anterior(self):
        original = datos()
        esperado = json.dumps(original, ensure_ascii=True, separators=(',', ':'), allow_nan=False)
        r = ResultadoInterfaces(original, app.MAX_OUTPUT)
        self.assertIsInstance(r, str)
        self.assertEqual(str(r), esperado)
        self.assertEqual(str(r.ajustar(app.MAX_OUTPUT)), esperado)
        reducido = r.ajustar(app.MIN_JSON)
        self.assertEqual(json.loads(reducido), OMITIDO)
        self.assertEqual(reducido.datos, OMITIDO)

    def test_ajustar_no_se_contamina_por_mutacion_de_copia(self):
        r = ResultadoInterfaces(datos(), app.MAX_OUTPUT)
        copia = r.datos
        copia['estado'] = 'error'
        self.assertEqual(r.ajustar(app.MAX_OUTPUT).datos['estado'], 'completo')

    def test_informes_identicos_en_completos_parciales_fallos_y_omision(self):
        from interfaces_red import normalizar
        originales = [
            (contrato.adaptar_interfaces, informe_verificado, datos()),
            (contrato.adaptar_interfaces, informe_verificado, datos('[{"ifname":"x"}]', '')),
            (contrato.adaptar_interfaces, informe_verificado, normalizar({'ip': fuente('', 'error_comando'), 'nmcli': fuente('', 'error_comando')})),
            (contrato.adaptar_interfaces, informe_verificado, dict(OMITIDO)),
            (contrato.adaptar_memoria, informe_memoria, datos_memoria()),
            (contrato.adaptar_memoria, informe_memoria, datos_memoria('SwapTotal: 100 kB')),
            (contrato.adaptar_memoria, informe_memoria, datos_memoria('', estado='truncada')),
        ]
        for adaptar, presentar, original in originales:
            for limite in (app.MAX_OUTPUT, 100):
                with self.subTest(herramienta=original['herramienta'], estado=original['estado'], limite=limite):
                    self.assertEqual(presentar(contrato.formato_anterior(adaptar(original)), limite=limite),
                                     presentar(original, limite=limite))

    def test_envoltorio_interno_no_impone_limite_adicional_ni_cambia_json_conversacional(self):
        original = datos()
        original['extension'] = ''
        base = len(json.dumps(original, ensure_ascii=True, separators=(',', ':'), allow_nan=False))
        original['extension'] = 'x' * (app.MAX_OUTPUT - base - 1)
        legacy = ResultadoInterfaces(original, app.MAX_OUTPUT)
        self.assertNotEqual(legacy.datos['estado'], 'omitido_por_limite')
        adaptado = contrato.adaptar_interfaces(legacy.datos)
        self.assertEqual(len(legacy), app.MAX_OUTPUT - 1)
        self.assertGreater(len(adaptado.a_json()), app.MAX_OUTPUT)
        self.assertEqual(contrato.formato_anterior(adaptado), legacy.datos)
        self.assertEqual(str(legacy), json.dumps(original, ensure_ascii=True, separators=(',', ':'), allow_nan=False))

    def test_adquisicion_completa_vista_parcial_y_codigos_sin_cambios(self):
        original = datos()
        original['interfaces'] *= 3
        r = contrato.adaptar_interfaces(original)
        _, estado = informe_verificado(contrato.formato_anterior(r))
        final = r.con_presentacion(estado)
        self.assertEqual(final.a_dict()['estado_adquisicion'], 'completo')
        self.assertEqual(final.estado_presentacion, 'parcial')
        self.assertEqual(control.codigo_salida(final.estado_presentacion), 3)


class IntegracionSimuladaContrato(unittest.TestCase):
    def casos(self):
        return (
            (app.ejecutar_interfaces_verificadas, 'ejecutar_consulta', ResultadoInterfaces(datos(), app.MAX_OUTPUT)),
            (app.ejecutar_memoria_verificada, 'consultar_memoria_verificada', datos_memoria()),
        )

    def test_modalidades_entregan_contrato_al_control_sin_http(self):
        original_control = app.ejecutar_verificada
        observados = []
        def observar(adquirir, presentar, **kwargs):
            def adquirir_contrato(deadline):
                r = adquirir(deadline)
                self.assertIsInstance(r, contrato.ResultadoVerificado)
                self.assertEqual(r.estado_presentacion, 'pendiente')
                return r
            def presentar_contrato(r):
                texto, final = presentar(r)
                self.assertIsInstance(final, contrato.ResultadoVerificado)
                observados.append(final)
                return texto, final
            return original_control(adquirir_contrato, presentar_contrato, **kwargs)
        for ejecutar, fuente_nombre, fuente_valor in self.casos():
            with self.subTest(modo=ejecutar.__name__), \
                 patch.object(app, fuente_nombre, return_value=fuente_valor) as fuente_mock, \
                 patch.object(app, 'ejecutar_verificada', side_effect=observar), \
                 patch.object(app, 'consultar_modelo', side_effect=AssertionError('No modelo')) as modelo, \
                 patch.object(app, 'abrir_http_local', side_effect=AssertionError('No HTTP')) as http, \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(ejecutar(), 0)
            fuente_mock.assert_called_once()
            modelo.assert_not_called()
            http.assert_not_called()
        self.assertEqual(len(observados), 2)
        self.assertTrue(all(r.estado_presentacion == 'completo' for r in observados))

    def test_control_admite_pareja_textual_anterior(self):
        with contextlib.redirect_stdout(io.StringIO()) as salida:
            codigo = control.ejecutar_verificada(lambda deadline: None, lambda r: ('ANTERIOR', 'parcial'),
                                                 segundos=120, comprobar_plazo=app.restante,
                                                 mensajes={'interrupcion': 'x', 'timeout': 'y', 'error': 'z'})
        self.assertEqual(codigo, 3)
        self.assertEqual(salida.getvalue(), 'ANTERIOR\n')

    def test_control_no_publica_contrato_pendiente(self):
        r = contrato.adaptar_memoria(datos_memoria())
        with contextlib.redirect_stdout(io.StringIO()) as salida:
            codigo = control.ejecutar_verificada(lambda deadline: r, lambda dato: ('NO_PUBLICAR', dato),
                                                 segundos=120, comprobar_plazo=app.restante,
                                                 mensajes={'interrupcion': 'x', 'timeout': 'y', 'error': 'z'})
        self.assertEqual(codigo, 1)
        self.assertNotIn('NO_PUBLICAR', salida.getvalue())
