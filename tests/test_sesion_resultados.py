"""Colección sobre fixtures; sin adquisiciones ni almacenamiento externo."""
import builtins
import copy
import json
import unittest
from unittest.mock import patch

import sesion_resultados as s
import historial_contratos as h
from informe_exportacion import preparar_informe, validar_informe
from resultado_verificado import adaptar_memoria, adaptar_interfaces
from test_memoria_verificada import normalizar
from test_interfaces_red import datos as interfaces
import test_historial_contratos as fixtures_historial
from test_historial_contratos import debian, apt_error


class Sesion(unittest.TestCase):
    def setUp(self):
        self.ahora = 100.
        self.sesion = s.ColeccionSesion(reloj=lambda: self.ahora)
        self.addCleanup(self.sesion.cerrar)

    def registro(self):
        return h.adaptar_verificado(adaptar_memoria(normalizar()), 'debian13')

    def test_insertar_consultar_y_copias(self):
        r = self.registro()
        original = copy.deepcopy(r)
        ident = self.sesion.insertar_saneado(r)
        r['metricas']['ram_total_bytes'] = None
        entradas = self.sesion.consultar()
        self.assertEqual(entradas[0]['id'], ident)
        self.assertEqual(entradas[0]['registro'], original)
        entradas[0]['registro']['hostname'] = 'privado'
        self.assertNotIn('hostname', self.sesion.consultar()[0]['registro'])

    def test_cinco_modos_verificados_sin_originales(self):
        for resultado in fixtures_historial.Historial().registros():
            self.sesion.insertar_verificado(resultado, 'fedora')
        self.assertEqual(self.sesion.estado()['registros'], 5)
        for entrada in self.sesion.consultar():
            self.assertEqual(h.validar(entrada['registro']), entrada['registro'])
            self.assertEqual(set(entrada), {'id', 'registro', 'observacion'})
        self.assertTrue(all(type(t) is str for t in self.sesion._registros.values()))

    def test_seleccion_en_orden_sin_duplicados(self):
        a = self.sesion.insertar_saneado(self.registro())
        b = self.sesion.insertar_saneado(self.registro())
        self.assertEqual([x['id'] for x in self.sesion.seleccionar([b,a])], [a,b])
        for ids in ([], [a,a], [999], [True], '1'):
            with self.assertRaises(s.ErrorSesion):
                self.sesion.seleccionar(ids)

    def test_limites_atomicamente_sin_perdida(self):
        self.sesion.insertar_saneado(self.registro())
        anterior = self.sesion.consultar()
        with patch.object(s, 'MAX_REGISTROS', 1):
            with self.assertRaises(s.ErrorSesion):
                self.sesion.insertar_saneado(self.registro())
        with patch.object(s, 'MAX_BYTES', self.sesion.estado()['bytes_serializados']):
            with self.assertRaises(s.ErrorSesion):
                self.sesion.insertar_saneado(self.registro())
        self.assertEqual(self.sesion.consultar(), anterior)

    def test_vaciado_y_no_reutilizacion_id(self):
        a = self.sesion.insertar_saneado(self.registro())
        self.sesion.vaciar()
        self.assertEqual(self.sesion.consultar(), [])
        self.assertEqual(self.sesion.estado()['bytes_serializados'], 0)
        b = self.sesion.insertar_saneado(self.registro())
        self.assertGreater(b, a)
        with self.assertRaises(s.ErrorSesion):
            self.sesion.seleccionar([a])

    def test_caducidad_no_se_renueva_y_purga(self):
        self.sesion.insertar_saneado(self.registro())
        self.ahora += 1700
        self.sesion.vaciar()
        self.sesion.insertar_saneado(self.registro())
        self.ahora = 100+s.VIDA_SEGUNDOS
        with self.assertRaises(s.ErrorSesion):
            self.sesion.consultar()
        self.assertEqual(self.sesion._registros, {})
        with self.assertRaises(s.ErrorSesion):
            self.sesion.insertar_saneado(self.registro())

    def test_retroceso_y_reloj_invalido_purgan(self):
        for ahora in (99., float('nan'), float('inf'), True):
            self.ahora = 100.
            coleccion = s.ColeccionSesion(reloj=lambda: self.ahora)
            coleccion.insertar_saneado(self.registro())
            self.ahora = ahora
            with self.assertRaises(s.ErrorSesion):
                coleccion.consultar()
            self.assertEqual(coleccion._registros, {})

    def test_rechaza_textos_no_validados_y_campos_privados(self):
        for r in ('salida privada', {'stdout': 'privado'}, self.registro() | {'hostname':'privado'}):
            with self.assertRaisesRegex(s.ErrorSesion, '^registro_no_valido$'):
                self.sesion.insertar_saneado(r)
        with self.assertRaises(s.ErrorSesion):
            self.sesion.insertar_verificado('texto', 'debian13')
        self.assertEqual(self.sesion.consultar(), [])

    def test_privacidad_interfaces_y_no_hashes(self):
        d = adaptar_interfaces(interfaces()).a_dict()
        d['datos']['interfaces'][0]['nombre'] = '/privado/usuario host 192.0.2.1'
        from resultado_verificado import ResultadoVerificado
        self.sesion.insertar_verificado(ResultadoVerificado(d), 'debian13')
        almacen = ''.join(self.sesion._registros.values())
        self.assertNotIn('privado', almacen)
        self.assertNotIn('192.0.2.1', almacen)
        self.assertNotIn('hash', almacen)

    def test_fechas_solo_explicitamente_verificadas(self):
        ident = self.sesion.insertar_saneado(self.registro())
        self.assertIsNone(self.sesion.seleccionar([ident])[0]['observacion'])
        obs = dict(fecha_utc='2026-11-05T12:00:00Z', verificada=True)
        ident = self.sesion.insertar_saneado(self.registro(), observacion=obs)
        obs['fecha_utc'] = 'privado'
        self.assertEqual(self.sesion.seleccionar([ident])[0]['observacion']['fecha_utc'], '2026-11-05T12:00:00Z')
        for obs in ({'fecha_utc':'ayer', 'verificada':True}, {'fecha_utc':'2026-11-05T12:00:00Z','verificada':False}):
            with self.assertRaises(s.ErrorSesion):
                self.sesion.insertar_saneado(self.registro(), observacion=obs)

    def test_desconocido_no_recogida_y_preparacion_posterior(self):
        r = self.registro()
        r['metricas']['ram_libre_bytes'] = None
        del r['metricas']['swap_ocupada_bytes']
        ident = self.sesion.insertar_saneado(r)
        seleccion = self.sesion.seleccionar([ident])
        d = preparar_informe([x['registro'] for x in seleccion], fecha_preparacion_utc='2026-11-05T12:00:00Z',
                             observaciones=[x['observacion'] for x in seleccion])
        m = {m['identificador']:m for m in d['resultados'][0]['metricas']}
        self.assertEqual(m['ram_libre_bytes']['estado_valor'], 'desconocido')
        self.assertEqual(m['swap_ocupada_bytes']['estado_valor'], 'no_recogida')
        self.assertEqual(validar_informe(d), d)

    def test_dpkg_y_apt_independientes(self):
        d = debian(2)
        d.update(estado_inventario='completo', estado_adquisicion='parcial', actualizaciones=apt_error())
        ident = self.sesion.insertar_saneado(h.adaptar_auditoria(d, 'debian13'))
        r = self.sesion.seleccionar([ident])[0]['registro']
        self.assertEqual(r['componentes']['dpkg']['ejecucion'], 'correcto')
        self.assertEqual(r['componentes']['apt']['ejecucion'], 'error')
        self.assertIsNone(r['metricas']['apt_total_posibles'])

    def test_cerrar_y_limites_del_contrato(self):
        r = self.registro()
        r['version'] = 2
        with self.assertRaises(s.ErrorSesion):
            self.sesion.insertar_saneado(r)
        self.sesion.cerrar()
        with self.assertRaises(s.ErrorSesion):
            self.sesion.consultar()

    def test_sin_io_sqlite_exportacion_ni_adquisiciones(self):
        r = self.registro()
        importar = builtins.__import__
        def comprobar(nombre, *a, **kw):
            if 'sqlite' in nombre or nombre in ('exportacion_escritor', 'historial_controlador', 'historial_persistente'):
                raise AssertionError('dependencia no permitida')
            return importar(nombre, *a, **kw)
        with patch('builtins.__import__', side_effect=comprobar), \
             patch('builtins.open', side_effect=AssertionError('archivo')), \
             patch('os.open', side_effect=AssertionError('descriptor')), \
             patch('os.mkdir', side_effect=AssertionError('directorio')), \
             patch('subprocess.Popen', side_effect=AssertionError('adquisicion')):
            ident = self.sesion.insertar_saneado(r)
            self.sesion.seleccionar([ident])
            self.sesion.consultar()
            self.sesion.vaciar()
