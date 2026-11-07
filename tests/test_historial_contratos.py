"""Contratos históricos sobre fixtures; sin adquisiciones ni persistencia."""
import copy
import json
import unittest
from unittest.mock import patch
import historial_contratos as h
from resultado_verificado import adaptar_memoria, adaptar_interfaces, ResultadoVerificado
from test_memoria_verificada import normalizar as memoria
from test_interfaces_red import datos as interfaces
from test_conexiones_verificadas import fuentes
from conexiones import normalizar_conexiones
from puertos import derivar_puertos
from servicios import normalizar_servicios
from auditoria_seguridad import normalizar as fedora


def debian(v=1):
    return dict(version=v, backend='debian', herramienta='auditoria_seguridad',
        alcance='inventario_local_dpkg', estado_seguridad='no_evaluada',
        estado_adquisicion='completo', inventario_completo=True, inventario_dpkg=[],
        fuente={'nombre': 'dpkg-query'}, recuentos_recogidos=dict(instalado=3078,
        incompleto=0, residual=0, no_instalado=0), total_instalados=3078,
        actualizaciones='no_implementado', cve='no_disponible', avisos_seguridad='no_disponible',
        limitaciones=[])


def apt_error():
    return dict(version=1, fuente='apt_pkg.Policy', estado_adquisicion='error', motivo='error',
        codigo=72, duracion_s=0.1, bytes=0, stderr_bytes=40, indices=None, candidatos=[],
        recuentos_recogidos=dict(registros=0, superiores=0, retenidos=0, posibles=0), total_posibles=None, instalabilidad='no_comprobada',
        seguridad='no_evaluada', limitaciones=[])


def fedora_error():
    return fedora({k: dict(estado='error_comando', codigo=1, stdout='') for k in
                   ('uname', 'rpm', 'kernels', 'pendientes', 'instalados')})


class Historial(unittest.TestCase):
    def registros(self):
        sockets = normalizar_conexiones(fuentes())
        return [adaptar_memoria(memoria()), adaptar_interfaces(interfaces()), sockets,
                derivar_puertos(sockets), normalizar_servicios(dict(estado='correcta', codigo=0, stdout=''))]

    def test_contratos_reales_normalizados_y_versiones(self):
        for origen in self.registros():
            for distro in ('fedora', 'debian13'):
                r = h.adaptar_verificado(origen, distro)
                self.assertEqual(h.validar(r), r)
                self.assertEqual(r['ejecucion'], 'correcto')
                self.assertEqual(r['version_adaptador'], 1)
                self.assertEqual(r['version_metricas'], 1)
                self.assertNotEqual(r['procedencia'], 'estado_declarado_v1')

    def test_metricas_memoria_bytes_y_no_actividad(self):
        r = h.adaptar_verificado(adaptar_memoria(memoria()), 'debian13')
        self.assertEqual(r['metricas']['ram_total_bytes'], 32768*1024)
        self.assertEqual(set(r['metricas']), set(h.MEMORIA))

    def test_servicios_y_sockets_sin_identidades(self):
        for origen in self.registros()[2:]:
            r = h.adaptar_verificado(origen, 'fedora')
            self.assertEqual(len(r['metricas']), 1)
            self.assertTrue(all(type(v) is int for v in r['metricas'].values()))
        r = h.adaptar_verificado(self.registros()[-1], 'fedora')
        self.assertEqual(r['metricas']['servicios_fallidos'], 0)

    def test_error_desconocido_no_se_convierte_en_cero(self):
        d = adaptar_memoria(memoria()).a_dict()
        d['estado_adquisicion'] = 'error'
        r = h.adaptar_verificado(ResultadoVerificado(d), 'fedora')
        self.assertTrue(all(v is None for v in r['metricas'].values()))
        self.assertEqual(r['calidad'], 'no_disponible')

    def test_parcial_y_presentacion_independientes(self):
        d = adaptar_memoria(memoria()).a_dict()
        d['estado_adquisicion'] = 'parcial'
        d['estado_presentacion'] = 'error'
        d['datos']['ram']['libre_bytes'] = None
        r = h.adaptar_verificado(ResultadoVerificado(d), 'fedora')
        self.assertEqual(r['ejecucion'], 'parcial')
        self.assertIsNone(r['metricas']['ram_libre_bytes'])
        self.assertIsNotNone(r['metricas']['ram_total_bytes'])

    def test_privacidad_no_referencias_ni_hashes(self):
        d = adaptar_interfaces(interfaces()).a_dict()
        secreto = '/privado/usuario 192.0.2.1 aa:bb:cc:dd:ee:ff host-secreto'
        d['datos']['interfaces'][0]['nombre'] = secreto
        d['incidencias'] = [dict(fase='adquisicion', codigo='aviso', detalle=secreto)]
        origen = ResultadoVerificado(d)
        antes = origen.a_json()
        r = h.adaptar_verificado(origen, 'debian13')
        self.assertEqual(origen.a_json(), antes)
        self.assertNotIn('privado', json.dumps(r))
        self.assertNotIn('192.0.2.1', json.dumps(r))
        self.assertNotIn('host-secreto', json.dumps(r))
        self.assertEqual(set(r['metricas']), {'interfaces_enumeradas_ip'})

    def test_rechaza_texto_y_dict_en_modo_verificado(self):
        for origen in ('ESTADO CORRECTA', '{}', {'version': 1}):
            with self.assertRaises(ValueError):
                h.adaptar_verificado(origen, 'fedora')

    def test_estados_sin_metricas_para_las_14(self):
        self.assertEqual(len(h.HERRAMIENTAS), 14)
        for herramienta in h.HERRAMIENTAS:
            for estado in h.EJECUCION:
                r = h.estado_conocido(herramienta, 'debian13', estado)
                self.assertEqual(r['metricas'], {})
                self.assertNotEqual(r['calidad'], 'verificada')
        with self.assertRaises(ValueError):
            h.estado_conocido('sistema', 'ubuntu', 'correcto')

    def test_debian_v1_separa_dpkg_y_apt(self):
        r = h.adaptar_auditoria(debian(), 'debian13')
        self.assertEqual(r['metricas']['dpkg_total_instalados'], 3078)
        self.assertEqual(r['componentes']['dpkg']['ejecucion'], 'correcto')
        self.assertEqual(r['componentes']['apt']['ejecucion'], 'no_ejecutado')
        self.assertEqual(r['cobertura'], 'no_verificada')

    def test_debian_v2_error_apt_no_borra_dpkg(self):
        d = debian(2)
        d.update(estado_inventario='completo', estado_adquisicion='parcial', actualizaciones=apt_error())
        r = h.adaptar_auditoria(d, 'debian13')
        self.assertEqual(r['metricas']['dpkg_total_instalados'], 3078)
        self.assertIsNone(r['metricas']['apt_total_posibles'])
        self.assertEqual(r['componentes']['apt']['ejecucion'], 'error')
        self.assertEqual(r['ejecucion'], 'parcial')

    def test_debian_parcial_recuentos_recogidos(self):
        d = debian()
        d.update(inventario_completo=False, estado_adquisicion='parcial', inventario_dpkg=[dict(nombre_binario='privado', arquitectura='amd64', version='1',
            estado_instalacion='install ok installed', categoria='instalado', nombre_fuente=None, version_fuente=None)])
        r = h.adaptar_auditoria(d, 'debian13')
        self.assertIsNone(r['metricas']['dpkg_total_instalados'])
        self.assertEqual(r['metricas']['dpkg_instalados'], 3078)

    def test_fedora_estado_y_desconocidos(self):
        r = h.adaptar_auditoria(fedora_error(), 'fedora')
        self.assertEqual(r['ejecucion'], 'error')
        self.assertIsNone(r['metricas']['paquetes_rpm'])
        self.assertIsNone(r['metricas']['avisos_pendientes'])
        self.assertEqual(r['procedencia'], 'fedora_auditoria_v1')

    def test_claves_desconocidas(self):
        d = adaptar_memoria(memoria()).a_dict()
        d['datos']['usuario'] = 'secreto'
        with self.assertRaisesRegex(ValueError, '^contrato_historico_invalido$'):
            h.adaptar_verificado(ResultadoVerificado(d), 'fedora')
        for clave in ('usuario', 'version_futura'):
            d = debian()
            d[clave] = 'privado'
            with self.assertRaises(ValueError):
                h.adaptar_auditoria(d, 'debian13')
        r = h.estado_conocido('sistema', 'fedora', 'correcto')
        r['usuario'] = 'privado'
        with self.assertRaises(ValueError):
            h.validar(r)

    def test_tipos_numericos_y_no_finitos(self):
        for valor in (True, -1, '12', 1.5, float('nan'), float('inf'), 2**63):
            d = adaptar_memoria(memoria()).a_dict()
            d['datos']['ram']['total_bytes'] = valor
            with self.assertRaises(ValueError):
                h.adaptar_verificado(ResultadoVerificado(d), 'fedora')

    def test_versiones_procedencia_y_mutacion(self):
        r = h.estado_conocido('sistema', 'fedora', 'correcto')
        for clave, valor in (('version', 2), ('version_metricas', True),
                             ('procedencia', '/privado'), ('ejecucion', 'seguro')):
            otro = copy.deepcopy(r)
            otro[clave] = valor
            with self.assertRaises(ValueError):
                h.validar(otro)
        copia = h.validar(r)
        copia['metricas']['privado'] = 1
        self.assertEqual(r['metricas'], {})

    def test_limites_entrada_salida_profundidad(self):
        with patch.object(h, 'MAX_LISTA', 1):
            with self.assertRaises(ValueError):
                h.adaptar_auditoria(debian(), 'debian13')
        with patch.object(h, 'MAX_ORIGEN_BYTES', 10):
            with self.assertRaises(ValueError):
                h.adaptar_auditoria(debian(), 'debian13')
        with patch.object(h, 'MAX_REGISTRO_BYTES', 10):
            with self.assertRaises(ValueError):
                h.estado_conocido('sistema', 'fedora', 'correcto')
        d = debian()
        d['limitaciones'] = ['x'*(h.MAX_TEXTO+1)]
        with self.assertRaises(ValueError):
            h.adaptar_auditoria(d, 'debian13')
        for _ in range(18):
            d = [d]
        with self.assertRaises(ValueError):
            h._limitar(d)

    def test_sin_io_ni_persistencia(self):
        origen = adaptar_memoria(memoria())
        with patch('builtins.open', side_effect=AssertionError('escritura')), \
             patch('subprocess.Popen', side_effect=AssertionError('adquisicion')):
            r = h.adaptar_verificado(origen, 'fedora')
            self.assertEqual(h.validar(r), r)


class RegresionesHistorial(unittest.TestCase):
    def test_fedora_parcial_y_exclusion_de_paquetes(self):
        d = fedora_error()
        d.update(estado_adquisicion='parcial', inventario_rpm=[dict(nombre='paquete-privado',
            epoch=0, version='1', release='1', arquitectura='x86_64')])
        d['recuentos']['paquetes_rpm_recogidos'] = 1
        r = h.adaptar_auditoria(d, 'fedora')
        self.assertEqual(r['metricas']['paquetes_rpm_recogidos'], 1)
        self.assertIsNone(r['metricas']['paquetes_rpm'])
        self.assertNotIn('paquete-privado', json.dumps(r))

    def test_procedencia_incompatible_rechazada(self):
        r = h.adaptar_verificado(adaptar_memoria(memoria()), 'fedora')
        r['procedencia'] = 'puertos_verificados_v1'
        with self.assertRaises(ValueError):
            h.validar(r)

    def test_claves_anidadas_desconocidas(self):
        d = debian()
        d['fuente']['usuario'] = 'privado'
        with self.assertRaises(ValueError):
            h.adaptar_auditoria(d, 'debian13')
        d = adaptar_interfaces(interfaces()).a_dict()
        d['datos']['interfaces'][0]['hostname'] = 'privado'
        with self.assertRaises(ValueError):
            h.adaptar_verificado(ResultadoVerificado(d), 'fedora')

    def test_apt_completo_no_es_cobertura_ni_seguridad(self):
        d = debian(2)
        a = apt_error()
        a.update(estado_adquisicion='completo', codigo=0, total_posibles=0, motivo=None)
        d.update(estado_inventario='completo', actualizaciones=a)
        r = h.adaptar_auditoria(d, 'debian13')
        self.assertEqual(r['metricas']['apt_total_posibles'], 0)
        self.assertEqual(r['componentes']['apt']['cobertura'], 'no_verificada')
        self.assertEqual(r['cobertura'], 'no_verificada')
