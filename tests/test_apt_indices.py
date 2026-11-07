"""Selección APT sintética; sin ejecutar APT, red ni procesos reales."""
import hashlib
import io
from pathlib import Path
import subprocess
import tempfile
import time
from types import SimpleNamespace as NS
import unittest
from unittest.mock import Mock, patch

import apt_indices as mod
import apt_debian as apt
import test_apt_debian as fixtures
from test_auditoria_debian import Selector

VACIO = (0, hashlib.sha256(b'').hexdigest())


def escenario():
    potenciales, efectivos, releases = {}, {}, {}
    componentes = ('main', 'contrib', 'non-free', 'non-free-firmware')
    def agregar(repo, comp, arch, estado='seleccionado', opcional=False):
        base = 'https://' + repo + '.example/dists/stable/'
        key = comp + '/binary-' + arch + '/Packages' if comp else 'Packages'
        objetivo = dict(filename='/var/lib/apt/lists/' + repo + '_' + key.replace('/', '_'),
                        architecture=arch, optional='yes' if opcional else 'no')
        potenciales[(base, key)] = objetivo
        dato, hashes = releases.setdefault(base, ({}, {}))
        hashes[key] = VACIO if estado == 'vacio' else (99, 'a' * 64)
        if estado == 'seleccionado':
            efectivos[(base, key)] = objetivo.copy()
    for comp in componentes:
        for arch in ('amd64', 'i386'):
            agregar('trixie', comp, arch)
            agregar('security', comp, arch, 'vacio' if comp == 'non-free' else 'seleccionado')
            agregar('updates', comp, arch, 'seleccionado' if comp == 'main' else 'vacio')
        for repo in ('trixie', 'security', 'updates'):
            agregar(repo, comp, 'all', 'no_aplicable')
    for arch in ('amd64', 'arm64'):
        agregar('brave', 'main', arch)
    agregar('brave', 'main', 'all', 'no_aplicable')
    agregar('lutris', '', '')
    agregar('proton', 'main', 'amd64')
    agregar('proton', 'main', 'all', opcional=True)
    agregar('proton', 'main', 'i386', 'vacio')
    agregar('code', 'main', 'amd64')
    agregar('code', 'main', 'all', 'vacio')
    for base, (dato, _) in releases.items():
        if 'trixie.' in base or 'updates.' in base:
            dato.update(architectures='all amd64 i386', **{'no-support-for-architecture-all': 'Packages'})
        elif 'security.' in base:
            dato['architectures'] = 'amd64 i386'
        elif 'brave.' in base:
            dato['architectures'] = 'amd64 arm64'
    return potenciales, efectivos, releases


def deb822(arch='all', tipo='Packages', filename='/var/lib/apt/lists/test'):
    return ('Identifier: ' + tipo + '\nMetaKey: main/binary-' + arch + '/Packages\n'
            'Architecture: ' + arch + '\nBase-URI: https://repo.example/dists/stable/\n'
            'URI: https://repo.example/dists/stable/main/binary-' + arch + '/Packages\n'
            'Filename: ' + filename + '\nOptional: yes\nTarget-Of: deb\n\n').encode()


class ObjetivosApt(unittest.TestCase):
    def clasificar(self, preparar=None, disponible=lambda ruta: True):
        p, e, r = escenario()
        if preparar:
            preparar(p, e, r)
        return mod.clasificar(p, e, lambda base: r[base], disponible)

    def test_23_falsos_positivos_multiarch_y_vacios(self):
        r = self.clasificar()
        self.assertEqual(r, dict(configurados=22, presentes=22, ausentes=0,
            necesarios=21, opcionales=1, no_aplicables=13, declarados_vacios=10,
            indeterminados=0, seleccion_verificada=True))
        p, e, _ = escenario()
        self.assertEqual(len(p), 45)
        self.assertIn('all', {d['architecture'] for d in e.values()})
        self.assertIn('i386', {d['architecture'] for d in e.values()})
        self.assertIn('arm64', {d['architecture'] for d in e.values()})

    def test_indices_seleccionados_realmente_ausentes_incluido_all(self):
        for sufijo in ('trixie_main_binary-i386_Packages', 'proton_main_binary-all_Packages'):
            r = self.clasificar(disponible=lambda ruta: not ruta.endswith(sufijo))
            self.assertTrue(r['seleccion_verificada'])
            self.assertEqual((r['presentes'], r['ausentes']), (21, 1))

    def test_release_ausente_o_insuficiente_no_autoriza_exclusion(self):
        p, e, releases = escenario()
        def ausente(base):
            raise FileNotFoundError('SECRETO')
        r = mod.clasificar(p, e, ausente, lambda ruta: True)
        self.assertFalse(r['seleccion_verificada'])
        self.assertEqual(r['indeterminados'], 45)
        # Que APT omita un objetivo no prueba por sí solo que sea prescindible.
        base, key = next(k for k in p if k not in e and 'code.' in k[0])
        del releases[base][1][key]
        r = mod.clasificar(p, e, lambda b: releases[b], lambda ruta: True)
        self.assertFalse(r['seleccion_verificada'])
        self.assertEqual(r['indeterminados'], 1)
        releases[base][1][key] = (0, 'f' * 64)
        r = mod.clasificar(p, e, lambda b: releases[b], lambda ruta: True)
        self.assertEqual(r['indeterminados'], 1)

    def test_seleccion_contradice_release(self):
        def preparar(p, e, r):
            base, key = next(iter(e))
            r[base][1][key] = VACIO
        self.assertFalse(self.clasificar(preparar)['seleccion_verificada'])

    def test_parser_excluye_sources_traducciones_dep11_y_conserva_all(self):
        contenido = b''.join(deb822(tipo=t) for t in ('Sources', 'Translations', 'DEP-11', 'Packages'))
        r = mod.parsear_objetivos(contenido, Path('/var/lib/apt/lists'))
        self.assertEqual(len(r), 1)
        self.assertEqual(next(iter(r.values()))['architecture'], 'all')

    def test_parser_rechaza_duplicados_inyecciones_rutas_y_truncamiento(self):
        for contenido in (deb822() * 2, deb822().replace(b'Optional: yes', b'Optional: yes\nOptional: no'),
                deb822().replace(b'Architecture: all', b'Architecture: i386'),
                deb822(filename='/etc/passwd'), deb822().replace(b'Target-Of: deb', b'Target-Of: deb-src'),
                deb822().replace(b'MetaKey:', b'campo sin separador'),
                deb822().replace(b'Optional: yes', b'Optional: $(OPTIONAL)'),
                deb822().replace(b'URI: https://repo.example/dists/stable/main', b'URI: https://otro.example/main'),
                b'Identifier: Packages\n', b'\xff', b'x' * (mod.MAX_LINEA + 1)):
            with self.subTest(contenido=contenido[:40]), self.assertRaises((ValueError, UnicodeError)):
                mod.parsear_objetivos(contenido, Path('/var/lib/apt/lists'))

    def test_lectura_de_archivo_ausente_o_denegado(self):
        for exc in (FileNotFoundError(), PermissionError(), IsADirectoryError()):
            with patch('builtins.open', side_effect=exc):
                self.assertFalse(mod._disponible('/indice'))

    def test_release_local_firmado_plano_vacio_y_metadatos_invalidos(self):
        # Solo archivos de prueba en /tmp; nunca modifica las listas de Debian.
        with tempfile.TemporaryDirectory(prefix='asistentelocal-release-') as tmp:
            directorio = Path(tmp)
            api = NS(uri_to_filename=lambda uri: uri.rsplit('/', 1)[1])
            cuerpo = ('Architectures: amd64 all\nSHA256:\n ' + VACIO[1] +
                      ' 0 main/binary-all/Packages\n')
            with patch.dict('sys.modules', {'apt_pkg': api}):
                for firmado in (False, True):
                    ruta = directorio / ('InRelease' if firmado else 'Release')
                    contenido = ('-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n' +
                        cuerpo + '\n-----BEGIN PGP SIGNATURE-----\nfixture\n') if firmado else cuerpo
                    ruta.write_text(contenido)
                    dato, hashes, leida, huella = mod._leer_release('https://repo/', directorio)
                    self.assertEqual(hashes['main/binary-all/Packages'], VACIO)
                    self.assertEqual(leida, ruta)
                    self.assertEqual(huella, hashlib.sha256(ruta.read_bytes()).digest())
                    ruta.unlink()
                for contenido in ('Date: hoy\n', cuerpo + 'SHA256: duplicado\n',
                                  cuerpo.replace(' 0 ', ' invalido ')):
                    (directorio / 'InRelease').write_text(contenido)
                    with self.assertRaises(ValueError):
                        mod._leer_release('https://repo/', directorio)

    def test_release_cambiado_o_seleccion_vacia_quedan_desconocidos(self):
        with patch.dict('sys.modules', {'apt_pkg': NS(config=NS(find_dir=lambda k: '/var/lib/apt/lists'))}), \
             patch.object(mod, '_ejecutar', return_value=b''):
            self.assertFalse(mod.seleccionar_indices()[0]['seleccion_verificada'])
        with patch.dict('sys.modules', {'apt_pkg': NS(config=NS(find_dir=lambda k: '/var/lib/apt/lists'))}), \
             patch.object(mod, '_ejecutar', return_value=deb822()), \
             patch.object(mod, '_disponible', return_value=True), \
             patch.object(mod, '_leer_release', return_value=({},
                 {'main/binary-all/Packages': (99, 'a' * 64)},
                 NS(open=lambda modo: io.BytesIO(b'nuevo')), hashlib.sha256(b'anterior').digest())):
            self.assertFalse(mod.seleccionar_indices()[0]['seleccion_verificada'])

    def test_comando_fijo_captura_acotada_timeout_y_limpieza(self):
        for modo in ('ok', 'timeout', 'stderr', 'limite', 'codigo'):
            p = Mock(stdout=io.BytesIO(), stderr=io.BytesIO())
            p.stdout.fileno = lambda: 1
            p.stderr.fileno = lambda: 2
            p.wait.return_value = 100 if modo == 'codigo' else 0
            p.poll.return_value = None
            bloques = {1: [b'x' * 20 if modo == 'limite' else deb822(), b''],
                       2: [b'aviso' if modo == 'stderr' else b'', b'']}
            with self.subTest(modo=modo), \
                 patch.object(mod.subprocess, 'Popen', return_value=p) as lanzar, \
                 patch.object(mod.selectors, 'DefaultSelector', return_value=Selector(modo == 'timeout')), \
                 patch.object(mod.os, 'read', side_effect=lambda fd, n: bloques[fd].pop(0)), \
                 patch.object(mod, 'MAX_BYTES', 8 if modo == 'limite' else 4194304):
                if modo == 'ok':
                    self.assertEqual(mod._ejecutar(True, time.monotonic() + 15), deb822())
                else:
                    with self.assertRaises(mod.ComprobacionFallida):
                        mod._ejecutar(True, time.monotonic() + 15)
                comando = lanzar.call_args.args[0]
                self.assertEqual(comando, list(mod.COMANDO) + ['--no-release-info'])
                self.assertNotIn('shell', lanzar.call_args.kwargs)
                self.assertEqual(lanzar.call_args.kwargs['stdin'].mode, 'rb')
                self.assertTrue(p.stdout.closed and p.stderr.closed)
                if modo in ('timeout', 'limite'):
                    p.kill.assert_called_once()

    def test_fallo_comprobacion_no_publica_cero_actualizaciones(self):
        # Protocolo real del supervisor con registros conservados y selección desconocida.
        meta = fixtures.indices()
        meta.update(seleccion_verificada=False, integridad_local='desconocida')
        r = fixtures.AptLocal().adquirir(fixtures.salida(meta=meta))
        self.assertEqual(r['motivo'], 'seleccion_indices_no_verificada')
        self.assertEqual(r['estado_adquisicion'], 'parcial')
        self.assertIsNone(r['total_posibles'])
        # El fallo real de ejecución produce metadatos desconocidos, no una selección vacía válida.
        with patch.dict('sys.modules', {'apt_pkg': NS(config=NS(find_dir=lambda k: '/var/lib/apt/lists'))}), \
             patch.object(mod, '_ejecutar', side_effect=FileNotFoundError()):
            seleccion, rutas = mod.seleccionar_indices()
        self.assertFalse(seleccion['seleccion_verificada'])
        self.assertEqual(rutas, set())

    def test_protocolo_rechaza_integridad_o_categorias_falsificadas(self):
        for cambio in (dict(integridad_local='completa', seleccion_verificada=False),
                       dict(necesarios=True), dict(indeterminados=1), dict(opcionales=1),
                       dict(ruta_privada='/SECRETO')):
            meta = fixtures.indices()
            meta.update(cambio)
            r = fixtures.AptLocal().adquirir(fixtures.salida(meta=meta))
            self.assertEqual(r['motivo'], 'formato_invalido')
            self.assertIsNone(r['total_posibles'])

    def test_historial_acepta_metadatos_nuevos_y_no_inventa_totales(self):
        import historial_contratos as historial
        from test_historial_contratos import debian
        d = debian(2)
        d['estado_inventario'] = 'completo'
        d['actualizaciones'] = fixtures.AptLocal().adquirir()
        self.assertEqual(historial.adaptar_auditoria(d, 'debian13')['metricas']['apt_total_posibles'], 1)
        meta = d['actualizaciones']['indices']
        meta.update(seleccion_verificada=False, integridad_local='desconocida')
        with self.assertRaises(ValueError):
            historial.adaptar_auditoria(d, 'debian13')
        d['estado_adquisicion'] = d['actualizaciones']['estado_adquisicion'] = 'parcial'
        d['actualizaciones']['motivo'] = 'seleccion_indices_no_verificada'
        d['actualizaciones']['total_posibles'] = None
        self.assertIsNone(historial.adaptar_auditoria(d, 'debian13')['metricas']['apt_total_posibles'])
