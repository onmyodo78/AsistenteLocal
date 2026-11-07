"""Regresiones de inicialización con una API falsa, sin consultas APT reales."""
import contextlib
import io
from pathlib import Path
import sys
import time
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

import apt_debian as apt
import test_apt_debian as fixtures


class InicializacionApt(unittest.TestCase):
    def setUp(self):
        p = patch.object(apt, 'seleccionar_indices', side_effect=fixtures.seleccion_simulada)
        p.start()
        self.addCleanup(p.stop)

    def test_opciones_en_memoria_antes_del_sistema_y_cache(self):
        api, cache, policy, sources = fixtures.api_simulada()
        orden = []
        opciones = {'Dir::Cache::pkgcache':'persistente',
                    'Dir::Cache::srcpkgcache':'persistente',
                    'APT::Default-Release':'trixie'}
        def init_config():
            self.assertNotIn('APT_CONFIG', apt.os.environ)
            orden.append('config')
        def configurar(clave, valor):
            opciones[clave] = valor
            orden.append(clave)
        def comprobar():
            self.assertEqual(opciones['Dir::Cache::pkgcache'], '')
            self.assertEqual(opciones['Dir::Cache::srcpkgcache'], 'persistente')
            self.assertEqual(opciones['Debug::NoLocking'], 'true')
            self.assertEqual(opciones['Dir::State::status'], '/var/lib/dpkg/status')
            self.assertEqual(opciones['APT::Default-Release'], 'trixie')
        def init_system():
            comprobar()
            orden.append('sistema')
        def abrir(progress):
            comprobar()
            self.assertIsNone(progress)
            self.assertEqual(orden[-1], 'sistema')
            orden.append('cache')
            return cache
        def crear_policy(valor):
            self.assertIs(valor, cache)
            self.assertEqual(orden[-1], 'cache')
            orden.append('policy')
            return policy
        api.init_config.side_effect = init_config
        api.config.set.side_effect = configurar
        api.init_system.side_effect = init_system
        api.Cache.side_effect = abrir
        api.Policy.side_effect = crear_policy
        with patch.dict(sys.modules, {'apt_pkg': api}), \
             patch.dict(apt.os.environ, {'APT_CONFIG':'config-no-usada'}), \
             patch.object(Path,'exists',return_value=True), \
             patch.object(apt.os,'stat',return_value=NS(st_mtime=time.time())), \
             patch.object(apt.subprocess,'Popen',side_effect=AssertionError('Proceso real')), \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(apt.emitir_local(),0)
        self.assertEqual(orden[0],'config')
        self.assertEqual(orden[-3:],['sistema','cache','policy'])
        for nombre in ('Acquire','DepCache','PackageManager','get_lock','SystemLock','FileLock'):
            getattr(api,nombre).assert_not_called()

    def test_fallo_cache_impide_policy_indices_y_resultados(self):
        api, cache, policy, sources = fixtures.api_simulada()
        api.Cache.side_effect = SystemError('Detalle interno que no debe publicarse')
        with patch.dict(sys.modules, {'apt_pkg':api}), patch.dict(apt.os.environ), \
             patch.object(Path,'exists',side_effect=AssertionError('No llegar a preferencias')), \
             patch.object(apt,'_indices',side_effect=AssertionError('No llegar a índices')), \
             contextlib.redirect_stdout(io.StringIO()) as stdout, \
             contextlib.redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(apt.emitir_local(),72)
        self.assertEqual(stdout.getvalue(),'')
        self.assertNotIn('Detalle interno',stderr.getvalue())
        self.assertIn('"etapa":"abrir_cache"',stderr.getvalue())
        self.assertIn('"relacion":"biblioteca_apt_indeterminada"',stderr.getvalue())
        api.Policy.assert_not_called()
        api.SourceList.assert_not_called()
