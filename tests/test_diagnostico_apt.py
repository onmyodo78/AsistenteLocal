"""Diagnóstico APT simulado: no importa apt_pkg real ni repite la adquisición."""
import contextlib
import copy
import errno
import io
import json
from pathlib import Path
import sys
import time
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

import apt_debian as apt
import test_apt_debian as fixtures


class DiagnosticoApt(unittest.TestCase):
    def setUp(self):
        p = patch.object(apt, 'seleccionar_indices', side_effect=fixtures.seleccion_simulada)
        p.start()
        self.addCleanup(p.stop)

    def worker(self, preparar):
        api, cache, policy, sources = fixtures.api_simulada()
        preparar(api, cache, policy, sources)
        with patch.dict(sys.modules, {'apt_pkg': api}), patch.dict(apt.os.environ), \
             patch.object(Path, 'exists', return_value=True), \
             patch.object(apt.os, 'stat', return_value=NS(st_mtime=time.time())), \
             patch.object(apt.subprocess, 'Popen', side_effect=AssertionError('Proceso real')), \
             contextlib.redirect_stdout(io.StringIO()) as stdout, \
             contextlib.redirect_stderr(io.StringIO()) as stderr:
            codigo = apt.emitir_local()
        return codigo, stdout.getvalue(), stderr.getvalue()

    def test_etapas_inicializacion_cache_policy_y_lecturas(self):
        casos = [
            ('init_config', lambda a,c,p,s: a.init_config),
            ('configuracion', lambda a,c,p,s: a.config.set),
            ('init_system', lambda a,c,p,s: a.init_system),
            ('abrir_cache', lambda a,c,p,s: a.Cache),
            ('crear_policy', lambda a,c,p,s: a.Policy),
            ('ruta_preferencias', lambda a,c,p,s: a.config.find_file),
            ('leer_preferencias', lambda a,c,p,s: p.read_pinfile),
            ('ruta_preferencias_d', lambda a,c,p,s: a.config.find_dir),
            ('leer_preferencias_d', lambda a,c,p,s: p.read_pindir),
            ('crear_sources', lambda a,c,p,s: a.SourceList),
            ('leer_sources', lambda a,c,p,s: s.read_main_list),
            ('buscar_indice', lambda a,c,p,s: s.find_index),
            ('seleccionar_candidata', lambda a,c,p,s: p.get_candidate_ver),
            ('comparar_versiones', lambda a,c,p,s: a.version_compare),
            ('prioridad_candidata', lambda a,c,p,s: p.get_priority)]
        for etapa, seleccionar in casos:
            def preparar(a,c,p,s):
                seleccionar(a,c,p,s).side_effect = PermissionError(errno.EACCES, 'SECRETO', '/ruta/privada')
            with self.subTest(etapa=etapa):
                codigo, stdout, stderr = self.worker(preparar)
                self.assertEqual(codigo, 72)
                self.assertEqual(len(stderr.splitlines()), 1)
                self.assertLessEqual(len(stderr.encode()), 512)
                dato = json.loads(stderr.removeprefix(apt.PREFIJO_DIAGNOSTICO))
                self.assertEqual(dato, dict(etapa=etapa, excepcion='OSError', errno=errno.EACCES,
                                           error_seguro='EACCES', relacion='permisos'))
                self.assertNotIn('SECRETO', stderr)
                self.assertNotIn('/ruta/privada', stderr)
                self.assertNotIn('Traceback', stderr)

    def test_stat_archivo_ausente_y_api_incompatible(self):
        api,cache,policy,sources = fixtures.api_simulada()
        contexto = {}
        with patch.object(apt.os, 'stat', side_effect=FileNotFoundError(errno.ENOENT, 'SECRETO')):
            with self.assertRaises(FileNotFoundError) as error:
                apt._indices(cache, sources, time.time(), contexto)
        self.assertEqual(contexto['etapa'], 'stat_indice')
        self.assertEqual(apt._diagnostico(contexto['etapa'], error.exception)['relacion'], 'datos_ausentes')
        def preparar(a,c,p,s):
            a.Policy.side_effect = TypeError('API PRIVADA')
        codigo, stdout, stderr = self.worker(preparar)
        self.assertEqual(codigo,72)
        dato=json.loads(stderr.removeprefix(apt.PREFIJO_DIAGNOSTICO))
        self.assertEqual((dato['etapa'],dato['relacion']),('crear_policy','api_posible'))
        self.assertIsNone(dato['errno'])

    def test_categorias_no_usan_textos_ni_nombres_arbitrarios(self):
        casos = [(PermissionError(errno.EPERM,'SECRETO'),'OSError','permisos'),
            (OSError(errno.ENOENT,'SECRETO'),'OSError','datos_ausentes'),
            (OSError(errno.ENOMEM,'SECRETO'),'OSError','recursos'),
            (OSError(999999,'SECRETO'),'OSError','sistema_indeterminado'),
            (AttributeError('SECRETO'),'AttributeError','api_posible'),
            (TypeError('SECRETO'),'TypeError','api_posible'),
            (KeyError('SECRETO'),'KeyError','datos_o_limites'),
            (ValueError('SECRETO'),'ValueError','datos_o_limites'),
            (MemoryError('SECRETO'),'MemoryError','recursos'),
            (SystemError('E: permiso denegado en SECRETO'),'SystemError','biblioteca_apt_indeterminada')]
        for exc,categoria,relacion in casos:
            with self.subTest(categoria=categoria,relacion=relacion):
                dato=apt._diagnostico('abrir_cache',exc)
                self.assertEqual((dato['excepcion'],dato['relacion']),(categoria,relacion))
                self.assertNotIn('SECRETO',json.dumps(dato))
        class NombrePrivado(PermissionError):
            def __str__(self):
                raise AssertionError('Nunca convertir la excepción en texto')
        dato=apt._diagnostico('abrir_cache',NombrePrivado(errno.EACCES,'secreto'))
        self.assertEqual(dato['excepcion'],'OSError')

    def test_transporte_solo_diagnostico_validado_y_contrato_intacto(self):
        dato=apt._diagnostico('abrir_cache',PermissionError(errno.EACCES,'SECRETO'))
        linea=apt.PREFIJO_DIAGNOSTICO+json.dumps(dato)+'\n'
        with contextlib.redirect_stderr(io.StringIO()) as stderr:
            resultado=fixtures.AptLocal().adquirir('',codigo=72,stderr=linea.encode())
        self.assertEqual(resultado['codigo'],72)
        self.assertEqual(resultado['motivo'],'consulta_apt_fallida')
        self.assertEqual(resultado['estado_adquisicion'],'error')
        self.assertIsNone(resultado['total_posibles'])
        self.assertNotIn('diagnostico',resultado)
        self.assertEqual(json.loads(stderr.getvalue().removeprefix(apt.PREFIJO_DIAGNOSTICO)),dato)
        self.assertNotIn('SECRETO',stderr.getvalue())
        # Un diagnóstico nunca convierte stderr en un éxito autorizado.
        with contextlib.redirect_stderr(io.StringIO()) as stderr:
            resultado=fixtures.AptLocal().adquirir(codigo=0,stderr=linea.encode())
        self.assertEqual(resultado['motivo'],'avisos_no_interpretados')
        self.assertEqual(stderr.getvalue(),'')

    def test_rechaza_diagnosticos_inyectados_y_excesivos(self):
        original=apt._diagnostico('abrir_cache',OSError(errno.EPERM,'secreto'))
        for clave,valor in [('etapa','/privado'),('excepcion','NombrePrivado'),('errno',True),
                            ('error_seguro','SECRETO'),('relacion','ruta_privada'),('extra','SECRETO')]:
            dato=copy.deepcopy(original)
            dato[clave]=valor
            with self.subTest(clave=clave), contextlib.redirect_stderr(io.StringIO()) as stderr:
                apt._reenviar_diagnostico((apt.PREFIJO_DIAGNOSTICO+json.dumps(dato)).encode(),72)
            self.assertEqual(stderr.getvalue(),'')
        for contenido in (b'error con ruta privada', b'x'*8193,
                          (apt.PREFIJO_DIAGNOSTICO+'{}\n').encode()):
            with contextlib.redirect_stderr(io.StringIO()) as stderr:
                apt._reenviar_diagnostico(contenido,72)
            self.assertEqual(stderr.getvalue(),'')
        a=apt.Acumulador()
        a.recibir('stderr',b'x'*(apt.MAX_STDERR+1))
        self.assertEqual(a.motivo,'limite_stderr')
        self.assertLessEqual(len(a.error_acotado),apt.MAX_STDERR)
