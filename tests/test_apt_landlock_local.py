"""Integración optativa con APT real, sin red ni escrituras del hijo.

ASISTENTE_PRUEBAS_APT=1 /usr/bin/python3 -B -m unittest discover -s tests -p test_apt_landlock_local.py -v

Requiere python3-apt, aislamiento disponible, índices locales y una srcpkgcache
reutilizable. No prepara ni modifica esos datos: su ausencia hace fallar la
comprobación estricta de éxito. El caso negativo desactiva la reutilización solo
en la memoria de un hijo ya aislado; nunca borra ni invalida archivos de Debian.
"""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

import apt_debian
import AsistenteLocal as app
from evidencia_local import comprobar


RAIZ = Path(__file__).resolve().parents[1]

# Se usa la implementación de producción sin alterar Landlock, seccomp ni límites.
# init_config sigue siendo real; únicamente se fuerza la ausencia de caché
# reutilizable en la configuración volátil del proceso de prueba.
SIN_REUTILIZACION = """
from auditoria_aislamiento import restringir
restringir()
import apt_pkg
from apt_debian import emitir_local
inicializar = apt_pkg.init_config
def sin_cache():
    inicializar()
    apt_pkg.config.set('Dir::Cache::srcpkgcache', '')
apt_pkg.init_config = sin_cache
raise SystemExit(emitir_local())
"""

REFERENCIA = """
from auditoria_aislamiento import restringir
restringir()
import json
import os
for variable in ('APT_CONFIG', 'DPKG_ROOT', 'DPKG_ADMINDIR'):
    os.environ.pop(variable, None)
import apt
cache = apt.Cache()
print(json.dumps({
    p.name.split(':', 1)[0] + ':' + p.installed.architecture:
        [p.installed.version, p.candidate.version if p.candidate else None]
    for p in cache if p.is_installed
}))
"""


@unittest.skipUnless(os.environ.get('ASISTENTE_PRUEBAS_APT') == '1',
                     'APT real desactivado; requiere ASISTENTE_PRUEBAS_APT=1')
class AptLandlockLocal(unittest.TestCase):
    def test_23_objetivos_no_seleccionados_del_equipo(self):
        # Instantánea optativa del equipo investigado: no prepara índices.
        codigo = '''
from auditoria_aislamiento import restringir
restringir()
import apt_pkg, apt_indices, json
apt_pkg.init()
print(json.dumps(apt_indices.seleccionar_indices()[0]))
'''
        r = subprocess.run([sys.executable, '-B', '-c', codigo], cwd=RAIZ,
                           stdin=subprocess.DEVNULL, capture_output=True,
                           text=True, timeout=15, check=True)
        self.assertEqual(r.stderr, '')
        self.assertEqual(json.loads(r.stdout), dict(configurados=22, presentes=22,
            ausentes=0, necesarios=21, opcionales=1, no_aplicables=13,
            declarados_vacios=10, indeterminados=0, seleccion_verificada=True))

    def test_faltante_real_y_release_inaccesible_sin_modificar_debian(self):
        # Inyección de fallos de lectura en el hijo: se consulta APT real y se
        # redirige una comprobación a una ruta inexistente. No se borra un índice.
        for fallo in ('indice', 'release', 'comando'):
            codigo = '''
from auditoria_aislamiento import restringir
restringir()
import apt_indices
from apt_debian import emitir_local
''' + ({
                'indice': '''
original = apt_indices._disponible
def disponible(ruta):
    if ruta.endswith('repo.protonvpn.com_debian_dists_stable_main_binary-all_Packages'):
        return original('/var/lib/apt/lists/__asistentelocal_indice_inexistente__')
    return original(ruta)
apt_indices._disponible = disponible
''',
                'release': '''
def ausente(*args):
    raise FileNotFoundError()
apt_indices._leer_release = ausente
''',
                'comando': '''
def ausente(*args):
    raise FileNotFoundError()
apt_indices._ejecutar = ausente
''',
            }[fallo]) + '\nraise SystemExit(emitir_local())\n'
            with self.subTest(fallo=fallo), \
                 patch.object(apt_debian, 'comando_aislado',
                              return_value=[sys.executable, '-B', '-c', codigo]):
                r = apt_debian.consultar_actualizaciones(15)
                self.assertEqual(r['codigo'], 0)
                self.assertEqual(r['estado_adquisicion'], 'parcial')
                self.assertTrue(r['candidatos'])
                self.assertIsNone(r['total_posibles'])
                if fallo == 'indice':
                    self.assertEqual(r['motivo'], 'indices_parciales')
                    self.assertEqual(r['indices']['ausentes'], 1)
                    self.assertEqual(r['indices']['integridad_local'], 'parcial')
                else:
                    self.assertEqual(r['motivo'], 'seleccion_indices_no_verificada')
                    self.assertEqual(r['indices']['integridad_local'], 'desconocida')

    def test_cache_reutilizable_con_cobertura_y_versiones_reales(self):
        # Impide que la ruta pública contacte accidentalmente con el modelo.
        with patch.object(app, 'abrir_http_local',
                          side_effect=AssertionError('Red no autorizada')):
            resultado = app.ejecutar_consulta('auditoria_seguridad',
                                             time.monotonic() + 30)
        comprobar('auditoria_seguridad', resultado, nivel_debian='apt_completo')
        self.assertTrue(resultado.datos['inventario_completo'])
        actualizaciones = resultado.datos['actualizaciones']
        self.assertEqual(actualizaciones['codigo'], 0)
        self.assertTrue(actualizaciones['candidatos'])
        self.assertIsNone(actualizaciones['motivo'])
        self.assertEqual(actualizaciones['indices']['integridad_local'], 'completa')
        self.assertEqual(actualizaciones['indices']['frescura'], 'no_verificada')
        self.assertEqual(actualizaciones['cobertura_aplicaciones'], 'no_verificada')
        instalados = {
            r['nombre_binario'] + ':' + r['arquitectura']: r['version']
            for r in resultado.datos['inventario_dpkg']
            if r['categoria'] == 'instalado'
        }
        self.assertEqual(instalados, {
            r['nombre_binario'] + ':' + r['arquitectura']: r['instalada']
            for r in actualizaciones['candidatos']
        })

        referencia = subprocess.run([sys.executable, '-B', '-c', REFERENCIA],
                                    cwd=RAIZ, stdin=subprocess.DEVNULL,
                                    capture_output=True, text=True, timeout=15,
                                    check=True)
        observados = {
            r['nombre_binario'] + ':' + r['arquitectura']:
                [r['instalada'], r['candidata']]
            for r in actualizaciones['candidatos']
        }
        self.assertEqual(observados, json.loads(referencia.stdout))

    def test_sin_cache_reutilizable_falla_cerrado_y_no_publica_cero(self):
        comando = [sys.executable, '-B', '-c', SIN_REUTILIZACION]
        with patch.object(apt_debian, 'comando_aislado', return_value=comando), \
             contextlib.redirect_stderr(io.StringIO()) as diagnostico:
            resultado = apt_debian.consultar_actualizaciones(15)
        self.assertEqual(resultado['codigo'], 72)
        self.assertEqual(resultado['estado_adquisicion'], 'error')
        self.assertEqual(resultado['motivo'], 'consulta_apt_fallida')
        self.assertIsNone(resultado['total_posibles'])
        self.assertEqual(resultado['candidatos'], [])
        self.assertIsNone(resultado['indices'])
        dato = json.loads(diagnostico.getvalue().removeprefix(
            apt_debian.PREFIJO_DIAGNOSTICO))
        self.assertEqual(dato['etapa'], 'abrir_cache')
        self.assertEqual(dato['excepcion'], 'SystemError')
        self.assertEqual(dato['categoria_mensaje'], 'permisos')
        self.assertNotIn('/tmp/', diagnostico.getvalue())
