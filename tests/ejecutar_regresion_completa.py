"""Regresión de la entrega pública, sin activar integraciones reales.

Amplía el corredor de referencia sin descubrir prototipos locales excluidos.
Los diagnósticos reales y LM Studio se validan por separado y con autorización.
"""
import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
for nombre in ('ASISTENTE_PRUEBAS_REALES', 'ASISTENTE_MANTENIMIENTO_REAL', 'ASISTENTE_PRUEBAS_APT'):
    os.environ[nombre] = '0'

from ejecutar_regresion_motor import MODULOS

COMPLEMENTARIOS = (
    'test_programacion_mantenimiento', 'test_apt_landlock_local', 'test_contratos_fedora', 'test_despliegue_helper_apt',
    'test_diagnostico_apt', 'test_evidencia', 'test_inicializacion_apt',
    'test_integracion_local', 'test_interfaces_verificadas', 'test_mensaje_apt',
    'test_motor_independiente_real', 'test_p0',
)

if __name__ == '__main__':
    seleccionados = {nombre.split('.')[0] for nombre in MODULOS}
    assert not seleccionados.intersection(COMPLEMENTARIOS)
    suite = unittest.defaultTestLoader.loadTestsFromNames([*MODULOS, *COMPLEMENTARIOS])
    sys.exit(0 if unittest.TextTestRunner(verbosity=1).run(suite).wasSuccessful() else 1)
