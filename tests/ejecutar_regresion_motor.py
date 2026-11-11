"""Selección revisada de regresiones simuladas. No activar descubrimiento general."""
import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ['ASISTENTE_PRUEBAS_REALES'] = '0'
os.environ['ASISTENTE_MANTENIMIENTO_REAL'] = '0'
MODULOS = '''test_operaciones_locales test_cliente_diagnostico_transporte test_tty_confirmacion test_dnf5_interactivo test_dnf5_preparacion test_diagnostico_mantenimiento test_ejecucion_apt test_motor_independiente test_informes_factuales test_motor_consultas_fase1
 test_limite_interpretacion test_proyeccion_compacta_auditoria test_interpretacion_auditoria_basica test_presentacion_auditoria_basica test_auditoria_basica test_autonomia_actual test_continuacion_auditoria test_lmstudio_comunicacion test_lmstudio_http
 test_lmstudio_diagnostico_http test_finalizacion_general test_captura_conversacional
 test_entorno test_infraestructura_integracion test_estabilizacion_debian
 test_backend_seguridad test_finalizacion_debian test_control_verificado
 test_resultado_verificado test_auditoria_seguridad.Auditoria test_auditoria_debian
 test_apt_debian test_apt_indices test_errores test_interfaces_red test_memoria_verificada
 test_conexiones_verificadas test_puertos_verificados test_servicios_verificados
 test_distribucion_linux test_historial_contratos test_historial_sqlite
 test_historial_persistente test_historial_controlador test_sesion_resultados
 test_informe_exportacion test_exportacion_generadores test_exportacion_controlador
 test_exportacion_escritor test_exportacion_interfaz'''.split()

if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromNames(MODULOS)
    sys.exit(0 if unittest.TextTestRunner(verbosity=1).run(suite).wasSuccessful() else 1)
