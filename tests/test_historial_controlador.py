"""Controlador con resultados sintéticos y SQLite exclusivamente en memoria."""
import copy
import json
import unittest
from unittest.mock import patch

import historial_controlador as c
import historial_contratos as contratos
from historial_sqlite import HistorialMemoria, ErrorHistorial
from test_historial_sqlite import auditoria, resultado


class Controlador(unittest.TestCase):
    def setUp(self):
        self.motor = HistorialMemoria()
        self.addCleanup(self.motor.cerrar)
        self.ahora = 100.
        self.control = c.ControladorHistorial(self.motor, reloj=lambda: self.ahora)
        self.control.activar()
        self.addCleanup(self.control.cerrar)

    def preparar(self):
        return self.control.preparar(auditoria(), [resultado()])

    def confirmar(self, ident):
        return self.control.confirmar(ident, self.control.vista_previa(ident), confirmacion=True)

    def test_desactivado_por_defecto_sin_conexion(self):
        with patch.object(c, 'HistorialMemoria') as motor:
            control = c.ControladorHistorial()
            with self.assertRaises(c.ErrorControlador):
                control.preparar(auditoria(), [resultado()])
            control.activar()
            ident = control.preparar(auditoria(), [resultado()])
            control.vista_previa(ident)
            motor.assert_not_called()
            control.cerrar()

    def test_preparacion_vista_determinista(self):
        ident = self.preparar()
        vista = self.control.vista_previa(ident)
        self.assertEqual(vista, self.control.vista_previa(ident))
        self.assertEqual(vista['resultados'][0], resultado())
        self.assertEqual(vista['omisiones'], list(c.OMISIONES))
        self.assertEqual(self.motor.listar_auditorias(), [])
        self.assertFalse(vista['persistencia_disco'])

    def test_confirmacion_valida_no_guarda_hasta_peticion(self):
        ident = self.preparar()
        token = self.confirmar(ident)
        self.assertEqual(self.motor.listar_auditorias(), [])
        aid = self.control.guardar(ident, token)
        self.assertEqual(self.motor.consultar_resultados(aid)[0]['registro'], resultado())

    def test_confirmaciones_implicitas_rechazadas(self):
        ident = self.preparar()
        for valor in (None, False, 1, 'manual', 'si', {}, []):
            with self.assertRaises(c.ErrorControlador):
                self.control.confirmar(ident, self.control.vista_previa(ident), confirmacion=valor)
        with self.assertRaises(c.ErrorControlador):
            self.control.guardar(ident)
        self.assertEqual(self.motor.listar_auditorias(), [])

    def test_cancelar_revoca_sin_escrituras(self):
        ident = self.preparar()
        token = self.confirmar(ident)
        self.control.cancelar(ident)
        with self.assertRaises(c.ErrorControlador):
            self.control.guardar(ident, token)
        self.assertEqual(self.motor.listar_auditorias(), [])

    def test_modificar_entrada_no_modifica_instantanea(self):
        a, r = auditoria(), resultado()
        ident = self.control.preparar(a, [r])
        vista = self.control.vista_previa(ident)
        a['hostname'] = '/privado'
        r['metricas']['usuario'] = 'privado'
        self.assertEqual(vista, self.control.vista_previa(ident))
        self.control.guardar(ident, self.confirmar(ident))
        self.assertNotIn('privado', json.dumps(self.motor.consultar_resultados(1)))

    def test_vista_alterada_no_autoriza(self):
        ident = self.preparar()
        vista = self.control.vista_previa(ident)
        vista['resultados'][0]['ejecucion'] = 'correcto'
        with self.assertRaises(c.ErrorControlador):
            self.control.confirmar(ident, vista, confirmacion=True)
        with self.assertRaises(c.ErrorControlador):
            self.control.guardar(ident)

    def test_reemplazar_revoca_confirmacion(self):
        ident = self.preparar()
        token = self.confirmar(ident)
        otro = contratos.estado_conocido('sistema', 'debian13', 'error')
        self.control.reemplazar(ident, auditoria(), [otro])
        with self.assertRaises(c.ErrorControlador):
            self.control.guardar(ident, token)
        aid = self.control.guardar(ident, self.confirmar(ident))
        self.assertEqual(self.motor.consultar_resultados(aid)[0]['registro'], otro)

    def test_reemplazo_invalido_tambien_revoca(self):
        ident = self.preparar()
        token = self.confirmar(ident)
        with self.assertRaises(c.ErrorControlador):
            self.control.reemplazar(ident, auditoria(), [{'privado': 'x'}])
        with self.assertRaises(c.ErrorControlador):
            self.control.guardar(ident, token)
        self.assertEqual(self.motor.listar_auditorias(), [])

    def test_autorizacion_especifica_y_no_transferible(self):
        ident = self.preparar()
        otro = self.preparar()
        token = self.confirmar(ident)
        self.confirmar(otro)
        with self.assertRaises(c.ErrorControlador):
            self.control.guardar(otro, token)
        with self.assertRaises(c.ErrorControlador):
            self.control.guardar(ident, token)
        self.assertEqual(self.motor.listar_auditorias(), [])

    def test_expiracion_y_retroceso_reloj(self):
        for momento in (100+c.VIGENCIA_SEGUNDOS, 99):
            self.ahora = 100
            ident = self.preparar()
            token = self.confirmar(ident)
            self.ahora = momento
            with self.assertRaises(c.ErrorControlador):
                self.control.guardar(ident, token)
        self.assertEqual(self.motor.listar_auditorias(), [])

    def test_reutilizacion_duplicado_y_doble_preparacion(self):
        ident, otro = self.preparar(), self.preparar()
        token, token2 = self.confirmar(ident), self.confirmar(otro)
        self.control.guardar(ident, token)
        for i,t in ((ident, token), (otro, token2)):
            with self.assertRaises(c.ErrorControlador):
                self.control.guardar(i, t)
        with self.assertRaises(c.ErrorControlador):
            self.preparar()
        self.assertEqual(len(self.motor.listar_auditorias()), 1)

    def test_nueva_confirmacion_revoca_anterior(self):
        ident = self.preparar()
        viejo = self.confirmar(ident)
        nuevo = self.confirmar(ident)
        with self.assertRaises(c.ErrorControlador):
            self.control.guardar(ident, viejo)
        self.control.guardar(ident, nuevo)

    def test_fallo_motor_consumido_sin_reintentos(self):
        ident = self.preparar()
        token = self.confirmar(ident)
        with patch.object(self.motor, 'guardar_auditoria', side_effect=ErrorHistorial('/privado')) as guardar:
            with self.assertRaisesRegex(c.ErrorControlador, '^guardado_fallido$'):
                self.control.guardar(ident, token)
            with self.assertRaises(c.ErrorControlador):
                self.control.guardar(ident, token)
            guardar.assert_called_once()
        self.assertEqual(self.motor.listar_auditorias(), [])

    def test_fallo_sqlite_real_en_memoria_rollback(self):
        self.motor._conexion.execute("CREATE TRIGGER fallo BEFORE INSERT ON resultados BEGIN SELECT RAISE(ABORT,'privado'); END")
        ident = self.preparar()
        with self.assertRaises(c.ErrorControlador):
            self.control.guardar(ident, self.confirmar(ident))
        self.assertEqual(self.motor.listar_auditorias(), [])

    def test_privacidad_validacion_eventos_y_procedencia(self):
        for r in ({'texto': '/privado'}, resultado() | {'hostname': 'privado'}):
            with self.assertRaisesRegex(c.ErrorControlador, '^preparacion_invalida$'):
                self.control.preparar(auditoria(), [r])
        with self.assertRaises(c.ErrorControlador):
            self.control.preparar(auditoria(), [resultado()], [dict(tipo='privado', resultado_orden=0, cantidad=0)])
        ident = self.preparar()
        vista = self.control.vista_previa(ident)
        self.assertEqual(vista['resultados'][0]['procedencia'], 'estado_declarado_v1')
        self.assertNotIn('/privado', json.dumps(vista))

    def test_limites_y_desactivar_revoca(self):
        with patch.object(c, 'MAX_PREPARADAS', 1):
            ident = self.preparar()
            with self.assertRaises(c.ErrorControlador):
                self.preparar()
        token = self.confirmar(ident)
        self.control.desactivar()
        self.control.activar()
        with self.assertRaises(c.ErrorControlador):
            self.control.guardar(ident, token)

    def test_contratos_estructurados_y_sin_io(self):
        from test_memoria_verificada import normalizar
        from resultado_verificado import adaptar_memoria
        r = contratos.adaptar_verificado(adaptar_memoria(normalizar()), 'debian13')
        with patch('builtins.open', side_effect=AssertionError('archivo')), \
             patch('subprocess.Popen', side_effect=AssertionError('adquisicion')):
            ident = self.control.preparar(auditoria(), [r])
            aid = self.control.guardar(ident, self.confirmar(ident))
            self.assertEqual(self.motor.consultar_resultados(aid)[0]['registro'], r)
        self.assertEqual(self.motor._conexion.execute('PRAGMA database_list').fetchone()[2], '')

    def test_destino_no_admitido(self):
        with self.assertRaises(c.ErrorControlador):
            c.ControladorHistorial(destino=object())
