"""Finalización simulada: nunca crea procesos ni aplica aislamiento."""
import contextlib
import unittest
from unittest.mock import MagicMock, patch

import AsistenteLocal as app
import auditoria_seguridad as audit
from test_auditoria_debian import Selector


class FinalizacionGeneral(unittest.TestCase):
    def adquirir(self, modulo, caso, presupuesto=15):
        reloj = [100.0]
        proceso = MagicMock()
        proceso.stdout.fileno.return_value = 1
        proceso.stderr.fileno.return_value = 2
        proceso.returncode = None
        proceso.poll.side_effect = lambda: proceso.returncode
        esperas = []
        def esperar(*, timeout):
            self.assertGreaterEqual(timeout, 0)
            self.assertLessEqual(reloj[0] + timeout, 100 + presupuesto)
            esperas.append(timeout)
            if caso == 'recogida' and proceso.kill.called:
                raise ChildProcessError('SECRETO')
            if caso in ('resistente', 'lectura_falla') or caso == 'timeout' and len(esperas) == 1:
                reloj[0] += timeout
                raise modulo.subprocess.TimeoutExpired('simulado', timeout)
            proceso.returncode = -9 if proceso.kill.called else 0
            return proceso.returncode
        proceso.wait.side_effect = esperar
        if caso == 'kill':
            proceso.kill.side_effect = PermissionError('SECRETO')
        if caso == 'poll':
            proceso.poll.side_effect = OSError('SECRETO')
        if caso == 'cierre':
            proceso.stdout.close.side_effect = OSError('SECRETO')
        selector = Selector()
        fila = b'pkg\t0\t1\t1.fc44\tx86_64\n'
        limitar = caso in ('limite', 'kill', 'recogida', 'poll', 'ya_terminado')
        bloques = {1: [fila * (2 if limitar else 1), b''], 2: [b'']}
        if caso == 'ya_terminado':
            proceso.returncode = 0
        def seleccionar(timeout):
            self.assertGreaterEqual(timeout, 0)
            self.assertLessEqual(reloj[0] + timeout,
                                 100 + presupuesto - min(1, presupuesto / 4))
            if caso == 'captura_timeout':
                reloj[0] += timeout
                return []
            return [(k, 1) for k in list(selector.claves.values())]
        selector.select = seleccionar
        with contextlib.ExitStack() as pila:
            lanzar = pila.enter_context(patch.object(modulo.subprocess, 'Popen', return_value=proceso))
            pila.enter_context(patch.object(modulo.selectors, 'DefaultSelector', return_value=selector))
            pila.enter_context(patch.object(modulo.os, 'read', side_effect=
                OSError('SECRETO') if caso == 'lectura_falla' else lambda fd, n: bloques[fd].pop(0)))
            pila.enter_context(patch.object(modulo.time, 'monotonic', side_effect=lambda: reloj[0]))
            if limitar:
                pila.enter_context(patch.object(modulo, 'MAX_COMMAND_BYTES' if modulo is app else 'MAX_PAQUETES', 1))
            funcion = modulo.ejecutar_comando if modulo is app else modulo._leer_inventario
            try:
                resultado = funcion(['simulado'], presupuesto)
            except (OSError, modulo.subprocess.TimeoutExpired) as error:
                resultado = error
        proceso.__enter__.assert_not_called()
        proceso.__exit__.assert_not_called()
        proceso.stdout.close.assert_called_once()
        proceso.stderr.close.assert_called_once()
        lanzar.assert_called_once()
        self.assertLessEqual(reloj[0], 100 + presupuesto)
        self.assertNotIn('SECRETO', str(resultado))
        return resultado, proceso, esperas

    def test_normal_sin_kill_ni_espera_repetida(self):
        for modulo in (app, audit):
            with self.subTest(modulo=modulo.__name__):
                r, p, esperas = self.adquirir(modulo, 'normal')
                self.assertEqual(r[0] if modulo is app else r['codigo'], 0)
                p.kill.assert_not_called()
                self.assertEqual(esperas, [14])

    def test_timeout_reserva_recogida_sin_ampliar_plazo(self):
        for modulo in (app, audit):
            with self.subTest(modulo=modulo.__name__):
                r, p, esperas = self.adquirir(modulo, 'timeout')
                p.kill.assert_called_once()
                self.assertEqual(esperas, [14, 1])
                if modulo is app:
                    self.assertIsInstance(r, app.subprocess.TimeoutExpired)
                else:
                    self.assertEqual(r['motivo'], 'tiempo_agotado')
                    self.assertEqual(r['estado'], 'parcial')
                    self.assertEqual(r['codigo'], -9)

    def test_resistente_no_se_declara_recogido(self):
        for modulo in (app, audit):
            with self.subTest(modulo=modulo.__name__):
                r, p, esperas = self.adquirir(modulo, 'resistente')
                self.assertEqual(esperas, [14, 1])
                p.kill.assert_called_once()
                if modulo is app:
                    self.assertIsInstance(r, OSError)
                    self.assertIn('terminacion_no_confirmada', str(r))
                else:
                    self.assertEqual(r['motivo'], 'terminacion_no_confirmada')
                    self.assertEqual(r['estado'], 'parcial')
                    self.assertIsNone(r['codigo'])

    def test_kill_por_limite_con_recogida_acotada(self):
        for modulo in (app, audit):
            with self.subTest(modulo=modulo.__name__):
                r, p, esperas = self.adquirir(modulo, 'limite')
                p.kill.assert_called_once()
                self.assertEqual(esperas, [15])
                self.assertEqual(r[0] if modulo is app else r['codigo'], -9)
                self.assertTrue(r[3] if modulo is app else r['estado'] == 'parcial')

    def test_errores_kill_recogida_poll_y_cierre(self):
        for modulo in (app, audit):
            for caso in ('kill', 'recogida', 'poll', 'cierre'):
                with self.subTest(modulo=modulo.__name__, caso=caso):
                    r, p, esperas = self.adquirir(modulo, caso)
                    if modulo is app:
                        self.assertIsInstance(r, OSError)
                        self.assertIn('error_recogida', str(r))
                    else:
                        self.assertEqual(r['motivo'], 'error_recogida')
                        self.assertNotEqual(r['estado'], 'correcta')
                    if caso == 'kill':
                        self.assertTrue(esperas)  # Se intenta recoger pese al fallo de kill.

    def test_ya_recogido_no_recibe_kill(self):
        for modulo in (app, audit):
            with self.subTest(modulo=modulo.__name__):
                r, p, esperas = self.adquirir(modulo, 'ya_terminado')
                p.kill.assert_not_called()
                self.assertEqual(esperas, [])

    def test_timeout_de_captura_con_recogida(self):
        for modulo in (app, audit):
            with self.subTest(modulo=modulo.__name__):
                r, p, esperas = self.adquirir(modulo, 'captura_timeout')
                p.kill.assert_called_once()
                self.assertEqual(esperas, [1])
                if modulo is app:
                    self.assertIsInstance(r, TimeoutError)
                else:
                    self.assertEqual(r['motivo'], 'tiempo_agotado')
                    self.assertEqual(r['estado'], 'error')

    def test_presupuesto_corto_reserva_proporcional(self):
        for modulo in (app, audit):
            with self.subTest(modulo=modulo.__name__):
                r, p, esperas = self.adquirir(modulo, 'timeout', .04)
                self.assertAlmostEqual(esperas[0], .03)
                self.assertAlmostEqual(esperas[1], .01)

    def test_fallo_lectura_no_oculta_terminacion_no_confirmada(self):
        for modulo in (app, audit):
            with self.subTest(modulo=modulo.__name__):
                r, p, esperas = self.adquirir(modulo, 'lectura_falla')
                p.kill.assert_called_once()
                if modulo is app:
                    self.assertIsInstance(r, OSError)
                    self.assertIn('terminacion_no_confirmada', str(r))
                else:
                    self.assertEqual(r['motivo'], 'terminacion_no_confirmada')
                    self.assertIsNone(r['codigo'])
                    self.assertEqual(r['estado'], 'error')
