"""Ciclo de vida APT/dpkg simulado: sin procesos, APT ni aislamiento reales."""
import contextlib
import unittest
from unittest.mock import Mock, patch

import apt_debian as apt
import auditoria_debian as deb
from test_apt_debian import salida
from test_auditoria_debian import Selector, fila


class FinalizacionDebian(unittest.TestCase):
    def adquirir(self, modulo, caso):
        reloj = [100.0]
        proceso = Mock()
        proceso.stdout.fileno.return_value = 1
        proceso.stderr.fileno.return_value = 2
        proceso.returncode = None
        proceso.poll.side_effect = lambda: proceso.returncode
        llamadas = []
        def esperar(*, timeout):
            llamadas.append((reloj[0],timeout))
            self.assertGreaterEqual(timeout,0)
            self.assertLessEqual(reloj[0]+timeout,115.0)
            if caso == 'error_recogida':
                raise OSError('SECRETO /privado')
            if caso == 'resistente' or caso == 'timeout' and len(llamadas) == 1:
                reloj[0] += timeout
                raise modulo.subprocess.TimeoutExpired('simulado',timeout)
            if caso == 'error_final' and proceso.kill.called:
                raise ChildProcessError('SECRETO /privado')
            proceso.returncode = -9 if proceso.kill.called else 0
            return proceso.returncode
        proceso.wait.side_effect = esperar
        if caso == 'kill_falla':
            proceso.kill.side_effect = PermissionError('SECRETO /privado')
        if caso == 'ya_terminado':
            proceso.returncode = 0
        if caso == 'poll_falla':
            proceso.poll.side_effect = ChildProcessError('SECRETO /privado')
        if caso == 'cierre_falla':
            proceso.stdout.close.side_effect = OSError('SECRETO /privado')
        texto = salida() if modulo is apt else fila()
        if caso in ('formato','error_final','kill_falla','ya_terminado','poll_falla'):
            texto += 'invalido\n'  # Prefijo válido conservado.
        if caso == 'sin_registros':
            texto = ''
        bloques = {1:[texto.encode(),b''],2:[b'']}
        selector = Selector()
        def seleccionar(plazo):
            self.assertLessEqual(reloj[0]+plazo,114.0)
            return [(k,1) for k in list(selector.claves.values())]
        selector.select = seleccionar
        funcion = modulo.consultar_actualizaciones if modulo is apt else modulo.consultar_inventario
        with patch.object(modulo.subprocess,'Popen',return_value=proceso) as lanzar, \
             patch.object(modulo.selectors,'DefaultSelector',return_value=selector), \
             patch.object(modulo.os,'read',side_effect=lambda fd,n:bloques[fd].pop(0)), \
             patch.object(modulo.time,'monotonic',side_effect=lambda:reloj[0]):
            datos = funcion(15)
        proceso.__enter__.assert_not_called() if hasattr(proceso,'__enter__') else None
        proceso.__exit__.assert_not_called() if hasattr(proceso,'__exit__') else None
        proceso.stdout.close.assert_called_once()
        proceso.stderr.close.assert_called_once()
        self.assertEqual(lanzar.call_count,1)
        self.assertLessEqual(reloj[0],115.0)
        import json
        self.assertNotIn('SECRETO',json.dumps(datos))
        self.assertNotIn('/privado',json.dumps(datos))
        return datos,proceso,llamadas

    def motivo(self, modulo, datos):
        return datos['motivo'] if modulo is apt else datos['fuente']['motivo']

    def test_terminacion_normal_sin_kill_ni_segunda_espera(self):
        for modulo in (apt,deb):
            with self.subTest(modulo=modulo.__name__):
                datos,proceso,llamadas = self.adquirir(modulo,'normal')
                self.assertEqual(datos['estado_adquisicion'],'completo')
                self.assertIsNone(self.motivo(modulo,datos))
                proceso.kill.assert_not_called()
                proceso.poll.assert_not_called()
                self.assertEqual(len(llamadas),1)
                self.assertEqual(llamadas[0],(100.0,14.0))

    def test_timeout_reserva_limpieza_dentro_del_plazo(self):
        for modulo in (apt,deb):
            with self.subTest(modulo=modulo.__name__):
                datos,proceso,llamadas = self.adquirir(modulo,'timeout')
                self.assertEqual(self.motivo(modulo,datos),'tiempo_agotado')
                self.assertEqual(datos['estado_adquisicion'],'parcial')
                self.assertEqual(llamadas,[(100.0,14.0),(114.0,1.0)])
                proceso.kill.assert_called_once()

    def test_resistente_no_declara_recogida_ni_total_confirmado(self):
        for modulo in (apt,deb):
            with self.subTest(modulo=modulo.__name__):
                datos,proceso,llamadas = self.adquirir(modulo,'resistente')
                self.assertEqual(self.motivo(modulo,datos),'terminacion_no_confirmada')
                self.assertEqual(datos['estado_adquisicion'],'parcial')
                self.assertIsNone(datos['codigo'] if modulo is apt else datos['fuente']['codigo'])
                self.assertIsNone(datos['total_posibles'] if modulo is apt else datos['total_instalados'])
                self.assertEqual(llamadas,[(100.0,14.0),(114.0,1.0)])
                proceso.kill.assert_called_once()

    def test_fallos_de_recogida_y_kill_no_se_convierten_en_exito(self):
        for modulo in (apt,deb):
            for caso in ('error_recogida','error_final','kill_falla','poll_falla','cierre_falla'):
                with self.subTest(modulo=modulo.__name__,caso=caso):
                    datos,proceso,_ = self.adquirir(modulo,caso)
                    self.assertEqual(self.motivo(modulo,datos),'error_recogida')
                    self.assertNotEqual(datos['estado_adquisicion'],'completo')
                    self.assertIsNone(datos['total_posibles'] if modulo is apt else datos['total_instalados'])
                    if caso == 'poll_falla':
                        proceso.kill.assert_not_called()

    def test_error_formato_recoge_sin_borrar_prefijo_valido(self):
        for modulo in (apt,deb):
            with self.subTest(modulo=modulo.__name__):
                datos,proceso,llamadas = self.adquirir(modulo,'formato')
                self.assertEqual(self.motivo(modulo,datos),'formato_invalido')
                filas = datos['candidatos'] if modulo is apt else datos['inventario_dpkg']
                self.assertEqual(len(filas),1)
                self.assertEqual(datos['estado_adquisicion'],'parcial')
                proceso.kill.assert_called_once()
                self.assertEqual(llamadas,[(100.0,15.0)])

    def test_proceso_ya_recogido_no_se_senala_ni_se_espera_de_nuevo(self):
        for modulo in (apt,deb):
            with self.subTest(modulo=modulo.__name__):
                datos,proceso,llamadas = self.adquirir(modulo,'ya_terminado')
                self.assertEqual(self.motivo(modulo,datos),'formato_invalido')
                proceso.kill.assert_not_called()
                self.assertEqual(llamadas,[])

    def test_plazo_agotado_no_introduce_minimo_positivo_ni_reintentos(self):
        proceso = Mock()
        proceso.poll.return_value = None
        proceso.wait.side_effect = deb.subprocess.TimeoutExpired('simulado',0)
        with patch.object(deb.time,'monotonic',return_value=20):
            codigo,motivo = deb._finalizar_proceso(proceso,15,False,None)
        proceso.wait.assert_called_once_with(timeout=0)
        proceso.kill.assert_called_once()
        self.assertEqual((codigo,motivo),(None,'terminacion_no_confirmada'))

    def test_esrch_entre_poll_y_kill_sigue_recogiendo(self):
        proceso = Mock()
        proceso.poll.return_value = None
        proceso.kill.side_effect = ProcessLookupError()
        proceso.wait.return_value = 72
        with patch.object(deb.time,'monotonic',return_value=10):
            self.assertEqual(deb._finalizar_proceso(proceso,15,False,None),(72,None))
        proceso.wait.assert_called_once_with(timeout=5)

    def test_presupuesto_corto_y_cero_no_se_amplian(self):
        for modulo in (apt,deb):
            funcion = modulo.consultar_actualizaciones if modulo is apt else modulo.consultar_inventario
            with patch.object(modulo.subprocess,'Popen') as lanzar, \
                 patch.object(modulo.time,'monotonic',return_value=10):
                datos = funcion(0)
            lanzar.assert_not_called()
            self.assertEqual(self.motivo(modulo,datos),'tiempo_agotado')
            proceso = Mock()
            proceso.poll.return_value = None
            proceso.wait.side_effect = modulo.subprocess.TimeoutExpired('simulado',0)
            with patch.object(modulo.subprocess,'Popen',return_value=proceso), \
                 patch.object(modulo.selectors,'DefaultSelector',return_value=Selector(True)), \
                 patch.object(modulo.time,'monotonic',side_effect=[10,10.08,10.11,10.11]):
                datos = funcion(.1)
            proceso.wait.assert_called_once_with(timeout=0)
            self.assertEqual(self.motivo(modulo,datos),'terminacion_no_confirmada')
            self.assertEqual(datos['estado_adquisicion'],'error')


if __name__ == '__main__':
    unittest.main()
