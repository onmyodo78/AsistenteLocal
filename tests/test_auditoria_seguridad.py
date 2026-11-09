import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import AsistenteLocal as app
import auditoria_seguridad as audit
from test_p0 import respuesta, llamada

RPM = 'kernel-core\t0\t6.18.2\t100.fc44\tx86_64\nopenssl\t1\t3.5.0\t1.fc44\tx86_64\n'


def aviso(paquete='openssl-1:3.5.1-1.fc44.x86_64', ident='FEDORA-2026-abcd'):
    return dict(name=ident, type='security', severity='Important', nevra=paquete, buildtime=1)


class Auditoria(unittest.TestCase):
    def setUp(self):
        parche = patch.object(app, 'seleccionar_backend_seguridad',
                              return_value={'backend': 'fedora', 'estado': 'disponible'})
        parche.start()
        self.addCleanup(parche.stop)

    def consultar(self, rpm=RPM, pendientes='[]', instalados='[]', kernel='6.18.2-100.fc44.x86_64\n'):
        try:
            registros = audit.inventario(rpm)
            fuente_rpm = dict(estado='correcta', codigo=0, registros=registros)
        except ValueError:
            fuente_rpm = dict(estado='error', codigo=0, registros=[], motivo='formato_invalido')
        with patch.object(app, 'consultar_inventario', return_value=fuente_rpm), \
             patch.object(app, 'metricas_auditoria'), \
             patch.object(app, 'ejecutar_comando', side_effect=[
                (0, kernel, '', False),
                (0, ''.join(l + '\n' for l in rpm.splitlines() if l.startswith('kernel-core\t')), '', False),
                (0, pendientes, '', False), (0, instalados, '', False)]) as run, \
             patch.object(app, 'abrir_http_local', side_effect=AssertionError('HTTP')):
            datos = app.consultar_auditoria_seguridad(time.monotonic() + 120)
        self.assertEqual([c.args[0] for c in run.call_args_list], [list(audit.CONSULTAS[0][1]), list(audit.CONSULTAS[2][1]), audit.comando_aislado('pendientes'), audit.comando_aislado('instalados')])
        self.assertTrue(all(0 < c.args[1] <= 15 for c in run.call_args_list))
        return datos

    def test_sin_actualizaciones(self):
        datos = self.consultar()
        self.assertEqual(datos['recuentos']['avisos_pendientes'], 0)
        self.assertFalse(datos['reinicio_pendiente_kernel'])
        self.assertEqual(datos['estado_adquisicion'], 'completo')
        self.assertEqual(datos['inventario_rpm'][1]['epoch'], 1)

    def test_agrupacion_y_estados(self):
        filas = [aviso(), aviso('openssl-libs-1:3.5.1-1.fc44.x86_64'), aviso()]
        datos = self.consultar(pendientes=json.dumps(filas), instalados=json.dumps([aviso(ident='FEDORA-2026-old')]))
        self.assertEqual(datos['recuentos']['avisos_pendientes'], 1)
        self.assertEqual(len(datos['avisos_pendientes'][0]['paquetes']), 2)
        self.assertEqual(datos['recuentos']['avisos_instalados'], 1)
        self.assertFalse(datos['reinicio_pendiente_kernel'])

    def test_kernel_nuevo(self):
        datos = self.consultar(rpm=RPM + 'kernel-core\t0\t6.18.10\t100.fc44\tx86_64\n')
        self.assertTrue(datos['reinicio_pendiente_kernel'])
        self.assertEqual(datos['kernels_mas_recientes_no_activos'], ['6.18.10-100.fc44.x86_64'])

    def test_kernel_antiguo_no_implica_reinicio(self):
        self.assertFalse(self.consultar(rpm=RPM + 'kernel-core\t0\t6.18.1\t100.fc44\tx86_64\n')['reinicio_pendiente_kernel'])

    def test_kernel_desconocido(self):
        for kernel in ['6.18.2-custom', '6.19.0-0.rc1.fc44.x86_64']:
            self.assertIsNone(self.consultar(kernel=kernel)['reinicio_pendiente_kernel'])
        self.assertIsNone(self.consultar(rpm=RPM.replace('kernel-core\t0', 'kernel-core\t1'))['reinicio_pendiente_kernel'])

    def test_otras_arquitecturas(self):
        self.assertFalse(self.consultar(rpm=RPM + 'kernel-core\t0\t6.19.0\t100.fc44\taarch64\n')['reinicio_pendiente_kernel'])

    def test_formatos_invalidos(self):
        for texto in ['', '{}', '[{}]', '[{"name":"a","name":"b"}]', 'No security updates needed']:
            datos = self.consultar(pendientes=texto)
            self.assertIsNone(datos['recuentos']['avisos_pendientes'])
            self.assertEqual(datos['fuentes']['pendientes']['estado'], 'formato_invalido')
        self.assertIsNone(self.consultar(rpm='invalido')['inventario_rpm'])

    def test_errores_consulta(self):
        for resultado in [(1, 'secreto', 'secreto', False), (0, RPM, '', True), (0, RPM, 'aviso', False)]:
            with patch.object(app, 'consultar_inventario', return_value=dict(estado='error', codigo=1, registros=[])), patch.object(app, 'metricas_auditoria'), patch.object(app, 'ejecutar_comando', return_value=resultado):
                datos = app.consultar_auditoria_seguridad(time.monotonic() + 120)
            self.assertEqual(datos['estado_adquisicion'], 'error')
            self.assertNotIn('secreto', json.dumps(datos))
            self.assertIsNone(datos['recuentos']['avisos_pendientes'])

    def test_excepciones(self):
        for error in [FileNotFoundError(), PermissionError(), OSError(), TimeoutError()]:
            with patch.object(app, 'consultar_inventario', side_effect=error), patch.object(app, 'metricas_auditoria'), patch.object(app, 'ejecutar_comando', side_effect=error):
                self.assertEqual(app.consultar_auditoria_seguridad(time.monotonic() + 120)['estado_adquisicion'], 'error')

    def test_plazo_vencido(self):
        with patch.object(app, 'ejecutar_comando') as run, self.assertRaises(TimeoutError):
            app.consultar_auditoria_seguridad(time.monotonic() - 1)
        run.assert_not_called()

    def test_json_acotado(self):
        datos = self.consultar()
        datos['inventario_rpm'] *= 2000
        for limite in [18000, 2500, 100, 0]:
            texto = audit.serializar(datos, limite)
            self.assertLessEqual(len(texto), limite)
            if texto:
                self.assertIn(json.loads(texto)['estado_presentacion'], ['parcial', 'omitido_por_limite'])

    def test_registro_y_cache_independiente_de_externas(self):
        self.assertEqual(len(app.TOOLS), 14)
        for permitir in (False, True):
            with patch.object(app, 'ALLOW_EXTERNAL', permitir):
                self.assertIn('auditoria_seguridad', app.herramientas_disponibles())
        for _, comando in audit.CONSULTAS[3:]:
            self.assertIn('--cacheonly', comando)
            self.assertIn('--no-plugins', comando)
            self.assertNotIn('sudo', comando)

    def test_presupuesto_conversacional(self):
        datos = self.consultar()
        datos['inventario_rpm'] *= 1000
        with patch.object(app, 'MAX_TOTAL_OUTPUT', 2500), \
             patch.object(app, 'consultar_auditoria_seguridad', return_value=datos) as adquirir, \
             patch.object(app, 'consultar_modelo', side_effect=[respuesta([llamada('auditoria_seguridad')]), respuesta(content='Fin')]) as modelo, \
             contextlib.redirect_stdout(io.StringIO()):
            app.preguntar('audita')
        adquirir.assert_called_once()
        mensajes = [m for m in modelo.call_args.args[0] if m['role'] == 'tool']
        self.assertLessEqual(len(mensajes[0]['content']), 2500)
        self.assertNotIn('inventario_rpm', json.loads(mensajes[0]['content']))

    def test_inventario_parcial_conserva_kernel_y_avisos(self):
        fuente = dict(estado='parcial', codigo=-9, motivo='limite_bytes', registros=audit.inventario(RPM))
        with patch.object(app, 'consultar_inventario', return_value=fuente), \
             patch.object(app, 'metricas_auditoria'), \
             patch.object(app, 'ejecutar_comando', side_effect=[
                (0, '6.18.1-100.fc44.x86_64', '', False),
                (0, RPM.splitlines()[0] + '\n', '', False),
                (0, '[]', '', False), (0, '[]', '', False)]):
            datos = app.consultar_auditoria_seguridad(time.monotonic() + 120)
        self.assertEqual(datos['estado_adquisicion'], 'parcial')
        self.assertEqual(len(datos['inventario_rpm']), 2)
        self.assertFalse(datos['inventario_completo'])
        self.assertIsNone(datos['recuentos']['paquetes_rpm'])
        self.assertEqual(datos['recuentos']['paquetes_rpm_recogidos'], 2)
        self.assertTrue(datos['reinicio_pendiente_kernel'])
        self.assertEqual(datos['recuentos']['avisos_pendientes'], 0)

    def test_aviso_puede_tener_ambos_estados(self):
        filas = json.dumps([aviso()])
        datos = self.consultar(pendientes=filas, instalados=filas)
        self.assertEqual(datos['avisos_pendientes'][0]['id'], datos['avisos_instalados'][0]['id'])

    def test_plazo_tras_adquirir_no_publica(self):
        with patch.object(app, 'restante', side_effect=[10, 10, TimeoutError(), TimeoutError()]), \
             patch.object(app, 'ejecutar_comando', return_value=(0, 'kernel', '', False)) as run, \
             self.assertRaises(TimeoutError):
            app.consultar_auditoria_seguridad(1)
        run.assert_called_once()

    def test_compatibilidad_dnf_y_error_cerrado(self):
        self.assertNotIn('--setopt=logfilelevel=0', audit.DNF)
        self.assertIn('--setopt=logdir=/proc/self/fd', audit.DNF)
        for codigo, stderr, esperado in [(0, audit.AVISO_LOG_DNF, 'correcta'),
                (0, '', 'correcta'),
                (0, 'Updating and loading repositories:\nRepositories loaded.\n', 'avisos_no_interpretados'),
                (0, 'otro aviso', 'avisos_no_interpretados'),
                (1, 'Error: repository unavailable', 'error_comando'),
                (100, '', 'error_comando'),
                (78, '', 'aislamiento_no_disponible'), (69, '', 'ejecutable_ausente')]:
            with patch.object(app, 'consultar_inventario', return_value=dict(estado='error',codigo=1,registros=[])), \
                 patch.object(app, 'ejecutar_comando', return_value=(codigo,'[]',stderr,False)) as run, \
                 patch.object(app, 'metricas_auditoria'):
                datos=app.consultar_auditoria_seguridad(time.monotonic()+120)
            self.assertEqual(datos['fuentes']['pendientes']['estado'], esperado)
            self.assertEqual(run.call_args_list[-1].args[0], audit.comando_aislado('instalados'))

    def test_timeout_conserva_hechos_y_no_reintenta(self):
        datos=self.consultar(pendientes=json.dumps([aviso()]))
        respuestas=[respuesta([llamada('auditoria_seguridad')]), TimeoutError('simulado')]
        def modelo(*args, **kwargs):
            if len(respuestas)==1:
                self.assertIn('Hechos de auditoria_seguridad', salida.getvalue())
                self.assertIn('Avisos de seguridad pendientes: 1', salida.getvalue())
            siguiente=respuestas.pop(0)
            if isinstance(siguiente, Exception):
                raise siguiente
            return siguiente
        with patch.object(app,'consultar_auditoria_seguridad',return_value=datos) as adquirir, \
             patch.object(app,'consultar_modelo',side_effect=modelo) as consultar, \
             contextlib.redirect_stdout(io.StringIO()) as salida:
            app.preguntar('audita')
        adquirir.assert_called_once()
        self.assertEqual(consultar.call_count,2)
        self.assertIn('fallo de interpretación no cambia la adquisición',salida.getvalue())
        self.assertIn('No se reintenta',salida.getvalue())

    def test_inventario_nunca_en_modelo(self):
        datos=self.consultar()
        datos['inventario_rpm'] *= 5000
        texto=audit.ResultadoAuditoria(datos,18000)
        self.assertLessEqual(len(texto),audit.MAX_RESUMEN)
        self.assertNotIn('inventario_rpm',json.loads(texto))
        self.assertNotIn('openssl',str(texto))
        self.assertEqual(len(texto.datos['inventario_rpm']),10000)
        copia=texto.datos
        copia['inventario_rpm'].clear()
        self.assertEqual(len(texto.datos['inventario_rpm']),10000)

    def test_metricas_no_contienen_datos(self):
        with contextlib.redirect_stderr(io.StringIO()) as out:
            audit.registrar_metricas('rpm',dict(estado='correcta',codigo=0,duracion_s=.1,stdout_bytes=100,
                stderr_bytes=0,registros_recogidos=10,stdout='SECRETO',stderr='PIN',registros=['inventario']))
        texto=out.getvalue()
        self.assertNotIn('SECRETO',texto)
        self.assertNotIn('PIN',texto)
        self.assertNotIn('inventario',texto)
        self.assertEqual(json.loads(texto.split(' ',1)[1])['registros_recogidos'],10)

    def test_claves_rpm_sin_arquitectura_no_son_paquetes_vulnerables(self):
        filas = audit.inventario('gpg-pubkey\t0\t1234abcd\t9876abcd\t(none)\n')
        self.assertIsNone(filas[0]['arquitectura'])
        with self.assertRaises(ValueError):
            audit.inventario('kernel-core\t0\t1\t1.fc44\t(none)\n')

    def test_compacto_siempre_acotado_sin_inventario(self):
        datos=self.consultar(pendientes=json.dumps([aviso(ident='FEDORA-2026-'+str(i)) for i in range(40)]))
        resultado=audit.ResultadoAuditoria(datos,18000)
        self.assertEqual(json.loads(resultado)['recuentos']['avisos_pendientes'],40)
        self.assertEqual(len(json.loads(resultado)['avisos_pendientes']),10)
        self.assertEqual(json.loads(resultado)['estado_presentacion'],'parcial')
        for limite in (5000,1500,100,0):
            texto=resultado.ajustar(limite)
            self.assertLessEqual(len(texto),limite)
            if texto:
                self.assertNotIn('inventario_rpm',json.loads(texto))

    def test_interpretacion_length_y_fallo_inicial(self):
        datos=self.consultar()
        final=respuesta(content='incompleto')
        final['choices'][0]['finish_reason']='length'
        with patch.object(app,'consultar_auditoria_seguridad',return_value=datos), \
             patch.object(app,'consultar_modelo',side_effect=[respuesta([llamada('auditoria_seguridad')]),final]), \
             contextlib.redirect_stdout(io.StringIO()) as out:
            app.preguntar('audita')
        self.assertIn('fallo de interpretación',out.getvalue())
        self.assertNotIn('Asistente: incompleto',out.getvalue())
        with patch.object(app,'consultar_modelo',side_effect=TimeoutError()), self.assertRaises(TimeoutError):
            app.preguntar('audita')


class InventarioIncremental(unittest.TestCase):
    def leer(self,codigo,timeout=3):
        return audit._leer_inventario([sys.executable,'-B','-c',codigo],timeout)

    def test_grande_completo_mayor_64k(self):
        resultado=self.leer("import sys; [sys.stdout.write('paquete%d\\t0\\t1.0\\t1.fc44\\tx86_64\\n' % i) for i in range(5000)]")
        self.assertEqual(resultado['estado'],'correcta')
        self.assertEqual(len(resultado['registros']),5000)
        self.assertGreater(resultado['stdout_bytes'],65536)
        self.assertLessEqual(resultado['stdout_bytes'],audit.MAX_INVENTARIO_BYTES)

    def test_limites_conservan_prefijo(self):
        codigo="import sys; sys.stdout.write(('pkg\\t0\\t1\\t1.fc44\\tx86_64\\n')*10000)"
        for campo,limite,motivo in [('MAX_PAQUETES',5,'limite_registros'),('MAX_INVENTARIO_BYTES',5000,'limite_bytes')]:
            with self.subTest(campo=campo),patch.object(audit,campo,limite):
                resultado=self.leer(codigo)
            self.assertEqual(resultado['estado'],'parcial')
            self.assertEqual(resultado['motivo'],motivo)
            self.assertTrue(resultado['registros'])

    def test_timeout_y_error_conservan_filas(self):
        for final,motivo in [("import time; time.sleep(2)",'tiempo_agotado'),("sys.exit(2)",'error_comando')]:
            resultado=self.leer("import sys; sys.stdout.write('pkg\\t0\\t1\\t1.fc44\\tx86_64\\n'); sys.stdout.flush(); "+final,.15)
            self.assertEqual(resultado['motivo'],motivo)
            self.assertEqual(len(resultado['registros']),1)
            self.assertEqual(resultado['estado'],'parcial')

    def test_lineas_invalidas_y_ultima_incompleta(self):
        codigo="import sys; sys.stdout.write('pkg\\t0\\t1\\t1.fc44\\tx86_64\\nINVALIDA\\nprefijo')"
        resultado=self.leer(codigo)
        self.assertEqual(resultado['motivo'],'formato_invalido')
        self.assertEqual(len(resultado['registros']),1)

    def test_linea_excesiva_y_stderr(self):
        for codigo,motivo in [("print('x'*5000)",'limite_linea'),("import sys; sys.stderr.write('x'*10000)",'limite_stderr')]:
            resultado=self.leer(codigo)
            self.assertEqual(resultado['motivo'],motivo)
            self.assertEqual(resultado['estado'],'error')

    def test_limite_total_tambien_en_stderr(self):
        with patch.object(audit,'MAX_INVENTARIO_BYTES',50):
            resultado=self.leer("import sys; sys.stderr.write('x'*1000)")
        self.assertEqual(resultado['motivo'],'limite_bytes')
        self.assertLessEqual(resultado['stdout_bytes']+resultado['stderr_bytes'],51)


class Aislamiento(unittest.TestCase):
    def test_error_antes_de_exec(self):
        import auditoria_aislamiento as aislado
        with patch.object(aislado.sys,'argv',['helper','pendientes']), \
             patch.object(aislado,'restringir',side_effect=OSError()), \
             patch.object(aislado.os,'execvpe') as ejecutar:
            self.assertEqual(aislado.main(),78)
        ejecutar.assert_not_called()

    def test_modo_desconocido_no_ejecuta(self):
        import auditoria_aislamiento as aislado
        with patch.object(aislado.sys,'argv',['helper','install']), \
             patch.object(aislado,'restringir') as restringir:
            self.assertEqual(aislado.main(),78)
        restringir.assert_not_called()

    def test_escrituras_metadatos_y_sockets_denegados(self):
        with tempfile.TemporaryDirectory(dir=Path(app.__file__).parent) as tmp:
            archivo=Path(tmp)/'sintetico.txt'
            archivo.write_text('original')
            script="""
import errno,json,os,socket,sys
from auditoria_aislamiento import restringir
try: restringir()
except Exception: sys.exit(78)
resultados=[]
for accion in (lambda:open(sys.argv[1],'w'),lambda:os.chmod(sys.argv[1],0o777),
               lambda:socket.socket(),lambda:os.unlink(sys.argv[1])):
    try: accion(); resultados.append(False)
    except PermissionError: resultados.append(True)
print(json.dumps(resultados))
"""
            proceso=subprocess.run([sys.executable,'-B','-c',script,str(archivo)],capture_output=True,timeout=3)
            if proceso.returncode==78:
                self.skipTest('Landlock/seccomp no disponibles: DNF debe fallar cerrado')
            self.assertEqual(proceso.returncode,0,proceso.stderr)
            self.assertEqual(json.loads(proceso.stdout),[True]*4)
            self.assertEqual(archivo.read_text(),'original')
