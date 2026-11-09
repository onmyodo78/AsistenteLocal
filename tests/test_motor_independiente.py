"""Motor/CLI simulados: no ejecutan procesos, APT, DNF, sockets ni LM Studio."""
import contextlib
import copy
import io
import json
import subprocess
import sys
import time
import types
import unittest
from unittest.mock import Mock, patch

import cli
import mantenimiento as motor
import motor_auditoria as auditoria
import mantenimiento_transporte as transporte
import mantenimiento_worker as worker
from adaptadores.debian import Debian, parsear_simulacion
from adaptadores.fedora import Fedora, parsear_transaccion, parsear_filas
from contratos_mantenimiento import base, componente, finalizar, validar, paquete
from distribucion_linux import detectar_distribucion


def instalado(n='uno', v='1', a='amd64', hold=False):
    return dict(nombre_binario=n, arquitectura=a, version=v, categoria='instalado',
                estado_instalacion=('hold' if hold else 'install') + ' ok installed')


def apt_salida():
    return ('Reading package lists...\n'
        '1 upgraded, 1 newly installed, 1 to remove and 1 not upgraded.\n'
        'Inst uno [1] (2 Debian:13/stable [amd64])\n'
        'Inst dos (3 Debian:13/stable [amd64])\n'
        'Remv viejo [1]\n'
        'Conf uno (2 Debian:13/stable [amd64])\n'
        'Conf dos (3 Debian:13/stable [amd64])\n')


def resultado(stdout='', estado='completo', error=None, codigo=0):
    return dict(stdout=stdout, estado=estado, error=error, codigo=codigo)


def simulacion():
    s = base('debian13','apt','plan')['simulacion']
    s.update(estado='completo', retenciones_estado='completo')
    s['actualizaciones'] = [paquete('uno','amd64','1','2')]
    return s


class SinProcesos(unittest.TestCase):
    def setUp(self):
        p = patch('subprocess.Popen', side_effect=AssertionError('Proceso real prohibido'))
        p.start()
        self.addCleanup(p.stop)
        import socket
        p = patch.object(socket, 'socket', side_effect=AssertionError('Socket prohibido'))
        p.start()
        self.addCleanup(p.stop)


class Apt(SinProcesos):
    def test_acciones_versiones_y_retenciones(self):
        d = parsear_simulacion(apt_salida().replace(' [amd64])', ' [amd64]) []'), [instalado(), instalado('viejo'), instalado('retenido',hold=True)])
        self.assertEqual(d['actualizaciones'], [paquete('uno','amd64','1','2')])
        self.assertEqual(d['instalaciones'], [paquete('dos','amd64',None,'3')])
        self.assertEqual(d['eliminaciones'], [paquete('viejo','amd64','1',None)])
        self.assertEqual(d['retenciones'][0]['nombre'], 'retenido')
        self.assertEqual(d['no_actualizados_total'], 1)

    def test_cero_verificado_necesita_resumen(self):
        d = parsear_simulacion('0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n', [])
        self.assertEqual(d['actualizaciones'], [])
        for texto in ('', 'Reading package lists...\n', '0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\nW: aviso\n'):
            with self.assertRaises(ValueError):
                parsear_simulacion(texto, [])

    def test_no_acepta_formato_incompleto_o_inconsistente(self):
        for texto in (apt_salida().replace('1 upgraded','2 upgraded'),
                      apt_salida().replace('[1] (2','[9] (2'),
                      apt_salida().replace(' [amd64]', ''),
                      apt_salida() + 'Purg uno\n',
                      apt_salida() + 'Conf otro (1 Debian [amd64])\n'):
            with self.subTest(texto=texto), self.assertRaises(ValueError):
                parsear_simulacion(texto, [instalado(), instalado('viejo')])

    def test_anotaciones_transitorias_reconciliadas(self):
        texto = apt_salida().replace('Inst uno [1] (2 Debian:13/stable [amd64])',
            'Inst uno [1] (2 Debian:13/stable [amd64]) [dos:amd64 ]')
        self.assertEqual(len(parsear_simulacion(texto, [instalado(),instalado('viejo')])['actualizaciones']),1)
        for modificado in (texto.replace('Conf dos (3 Debian:13/stable [amd64])',
                                        'Conf dos (3 Debian:13/stable [amd64]) [dos:amd64 ]'),
                           texto.replace('[dos:amd64 ]','[desconocido:amd64 ]'),
                           texto.replace('Conf dos (3 Debian:13/stable [amd64])','')):
            with self.assertRaises(ValueError):
                parsear_simulacion(modificado, [instalado(),instalado('viejo')])

    def test_fallo_nativo_no_es_cero_actualizaciones(self):
        with patch('adaptadores.debian.ejecutar', return_value=resultado(apt_salida(),'error','tiempo_agotado')):
            s = Debian().simular(time.monotonic()+120, {'estado_inventario':'completo','inventario_dpkg':[instalado()]})
        self.assertEqual(s['estado'], 'error')
        self.assertEqual(s['errores'], ['tiempo_agotado'])

    def test_inventario_parcial_no_valida_simulacion(self):
        with patch('adaptadores.debian.ejecutar', return_value=resultado(apt_salida())):
            s = Debian().simular(time.monotonic()+120, {'estado_inventario':'parcial'})
        self.assertEqual(s['estado'], 'no_verificable')

    def test_capacidades_no_se_inventan_por_binario(self):
        with patch('adaptadores.debian.os.path.isfile', return_value=True), \
             patch('adaptadores.debian.os.access', return_value=True), \
             patch('adaptadores.debian.ejecutar', return_value=resultado('apt 99.0')):
            self.assertFalse(Debian().capacidades(time.monotonic()+120)['simulacion'])

    def test_candidatas_no_dependen_de_simulacion(self):
        datos = dict(estado_inventario='completo', actualizaciones=dict(estado_adquisicion='completo', motivo=None,
            candidatos=[dict(nombre_binario='uno',arquitectura='amd64',instalada='1',candidata='2',superior=True)]))
        with patch('adaptadores.debian.consultar_auditoria', return_value=datos):
            c, _ = Debian().consultar(time.monotonic()+120)
        self.assertEqual(c['paquetes'], [paquete('uno','amd64','1','2')])
        self.assertEqual(c['estado'], 'completo')


class Dnf(SinProcesos):
    def acciones(self):
        return dict(version=1,resolvedor='dnf4',acciones=[
            dict(accion='actualizar',nombre='uno',arquitectura='x86_64',version='0:2-1'),
            dict(accion='reemplazado',nombre='uno',arquitectura='x86_64',version='0:1-1'),
            dict(accion='instalar',nombre='dos',arquitectura='noarch',version='0:3-1'),
            dict(accion='eliminar',nombre='viejo',arquitectura='x86_64',version='0:1-1')])

    def inventario(self):
        return [paquete(n,'x86_64','0:1-1',None) for n in ('uno','viejo')]

    def test_transaccion_nativa_y_contrato_comun(self):
        s = parsear_transaccion(json.dumps(self.acciones()), self.inventario())
        self.assertEqual(s['actualizaciones'], [paquete('uno','x86_64','0:1-1','0:2-1')])
        self.assertEqual(s['eliminaciones'][0]['nombre'], 'viejo')
        self.assertEqual(s['instalaciones'][0]['nombre'], 'dos')

    def test_accion_desconocida_reemplazo_suelto_version_ambigua(self):
        acciones = self.acciones()
        acciones['acciones'][0]['accion'] = 'comando'
        with self.assertRaises(ValueError):
            parsear_transaccion(json.dumps(acciones), self.inventario())
        with self.assertRaises(ValueError):
            parsear_transaccion(json.dumps(self.acciones()), self.inventario() + [paquete('uno','x86_64','0:0-1',None)])

    def test_listado_estricto_sin_tablas_humanas(self):
        self.assertEqual(parsear_filas('uno\tx86_64\t0:2-1\n')[0]['anterior'], '0:2-1')
        with self.assertRaises(ValueError):
            parsear_filas('Last metadata expiration check: now\n')

    def test_dnf5_aborto_nunca_confirma_simulacion(self):
        a = Fedora()
        a.gestor = 'dnf5'
        # Sin binding no se permite ni sondeo de aborto ni simulación textual.
        with patch('adaptadores.fedora.importlib.util.find_spec',return_value=None), patch('adaptadores.fedora.ejecutar', side_effect=AssertionError('sondeo innecesario')):
            s = a.simular(time.monotonic()+120, self.inventario())
        self.assertEqual(s['estado'], 'no_verificable')

    def test_dnf4_json_invalido_conserva_contrato_en_motor_y_cli(self):
        a = Fedora()
        a.gestor = 'dnf'
        distro = dict(estado='soportado', id='fedora', version_id='44')
        capacidades = dict(consulta=True, simulacion=True, ejecucion=False, solo_cache=True, sin_red=True)
        candidatas = componente('completo', [paquete('uno','x86_64','0:1-1','0:2-1')])
        with patch.object(a, 'capacidades', return_value=capacidades), \
             patch.object(a, 'consultar', return_value=(candidatas, self.inventario())), \
             patch('adaptadores.fedora.ejecutar', return_value=resultado('JSON INVALIDO')):
            s = a.simular(time.monotonic()+120, self.inventario())
            self.assertEqual(set(s), set(base('fedora','dnf','plan')['simulacion']))
            self.assertEqual(s['estado'], 'no_verificable')
            self.assertEqual(s['retenciones_estado'], 'no_comprobada')
            self.assertIsNone(s['no_actualizados_total'])
            self.assertEqual(s['errores'], ['transaccion_dnf_no_interpretada'])
            for clave in ('actualizaciones','instalaciones','eliminaciones','retenciones'):
                self.assertEqual(s[clave], [])
            def consultar(operacion):
                return motor.consultar(operacion, distribucion=distro, adaptador=a)
            d = consultar('plan')
            validar(d)
            self.assertEqual(d['estado'], 'parcial')
            self.assertEqual(d['simulacion'], s)
            self.assertEqual(d['candidatas'], candidatas)
            self.assertEqual(d['comparacion']['estado'], 'no_comprobada')
            self.assertFalse(d['ejecucion_habilitada'])
            for formato in ('json','texto'):
                with self.subTest(formato=formato), \
                     patch.object(cli, 'consultar', side_effect=consultar), \
                     patch.object(cli.os, 'geteuid', return_value=1000), \
                     contextlib.redirect_stdout(io.StringIO()) as salida:
                    self.assertEqual(cli.main(['--formato',formato,'plan']), 3)
                if formato == 'json':
                    publicado = json.loads(salida.getvalue())
                    validar(publicado)
                    self.assertEqual(publicado, d)
                else:
                    self.assertIn('Simulación del resolvedor: no_verificable', salida.getvalue())
                    self.assertIn('transaccion_dnf_no_interpretada', salida.getvalue())
                self.assertNotIn('operacion_fallida', salida.getvalue())

    def test_binding_dnf4_resuelve_sin_ejecutar_transaccion(self):
        base_dnf = Mock()
        base_dnf.__enter__ = Mock(return_value=base_dnf)
        base_dnf.__exit__ = Mock(return_value=None)
        base_dnf.resolve.return_value = True
        base_dnf.transaction = [types.SimpleNamespace(action=1,
            pkg=types.SimpleNamespace(name='uno',arch='x86_64',evr='0:2-1'))]
        dnf = types.ModuleType('dnf')
        dnf.__path__ = []
        dnf.Base = Mock(return_value=base_dnf)
        tr = types.ModuleType('dnf.transaction')
        tr.PKG_UPGRADE = 1
        with patch.dict(sys.modules, {'dnf':dnf,'dnf.transaction':tr}), \
             patch.dict(worker.os.environ, {'TMPDIR':'/tmp/simulado'}), \
             contextlib.redirect_stdout(io.StringIO()) as salida:
            codigo = worker.resolver_dnf()
        self.assertEqual(codigo,0)
        self.assertEqual(json.loads(salida.getvalue())['resolvedor'],'dnf4')
        base_dnf.resolve.assert_called_once_with()
        base_dnf.do_transaction.assert_not_called()
        base_dnf.download_packages.assert_not_called()
        self.assertTrue(base_dnf.conf.cacheonly)
        self.assertFalse(base_dnf.conf.plugins)


class Motor(SinProcesos):
    def adaptador(self, distro='debian13', gestor='apt'):
        a = Mock(distribucion=distro, gestor=gestor)
        a.capacidades.return_value = dict(consulta=True,simulacion=True,ejecucion=False,solo_cache=True,sin_red=True)
        a.consultar.return_value = (componente('completo', [paquete('uno','amd64','1','2'),paquete('retenido','amd64','1','2')]), {})
        a.simular.return_value = simulacion()
        return a

    def test_independiente_y_compara_candidatas_con_resolvedor(self):
        a = self.adaptador()
        d = motor.consultar(adaptador=a)
        validar(d)
        self.assertEqual(d['estado'], 'completo')
        self.assertEqual(d['comparacion']['no_previstas'][0]['nombre'], 'retenido')
        self.assertFalse(d['ejecucion_habilitada'])

    def test_contratos_debian_fedora_compatibles(self):
        documentos=[]
        for distro, gestor in [('debian13','apt'),('fedora','dnf')]:
            d = motor.consultar(adaptador=self.adaptador(distro,gestor))
            validar(d)
            documentos.append(d)
        self.assertEqual(set(documentos[0]),set(documentos[1]))
        self.assertEqual(set(documentos[0]['simulacion']),set(documentos[1]['simulacion']))

    def test_fallo_parcial_no_oculta_candidatas(self):
        a = self.adaptador()
        a.simular.side_effect = TimeoutError()
        d = motor.consultar(adaptador=a)
        self.assertEqual(d['estado'], 'parcial')
        self.assertEqual(len(d['candidatas']['paquetes']), 2)
        self.assertEqual(d['simulacion']['estado'], 'error')
        self.assertEqual(d['comparacion']['estado'], 'no_comprobada')
        a.simular.assert_called_once()
        a.consultar.assert_called_once()

    def test_simulacion_sin_capacidad_no_se_ejecuta(self):
        a = self.adaptador()
        a.capacidades.return_value['simulacion'] = False
        d = motor.consultar(adaptador=a)
        self.assertEqual(d['simulacion']['estado'],'no_disponible')
        a.simular.assert_not_called()

    def test_consulta_y_capacidades_no_simulan(self):
        for op in ('capacidades','actualizaciones'):
            a=self.adaptador()
            d=motor.consultar(op,adaptador=a)
            a.simular.assert_not_called()
            self.assertEqual(d['simulacion']['estado'],'no_realizada')

    def test_no_amplia_distribuciones_ni_operaciones(self):
        for texto in ('ID=ubuntu\nVERSION_ID=24.04\nID_LIKE=debian','ID=debian\nVERSION_ID=12'):
            d = motor.consultar(distribucion=detectar_distribucion(contenido=texto))
            self.assertEqual(d['estado'],'no_disponible')
        with self.assertRaises(ValueError):
            motor.consultar('actualizar')

    def test_determinismo_y_huella_no_autoriza(self):
        a=self.adaptador()
        d=motor.consultar(adaptador=a)
        otro=motor.consultar(adaptador=self.adaptador())
        self.assertEqual(d,otro)
        d['candidatas']['paquetes'][0]['propuesta']='9'
        with self.assertRaises(ValueError):
            validar(d)
        d['ejecucion_habilitada']=True
        with self.assertRaises(ValueError):
            finalizar(d)

    def test_no_valida_simulacion_con_versiones_desconocidas(self):
        d=base('fedora','dnf','plan')
        d['simulacion']=simulacion()
        d['simulacion']['actualizaciones'][0]['anterior']=None
        with self.assertRaises(ValueError):
            finalizar(d)


class CLI(SinProcesos):
    def test_json_y_codigos_sin_lmstudio(self):
        for estado, codigo in [('completo',0),('parcial',3),('error',1)]:
            d=base('debian13','apt','actualizaciones')
            d['estado']=estado
            d=finalizar(d)
            with patch.object(cli,'consultar',return_value=d), patch.object(cli.os,'geteuid',return_value=1000), \
                 contextlib.redirect_stdout(io.StringIO()) as salida:
                self.assertEqual(cli.main(['--formato','json','actualizaciones']),codigo)
            self.assertEqual(json.loads(salida.getvalue())['version'],1)

    def test_no_hay_operacion_de_ejecucion(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            cli.main(['actualizar'])

    def test_texto_separa_candidatas_y_resolvedor(self):
        d=finalizar(base('debian13','apt','plan'))
        texto=cli.informe_plan(d)
        self.assertIn('Candidatas (no son una transacción)',texto)
        self.assertIn('Simulación del resolvedor: no_realizada',texto)
        self.assertIn('Ejecución real: no autorizada por este plan',texto)

    def test_no_permite_root(self):
        with patch.object(cli.os,'geteuid',return_value=0), patch.object(cli,'consultar') as consultar, \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(['plan']),1)
        consultar.assert_not_called()

    def test_auditoria_reutiliza_fuentes_y_presentacion(self):
        datos={'backend':'debian','estado_inventario':'completo','total_instalados':3109,
               'actualizaciones':{'estado_adquisicion':'completo','total_posibles':35},'estado_adquisicion':'completo'}
        with patch.object(cli,'auditar',return_value=datos), patch.object(cli.os,'geteuid',return_value=1000), \
             contextlib.redirect_stdout(io.StringIO()) as salida:
            self.assertEqual(cli.main(['auditoria']),0)
        self.assertIn('3109',salida.getvalue())
        self.assertIn('35',salida.getvalue())


class Seguridad(SinProcesos):
    def test_quiet_solo_en_consulta_dnf5_de_datos(self):
        comandos = worker.comandos()
        self.assertEqual(comandos['dnf5-consultar'], ('/usr/bin/dnf5', '-q',
            '--cacheonly', '--no-plugins', 'repoquery', '--upgrades',
            '--qf', '%{name}\t%{arch}\t%{evr}'))
        self.assertEqual(comandos['dnf5-version'], ('/usr/bin/dnf5', '--version'))
        self.assertNotIn('-q', comandos['dnf-consultar'])
        self.assertFalse(any('check-update' in c or 'check-upgrade' in c
                             for c in comandos.values()))

    def test_catalogo_sin_operacion_modificadora(self):
        for modo, comando in worker.comandos().items():
            self.assertTrue(comando[0].startswith('/usr/bin/'))
            self.assertNotIn('update',comando)
            if 'upgrade' in comando:
                self.assertIn('--assumeno',comando)
            if 'dist-upgrade' in comando:
                self.assertIn('--simulate',comando)
            self.assertNotIn('sudo',comando)
        with self.assertRaises(ValueError):
            transporte.ejecutar('apt-instalar',time.monotonic()+120)

    def test_worker_rechaza_argumentos_libres_antes_de_aislar(self):
        with patch.object(worker.sys,'argv',['worker','apt-simular','--yes']):
            self.assertEqual(worker.main(),78)

    def test_worker_falla_cerrado_sin_temporal_privado(self):
        with patch.object(worker.sys,'argv',['worker','apt-simular']), \
             patch.object(worker.os,'geteuid',return_value=1000), \
             patch.dict(worker.os.environ,{'ASISTENTE_TEMPORAL':'/var/lib/dpkg'}), \
             patch.object(worker.os,'execve') as ejecutar:
            self.assertEqual(worker.main(),78)
        ejecutar.assert_not_called()

    def test_transporte_root_y_plazo_agotado_no_lanzan(self):
        with patch.object(transporte.os,'geteuid',return_value=0):
            self.assertEqual(transporte.ejecutar('apt-simular',time.monotonic()+120)['error'],'ejecucion_root_rechazada')
        with patch.object(transporte.os,'geteuid',return_value=1000):
            self.assertEqual(transporte.ejecutar('apt-simular',time.monotonic()-1)['error'],'tiempo_agotado')

    def test_auditoria_correlacion_debian_no_adquiere(self):
        seleccion=dict(backend='debian',distribucion={'id':'debian','version_id':'13'})
        with patch.object(auditoria,'seleccionar_backend_seguridad',return_value=seleccion), \
             patch.object(auditoria,'auditoria_debian') as adquirir:
            d=auditoria.consultar('correlacion_seguridad')
        adquirir.assert_not_called()
        self.assertEqual(d['estado'],'no_implementado')


class Transporte(SinProcesos):
    def simular(self, stdout=b'', stderr=b'', codigo=0, limite=None, modo='apt-simular'):
        proceso = Mock()
        proceso.stdout.fileno.return_value = 10
        proceso.stderr.fileno.return_value = 11
        proceso.wait.return_value = codigo
        proceso.poll.return_value = None
        bloques = {10: [stdout,b''], 11:[stderr,b'']}
        class Selector:
            def __init__(self): self.claves={}
            def __enter__(self): return self
            def __exit__(self,*a): pass
            def register(self, archivo, eventos, data):
                self.claves[archivo.fileno()]=types.SimpleNamespace(fd=archivo.fileno(),data=data,fileobj=archivo)
            def unregister(self, archivo): del self.claves[archivo.fileno()]
            def get_map(self): return self.claves
            def select(self, espera): return [(v,1) for v in list(self.claves.values())]
        with patch.object(transporte.subprocess,'Popen',return_value=proceso) as lanzar, \
             patch.object(transporte.selectors,'DefaultSelector',Selector), \
             patch.object(transporte.os,'read',side_effect=lambda fd,n: bloques[fd].pop(0)), \
             patch.object(transporte.os,'geteuid',return_value=1000), \
             patch.object(transporte,'MAX_BYTES',limite or transporte.MAX_BYTES):
            r=transporte.ejecutar(modo,time.monotonic()+120)
        self.assertNotIn('shell',lanzar.call_args.kwargs)
        self.assertNotIn('APT_CONFIG',lanzar.call_args.kwargs['env'])
        self.assertNotIn('LD_PRELOAD',lanzar.call_args.kwargs['env'])
        return r

    def test_captura_acotada_y_stderr_no_verificado(self):
        self.assertEqual(self.simular(b'datos')['estado'],'completo')
        r=self.simular(b'datos',b'aviso privado')
        self.assertEqual(r['error'],'avisos_no_verificados')
        self.assertNotIn('privado',json.dumps(r))

    def test_limite_y_fallo_aislamiento(self):
        self.assertEqual(self.simular(b'12345',limite=4)['error'],'limite_salida')
        self.assertEqual(self.simular(codigo=78)['error'],'aislamiento_no_disponible')

    def test_dnf5_quiet_no_relaja_stderr(self):
        # Datos que se esperan tras suprimir DNF5 sus mensajes informativos.
        fila = b'uno\tx86_64\t0:2-1\n'
        self.assertEqual(self.simular(fila, modo='dnf5-consultar')['estado'],'completo')
        for mensaje in (b'Updating and loading repositories:\nRepositories loaded.\n',
                        b'Warning: unknown diagnostic\n'):
            with self.subTest(mensaje=mensaje):
                r = self.simular(fila,mensaje,modo='dnf5-consultar')
                self.assertEqual(r['error'],'avisos_no_verificados')

    def test_dnf5_codigos_no_cero_no_son_exito_repoquery(self):
        for codigo in (1, 100):
            for stderr in (b'', b'Error: repository unavailable\n'):
                with self.subTest(codigo=codigo,stderr=stderr):
                    r = self.simular(stderr=stderr,codigo=codigo,modo='dnf5-consultar')
                    self.assertEqual(r['estado'],'error')
                    self.assertEqual(r['codigo'],codigo)
                    self.assertEqual(r['error'],'error_gestor')


class Contratos(SinProcesos):
    def test_rechaza_inyecciones_y_versiones_de_contrato(self):
        for nombre in ('--assumeno','../../tmp/paquete','paquete;id','paquete\nFALSO'):
            with self.assertRaises(ValueError): paquete(nombre,'amd64','1','2')
        d=base('debian13','apt','plan')
        d['version']=2
        with self.assertRaises(ValueError): finalizar(d)

    def test_no_oculta_capacidades_fallidas(self):
        a=Mock(distribucion='debian13',gestor='apt')
        a.capacidades.side_effect=OSError()
        d=motor.consultar(adaptador=a)
        self.assertEqual(d['estado'],'no_disponible')
        self.assertEqual(d['candidatas']['errores'],['capacidades_no_verificadas'])
        a.consultar.assert_not_called()
