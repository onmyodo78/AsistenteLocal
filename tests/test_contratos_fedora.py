"""Regresiones Fedora con datos sintéticos, sin ejecutables del anfitrión."""
import copy
import json
from pathlib import Path
import sys
import time
import types
import unittest
from unittest.mock import Mock, patch

import AsistenteLocal as app
import auditoria_seguridad as audit
import correlacion_seguridad as corr

FORMATO = '%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n'
DNF = ('dnf', '-q', '--cacheonly', '--no-plugins', '--setopt=logdir=/proc/self/fd',
       'updateinfo', 'list', '--security', '--json')
NEVRA = 'ejemplo-1:2.0-1.fc44.x86_64'
RPM = 'kernel-core\t0\t6.18.2\t100.fc44\tx86_64\nejemplo\t1\t1.0\t1.fc44\tx86_64\n'
AVISO = 'FEDORA-2026-sintetico'


def local():
    salidas = dict(uname='6.18.2-100.fc44.x86_64', rpm=RPM,
        kernels=RPM.splitlines()[0]+'\n', instalados='[]',
        pendientes=json.dumps([dict(type='security', name=AVISO, nevra=NEVRA)]))
    return audit.normalizar({n: dict(estado='correcta', codigo=0, stdout=s)
                             for n,s in salidas.items()})


def detalles():
    return json.dumps([dict(Type='security', Name=AVISO,
        references=[dict(Type='cve', Id='CVE-2026-1234')], collections={'packages': [NEVRA]})])


class ContratosFedora(unittest.TestCase):
    def setUp(self):
        for objeto, nombre in ((audit.subprocess, 'Popen'), (corr.urllib.request, 'urlopen'),
                               (corr.urllib.request, 'build_opener')):
            parche = patch.object(objeto, nombre, side_effect=AssertionError('Operación real prohibida'))
            parche.start()
            self.addCleanup(parche.stop)

    def test_comandos_y_argumentos(self):
        consultas = (('uname', ('uname','-r')), ('rpm', ('rpm','-qa','--qf',FORMATO)),
            ('kernels', ('rpm','-q','kernel-core','--qf',FORMATO)),
            ('pendientes',DNF+('--available',)), ('instalados',DNF+('--installed',)))
        self.assertEqual(audit.FORMATO_RPM, FORMATO)
        self.assertEqual(audit.CONSULTAS, consultas)
        self.assertEqual(corr.COMANDO, ('dnf5','-q','--cacheonly','--no-plugins',
            '--setopt=logdir=/proc/self/fd','advisory','info','--security','--available','--json'))
        self.assertEqual(app.TOOLS['auditoria_seguridad']['commands'], [list(c) for _,c in consultas])
        self.assertEqual(app.TOOLS['correlacion_seguridad']['commands'],
                         [list(c) for _,c in consultas]+[list(corr.COMANDO)])
        for modo in ('rpm','pendientes','instalados'):
            self.assertEqual(audit.comando_aislado(modo), [sys.executable,'-B',
                str(Path(audit.__file__).with_name('auditoria_aislamiento.py').resolve()),modo])
        with self.assertRaises(ValueError):
            audit.comando_aislado('dpkg')

    def test_estructura_local(self):
        datos = local()
        self.assertEqual(set(datos), {'version','herramienta','estado_adquisicion','fuentes',
            'kernel_activo','kernels_instalados','kernels_mas_recientes_no_activos',
            'reinicio_pendiente_kernel','inventario_rpm','inventario_completo',
            'avisos_pendientes','avisos_instalados','recuentos','limitaciones'})
        self.assertEqual(datos['version'],1)
        self.assertEqual(datos['estado_adquisicion'],'completo')
        self.assertEqual([p['nombre'] for p in datos['inventario_rpm']], ['ejemplo', 'kernel-core'])
        self.assertEqual(datos['inventario_rpm'][0],dict(nombre='ejemplo',epoch=1,
            version='1.0',release='1.fc44',arquitectura='x86_64'))
        self.assertEqual(datos['avisos_pendientes'],[{'id':AVISO,'paquetes':[NEVRA]}])
        self.assertEqual(datos['recuentos'],dict(paquetes_rpm=2,avisos_pendientes=1,
            avisos_instalados=0,paquetes_rpm_recogidos=2))
        self.assertFalse(datos['reinicio_pendiente_kernel'])

    def test_limites_y_privacidad(self):
        self.assertEqual((audit.MAX_INVENTARIO_BYTES,audit.MAX_PAQUETES,audit.MAX_LINEA,
            audit.MAX_STDERR,audit.MAX_RESUMEN),(4194304,25000,1024,8192,5000))
        self.assertEqual((app.MAX_SECONDS,app.MAX_MODEL_SECONDS,app.MAX_OUTPUT,
            app.MAX_TOTAL_OUTPUT,app.MAX_COMMAND_BYTES),(120,45,18000,60000,65536))
        datos = local()
        resultado = audit.ResultadoAuditoria(datos,18000)
        vista = json.loads(resultado)
        self.assertEqual(vista['version'],2)
        self.assertNotIn('inventario_rpm',vista)
        self.assertNotIn('ejemplo',str(resultado))
        self.assertEqual(vista['avisos_pendientes'],[{'id':AVISO,'paquetes':1}])
        self.assertLessEqual(len(resultado),5000)
        copia = resultado.datos
        copia['inventario_rpm'].clear()
        self.assertEqual(resultado.datos,datos)
        datos['avisos_pendientes'] *= 11
        datos['avisos_instalados'] = datos['avisos_pendientes']
        vista = json.loads(audit.ResultadoAuditoria(datos,5000))
        self.assertEqual((len(vista['avisos_pendientes']),len(vista['avisos_instalados'])),(10,5))
        self.assertEqual(vista['estado_presentacion'],'parcial')
        for limite in (100,1000):
            self.assertLessEqual(len(resultado.ajustar(limite)),limite)
            json.loads(resultado.ajustar(limite))

    def test_versiones_y_cve(self):
        for orden,estado in [(-1,'correccion_pendiente_confirmada'),
            (0,'version_correctiva_alcanzada'),(1,'version_correctiva_alcanzada')]:
            comparar = Mock(return_value=orden)
            filas = corr.correlacionar(local(),detalles(),None,comparar=comparar)
            comparar.assert_called_once_with(('1','1.0','1.fc44'),('1','2.0','1.fc44'))
            self.assertEqual(filas,[dict(aviso=AVISO,paquete='ejemplo',arquitectura='x86_64',
                instalada_evr='1:1.0-1.fc44',correctiva_nevra=NEVRA,estado_local=estado,
                cves=[dict(id='CVE-2026-1234',en_kev=None)])])
        datos = local()
        datos['avisos_pendientes'] = []
        fila = corr.correlacionar(datos,detalles(),{'CVE-2026-1234'},comparar=lambda a,b:-1)[0]
        self.assertEqual(fila['estado_local'],'no_determinado')
        self.assertTrue(fila['cves'][0]['en_kev'])
        with patch.dict(sys.modules,{'rpm':None}):
            self.assertEqual(corr.correlacionar(local(),detalles(),None)[0]['estado_local'],'no_determinado')

    def test_adquisicion_sin_externas(self):
        ejecutar = Mock(return_value=(0,detalles(),'',False))
        with patch.dict(sys.modules,{'rpm':None}):
            datos = corr.consultar(lambda plazo:local(),ejecutar,False,time.monotonic()+120)
        comando,timeout = ejecutar.call_args.args
        self.assertEqual(comando,[sys.executable,'-B',str(Path(corr.__file__).resolve()),'--detalle-local'])
        self.assertTrue(0 < timeout <= 15)
        self.assertEqual(set(datos),{'herramienta','fuentes_locales','inventario_completo',
            'resultados','referencias','alcance','limitaciones','detalle_dnf5','cisa_kev','total_resultados',
            'diagnostico_detalle','estado_adquisicion'})
        self.assertEqual(datos['cisa_kev'],{'estado':'no_autorizada'})
        self.assertEqual(datos['detalle_dnf5'],'correcto')
        self.assertEqual(datos['total_resultados'],1)
        self.assertEqual(datos['estado_adquisicion'],'parcial')  # sin binding RPM
        self.assertNotIn('inventario_rpm',datos)

    def test_diagnostico_detalle_sin_exponer_salidas(self):
        for retorno, motivo in [
            ((78,'','',False),'aislamiento_no_disponible'),
            ((69,'','',False),'dependencia_ausente'),
            ((1,'','',False),'error_comando'),
            ((1,'','Error: repository unavailable',False),'error_comando'),
            ((100,'[]','',False),'error_comando'),
            ((0,'[]','aviso privado',False),'avisos_no_interpretados'),
            ((0,'[]','Updating and loading repositories:\nRepositories loaded.\n',False),
             'avisos_no_interpretados'),
            ((0,'[','',True),'salida_truncada'),
            ((0,'{}','',False),'formato_invalido')]:
            with self.subTest(motivo=motivo):
                datos = corr.consultar(lambda fin:local(),Mock(return_value=retorno),False,time.monotonic()+30)
                self.assertEqual(datos['diagnostico_detalle']['motivo'],motivo)
                self.assertEqual(datos['estado_adquisicion'],'parcial')
                self.assertIsNone(datos['total_resultados'])
                self.assertNotIn('privado',json.dumps(datos))

    def test_vacio_valido_no_equivale_a_fuente_ausente(self):
        for completo in (True, False):
            datos_local = local()
            datos_local['inventario_completo'] = completo
            if not completo:
                datos_local['inventario_rpm'] = None
            datos = corr.consultar(lambda fin:datos_local,
                Mock(return_value=(0,'[]',audit.AVISO_LOG_DNF,False)),False,time.monotonic()+30)
            self.assertEqual(datos['detalle_dnf5'],'correcto')
            self.assertEqual(datos['estado_adquisicion'],'completo' if completo else 'parcial')
            self.assertEqual(datos['total_resultados'],0 if completo else None)

    def test_cierre_completo_con_comparacion_rpm_y_fuentes_completas(self):
        with patch.dict(sys.modules,{'rpm':types.SimpleNamespace(labelCompare=lambda a,b:-1)}):
            datos = corr.consultar(lambda fin:local(),
                Mock(return_value=(0,detalles(),'',False)),False,time.monotonic()+30)
        self.assertEqual(datos['estado_adquisicion'],'completo')
        self.assertEqual(datos['resultados'][0]['estado_local'],'correccion_pendiente_confirmada')

    def test_diagnostico_excepciones(self):
        for error, motivo in ((TimeoutError(),'tiempo_agotado'),(OSError(),'error_sistema')):
            datos = corr.consultar(lambda fin:local(),Mock(side_effect=error),False,time.monotonic()+30)
            self.assertEqual(datos['diagnostico_detalle']['motivo'],motivo)
            self.assertIsNone(datos['total_resultados'])

    def test_relacion_por_nombre_arquitectura_y_aviso_pendiente(self):
        datos_local = local()
        datos_local['inventario_rpm'][0]['arquitectura'] = 'aarch64'
        self.assertEqual(corr.correlacionar(datos_local,detalles(),None,lambda a,b:-1),[])
        datos_local = local()
        datos_local['avisos_pendientes'] = None
        self.assertEqual(corr.correlacionar(datos_local,detalles(),None,lambda a,b:-1)[0]
                         ['estado_local'],'no_determinado')

    def test_colecciones_invalidas_no_se_aceptan_como_vacias(self):
        for coleccion in ([], None, {'packages':{}}, {'packages':'texto'}):
            filas = json.loads(detalles())
            filas[0]['collections'] = coleccion
            with self.subTest(coleccion=coleccion), self.assertRaises(ValueError):
                corr.correlacionar(local(),json.dumps(filas),None,lambda a,b:-1)

    def test_detalle_invalido_y_presentacion(self):
        for retorno in ((1,detalles(),'',False),(0,detalles(),'aviso',False),
                        (0,detalles(),'',True),(0,'{}','',False)):
            datos = corr.consultar(lambda plazo:local(),Mock(return_value=retorno),False,time.monotonic()+120)
            self.assertEqual(datos['detalle_dnf5'],'no_disponible_o_formato_invalido')
        datos['resultados'] = [{'dato':'x'*500} for _ in range(30)]
        datos['total_resultados'] = 30
        antes = copy.deepcopy(datos)
        texto = corr.presentar(datos,2500)
        vista = json.loads(texto)
        self.assertLessEqual(len(texto),2500)
        self.assertGreater(vista['resultados_omitidos'],0)
        self.assertEqual(len(vista['resultados'])+vista['resultados_omitidos'],30)
        self.assertEqual(datos,antes)
        self.assertLessEqual(len(corr.presentar(datos,20)),20)
