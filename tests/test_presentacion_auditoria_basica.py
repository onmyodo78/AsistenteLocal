"""Presentación pura sobre trazas simuladas, sin adquisiciones del anfitrión."""
import unittest
from unittest.mock import patch

import auditoria_basica as a
from contratos_mantenimiento import serializar,finalizar,paquete
from contratos_autonomia import validar_traza
from test_auditoria_basica import Herramientas,Reloj,distro,resultado


class Presentacion(unittest.TestCase):
    def setUp(self):
        self.h=Herramientas()
        import subprocess
        barrera=patch.object(subprocess,'Popen',side_effect=AssertionError('Proceso real prohibido'))
        barrera.start();self.addCleanup(barrera.stop)
    def traza(self,nombre='debian',exclusiones=()):
        return a.auditar(herramientas=self.h,detectar=lambda:distro(nombre),
                         reloj=Reloj(),exclusiones=exclusiones)
    def test_resumen_resultados_y_agrupacion_sin_modificar_json(self):
        memoria=resultado('memoria');memoria['resultado'].update(ram=dict(total_bytes=8*1024**3,disponible_estimada_bytes=6*1024**3),swap=dict(total_bytes=2*1024**3,ocupada_bytes=0))
        servicios=resultado('servicios_fallidos');servicios['resultado']['datos'].update(total_unidades=1,unidades=[dict(nombre='ejemplo.service')])
        red=resultado('interfaces_red');red['resultado']['interfaces']=[dict(nombre='eth0',administrativo='UP',operativo='UP',networkmanager={'estado_observado':'connected'})]
        self.h.valores.update(memoria=memoria,servicios_fallidos=servicios,interfaces_red=red)
        traza=self.traza();antes=serializar(traza)
        texto=a.informe(traza)
        for esperado in ('Áreas comprobadas: 7/7','Hallazgos:','Pendientes:',
                         '8.0 GiB','6.0 GiB','Swap: 0 B','ejemplo.service',
                         'eth0: administrativo UP','100 B disponibles',
                         'Resolvedor: 1 actualizaciones','Preparación APT:',
                         'observaciones agrupadas','Referencias:'):
            self.assertIn(esperado,texto)
        self.assertEqual(antes,serializar(traza))
        self.assertEqual(validar_traza(traza),traza)
        self.assertEqual(texto.count('P3 |'),1)
    def test_actualizaciones_por_nombre_y_versiones_mixtas(self):
        valor=resultado('plan_mantenimiento');p=valor['resultado']
        p['simulacion']['actualizaciones']=[paquete('libreoffice-'+str(i),'amd64','1','2' if i%2 else '3') for i in range(35)]
        valor['resultado']=finalizar(p)
        self.h.valores['plan_mantenimiento']=valor
        traza=self.traza();antes=serializar(traza)
        texto=a.informe(traza)
        self.assertIn('libreoffice* (por nombre): 35 actualizaciones',texto)
        self.assertIn('versiones diversas',texto)
        self.assertNotIn('libreoffice-34:amd64',texto)
        self.assertEqual(len(next(r for r in traza if r['tipo']=='evidencia' and r['operacion_id']=='plan_mantenimiento')['datos']['resultado']['simulacion']['actualizaciones']),35)
        self.assertEqual(antes,serializar(traza))
    def test_parcial_con_datos_validos_no_inventa_intercambio_ni_retenciones(self):
        memoria=resultado('memoria');memoria['estado']='parcial'
        memoria['resultado']['ram']={'total_bytes':1024,'disponible_estimada_bytes':None}
        memoria['resultado']['swap']={}
        self.h.valores['memoria']=memoria
        valor=resultado('plan_mantenimiento');valor['estado']='parcial'
        valor['resultado']['estado']='parcial'
        valor['resultado']['simulacion'].update(estado='no_verificable',retenciones_estado='no_comprobada',errores=['formato_no_verificado'])
        self.h.valores['plan_mantenimiento']=valor
        texto=a.informe(self.traza())
        self.assertIn('disponibles (estimación)',texto)
        self.assertIn('Swap: desconocido ocupada de desconocido',texto)
        self.assertIn('Simulación no verificable',texto)
        self.assertIn('formato_no_verificado',texto)
        self.assertNotIn('Resolvedor:',texto)
        self.assertNotIn('Retenciones: 0',texto)
    def test_fallos_no_presentan_ceros_y_capacidades_ausentes(self):
        self.h.fallo.update(servicios_fallidos=OSError('error'),interfaces_red=OSError('error'))
        self.h.ausentes={'disco'}
        texto=a.informe(self.traza())
        self.assertIn('Auditoría básica autónoma: parcial',texto)
        self.assertIn('Sin resultados utilizables',texto)
        self.assertIn('Comprobación no realizada',texto)
        self.assertIn('Error: adquisicion_fallida',texto)
        self.assertNotIn('Servicios fallidos observados: 0',texto)
    def test_sin_comprobaciones_y_exclusiones(self):
        traza=self.traza(exclusiones=['identidad','disco','memoria','servicios','red','seguridad','mantenimiento'])
        texto=a.informe(traza)
        self.assertIn('Áreas comprobadas: 0/7; excluidas: 7',texto)
        self.assertIn('No se ejecutaron comprobaciones',texto)
        self.assertIn('Sin hallazgos registrados',texto)
        self.assertEqual(self.h.llamadas,[])
        for op in ('memoria','servicios_fallidos','interfaces_red'):
            valor=resultado(op);valor['resultado']={};self.h.valores[op]=valor
        texto=a.informe(self.traza())
        self.assertIn('RAM: desconocido',texto)
        self.assertIn('Número de servicios fallidos desconocido',texto)
        self.assertIn('No hay interfaces utilizables en el resultado',texto)
        self.assertNotIn('Servicios fallidos observados: 0',texto)
    def test_fedora_retenciones_desconocidas_y_avisos_no_vulnerabilidad(self):
        valor=resultado('plan_mantenimiento')
        valor['resultado'].update(distribucion='fedora',gestor='dnf')
        valor['resultado']['simulacion']['retenciones_estado']='no_comprobada'
        valor['resultado']=finalizar(valor['resultado'])
        self.h.valores['plan_mantenimiento']=valor
        audit=resultado('auditoria_seguridad');audit['resultado'].pop('inventario_dpkg')
        audit['resultado'].update(inventario_rpm=[],recuentos={'avisos_pendientes':None})
        self.h.valores['auditoria_seguridad']=audit
        texto=a.informe(self.traza('fedora'))
        self.assertIn('Retenciones: no comprobadas',texto)
        self.assertIn('Avisos Fedora pendientes: desconocidos',texto)
        self.assertIn('Un aviso no demuestra vulnerabilidad',texto)
    def test_no_muestra_resultados_de_evidencia_fallida_y_limita_texto(self):
        valor=resultado('memoria');valor['estado']='error'
        self.h.valores['memoria']=valor
        traza=self.traza();texto=a.informe(traza)
        self.assertNotIn('RAM:',texto)
        # El contrato permite conclusiones extensas: la presentación debe mantener
        # el límite de salida sin alterar las evidencias ni el JSON original.
        for r in traza:
            if r['tipo']=='hallazgo':r['conclusion_python']='Observación '+r['id']+'x'*10000
        antes=serializar(traza)
        texto=a.informe(traza)
        self.assertLessEqual(len(texto),18000)
        self.assertIn('Informe abreviado',texto)
        self.assertEqual(antes,serializar(traza))


if __name__=='__main__':unittest.main()
