"""Adaptación de lecturas existentes. Sin imports conversacionales ni escalada."""
import copy
import json
import os
from pathlib import Path
import shutil
import sys
import time
from motor_auditoria import ejecutar_comando
from contratos_autonomia import OPERACIONES, ESTADOS, exigir


def consultar_disco(comando, deadline):
    """Lectura existente compartida; no conserva la salida libre de df."""
    fuente=comando(('df','-h'),deadline)
    montajes=[];vistos=set();fallo=False
    for ruta in ('/','/usr','/var','/tmp'):
        if time.monotonic()>=deadline:raise TimeoutError('plazo_agotado')
        try:
            st=os.stat(ruta);v=os.statvfs(ruta)
            if st.st_dev not in vistos:
                vistos.add(st.st_dev)
                montajes.append(dict(ruta=ruta,dispositivo=st.st_dev,
                    disponible_bytes=v.f_bavail*v.f_frsize,total_bytes=v.f_blocks*v.f_frsize))
        except OSError:fallo=True
    datos=dict(montajes=montajes,fuente=fuente['estado'],integridad='no_comprobada')
    estado='completo' if fuente['estado']=='correcta' and not fallo else 'parcial'
    return datos, estado


class HerramientasLocales:
    def __init__(self):
        if os.geteuid()==0:raise PermissionError('auditoria_root_rechazada')
        self.subconsultas = []

    def capacidad(self, operacion, distribucion):
        requisitos = {
            'sistema':('uname',), 'disco':('df',), 'memoria':(),
            'servicios_fallidos':('systemctl',), 'interfaces_red':('ip','nmcli'),
            'auditoria_seguridad':('dpkg-query',) if distribucion['id']=='debian' else ('rpm','dnf'),
            'plan_mantenimiento':('apt-get',) if distribucion['id']=='debian' else ('rpm','dnf'),
            'diagnostico_mantenimiento_apt':('dpkg',), 'correlacion_seguridad':('rpm','dnf5'),
        }
        exigir(operacion in OPERACIONES)
        if distribucion['estado']!='soportado':
            return 'no_disponible', [], 'distribucion_no_soportada'
        if operacion=='diagnostico_mantenimiento_apt' and distribucion['id']!='debian':
            return 'no_disponible', [], 'solo_debian13'
        if operacion=='correlacion_seguridad' and distribucion['id']!='fedora':
            return 'no_disponible', [], 'cve_debian_no_implementadas'
        disponibles=[n for n in requisitos[operacion] if shutil.which(n)]
        if operacion=='sistema':
            disponibles.extend(['python:'+sys.version.split()[0],'interprete:'+sys.executable,
                'entorno:flatpak' if os.environ.get('FLATPAK_ID') or Path('/.flatpak-info').exists() else 'entorno:sin_indicios_flatpak'])
        if operacion in ('interfaces_red','auditoria_seguridad','plan_mantenimiento'):
            apta=bool(disponibles)
        else:apta=all(shutil.which(n) for n in requisitos[operacion])
        return ('disponible' if apta else 'no_disponible'), disponibles, 'sondeo_informativo_no_garantiza_adquisicion'

    def comando(self, comando, deadline):
        inicio=time.monotonic()
        restante=deadline-inicio
        if restante<=0:raise TimeoutError('plazo_agotado')
        codigo,salida,error,truncado=ejecutar_comando(list(comando),min(15,restante))
        estado='truncada' if truncado else 'error_comando' if codigo else 'avisos_no_interpretados' if error else 'correcta'
        self.subconsultas.append(dict(operacion=comando[0],estado=estado,
                                     duracion_ms=max(0,int((time.monotonic()-inicio)*1000))))
        return dict(estado=estado,codigo=codigo,stdout=salida,stderr=error)

    def ejecutar(self, operacion, deadline, previos):
        exigir(operacion in OPERACIONES)
        self.subconsultas=[]
        if time.monotonic()>=deadline:raise TimeoutError('plazo_agotado')
        if operacion=='sistema':
            fuente=self.comando(('uname','-a'),deadline)
            datos=dict(kernel=fuente['stdout'].strip(),fuente={k:v for k,v in fuente.items() if k!='stdout'})
            estado='completo' if fuente['estado']=='correcta' else 'no_verificable'
        elif operacion=='disco':
            datos, estado = consultar_disco(self.comando, deadline)
        elif operacion=='memoria':
            from memoria import comando_meminfo,normalizar_memoria
            datos=normalizar_memoria(self.comando(comando_meminfo(sys.executable,65536),deadline))
            estado=datos['estado']
        elif operacion=='servicios_fallidos':
            from servicios import COMANDO,normalizar_servicios
            datos=normalizar_servicios(self.comando(COMANDO,deadline)).a_dict()
            estado=datos['estado_adquisicion']
        elif operacion=='interfaces_red':
            from interfaces_red import normalizar
            comandos={'ip':('ip','-j','-s','link','show'),
                      'nmcli':('nmcli','-t','--escape','yes','-f','DEVICE,TYPE,STATE,CONNECTION','device','status')}
            fuentes={}
            for nombre,cmd in comandos.items():
                try:fuentes[nombre]=self.comando(cmd,deadline)
                except OSError:fuentes[nombre]=dict(estado='ejecutable_ausente',codigo=None,stdout='',stderr='')
            datos=normalizar(fuentes);estado=datos['estado']
        elif operacion=='auditoria_seguridad':
            from motor_auditoria import consultar
            datos=consultar(operacion,deadline)
            estado=datos.get('estado_adquisicion','no_disponible')
        elif operacion=='plan_mantenimiento':
            from mantenimiento import consultar
            from contratos_mantenimiento import validar
            datos=consultar('plan',deadline=deadline,datos_previos=previos.get('auditoria_seguridad'),observador=self.subconsultas.append)
            validar(datos);estado=datos['estado']
        elif operacion=='diagnostico_mantenimiento_apt':
            from diagnostico_mantenimiento import diagnosticar
            def comprobar():
                # Nunca usar cliente administrativo (ni su espera ilimitada).
                helper=Path('/usr/local/lib/asistentelocal/ejecutor_apt.py')
                if not helper.exists():return dict(estado='cancelado',error='ejecutor_no_instalado')
                from cliente_ejecucion_apt import comprobar_proteccion
                if not comprobar_proteccion():return dict(estado='no_verificable')
                fuente=self.comando(('/usr/bin/python3','-I','-S','-B',str(helper),'comprobar'),deadline)
                if fuente['estado']!='correcta':return dict(estado='no_verificable')
                return json.loads(fuente['stdout'])
            def sondeo(modo, fin):
                from mantenimiento_transporte import ejecutar
                inicio=time.monotonic()
                r=ejecutar(modo,min(fin,deadline))
                self.subconsultas.append(dict(operacion=modo,estado=r['estado'],duracion_ms=max(0,int((time.monotonic()-inicio)*1000))))
                return r
            datos=diagnosticar(plan=previos['plan_mantenimiento'],deadline=deadline,
                               ejecutor=comprobar,sondeo=sondeo)
            estado='parcial' if datos['evaluacion']=='NO_VERIFICABLE' else 'completo'
        else:
            from correlacion_seguridad import consultar
            local=previos['auditoria_seguridad']
            def ejecutar(cmd,timeout):
                r=self.comando(cmd,min(deadline,time.monotonic()+timeout))
                return r['codigo'],r['stdout'],r['stderr'],r['estado']=='truncada'
            datos=consultar(lambda fin:copy.deepcopy(local),ejecutar,False,deadline)
            estado=datos.get('estado_adquisicion', 'parcial')
        # Los motores compuestos conservan las fuentes nativas con sus estados
        # y duraciones; la traza no los convierte en llamadas nuevas del modelo.
        if type(datos) is not dict:raise ValueError('resultado_no_estructurado')
        for nombre,fuente in datos.get('fuentes',{}).items():
            if type(fuente) is dict:
                self.subconsultas.append(dict(operacion=nombre,estado=str(fuente.get('estado','no_verificable')),
                    duracion_ms=max(0,int(fuente.get('duracion_s',0)*1000))))
        if estado not in ESTADOS:estado='no_verificable'
        return dict(estado=estado,resultado=datos,subconsultas=copy.deepcopy(self.subconsultas))
