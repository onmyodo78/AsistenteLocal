"""Cliente sin privilegios. Catálogo fijo, sin contraseñas ni confirmaciones automáticas."""
import json
import os
from pathlib import Path
import subprocess
import stat
import sys
import time
from autorizacion_apt import crear_peticion,comprobar_plan
from contratos_mantenimiento import serializar

HELPER=Path('/usr/local/lib/asistentelocal/ejecutor_apt.py')
HELPER_DNF5=Path('/usr/local/lib/asistentelocal-dnf5/ejecutor_apt.py')


def comprobar_proteccion(helper=None):
    helper=HELPER if helper is None else helper
    for p in (helper.parent,*helper.parent.parents):
        st=p.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022:
            return False
    st=helper.lstat()
    return stat.S_ISREG(st.st_mode) and st.st_uid==0 and not st.st_mode&0o022 and st.st_nlink==1


def invocar(operacion,peticion=None,*,backend='apt'):
    if backend not in ('apt','dnf5'):raise ValueError('operacion_no_autorizada')
    if operacion not in ('comprobar','ejecutar','historial','descargar'):raise ValueError('operacion_no_autorizada')
    if backend=='dnf5' and operacion=='descargar':raise ValueError('operacion_no_autorizada')
    helper=HELPER if backend=='apt' else HELPER_DNF5
    if not helper.is_file():
        return dict(version=1,estado='cancelado',error='ejecutor_no_instalado')
    if not (comprobar_proteccion() if backend=='apt' else comprobar_proteccion(helper)):
        return dict(version=1,estado='cancelado',error='instalacion_no_protegida')
    comando=['/usr/bin/python3','-I','-S','-B',str(helper),operacion]
    if operacion!='comprobar':comando=['/usr/bin/sudo','-k','--']+comando
    # sudo pide la contraseña al terminal del usuario, nunca mediante -S.
    inicio=time.monotonic()
    proceso=subprocess.Popen(comando,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
        stderr=None,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','LANG':'C',
                         'HOME':os.path.expanduser('~')})
    entrada=serializar(peticion).encode() if peticion is not None else b''
    while True:
        try:
            salida,_=proceso.communicate(input=entrada)
            break
        except KeyboardInterrupt:
            # No usar subprocess.run/context manager: matarían al hijo ante un
            # error. Una transacción empezada debe finalizar/reconciliarse.
            entrada=None
            print('No se mata el ejecutor '+backend+'; esperando su resultado. Consulte historial-'+backend+' ante una desconexión.',file=sys.stderr)
    duracion=round(max(0.0,time.monotonic()-inicio),6)
    # Solo metadatos: nunca persistir respuesta cruda, stderr o texto de sudo.
    def rechazar(motivo):
        return dict(version=1,estado='resultado_desconocido',
            error='respuesta_ejecutor_no_confirmada',diagnostico_transporte=dict(
                motivo=motivo,codigo_salida=proceso.returncode,
                duracion_s=duracion,bytes_recibidos=len(salida)))
    if len(salida)>1024*1024:return rechazar('tamano_excesivo')
    try:
        r=json.loads(salida)
    except (ValueError,UnicodeError):
        return rechazar('json_invalido')
    if type(r) is not dict:return rechazar('estructura_incorrecta')
    if type(r.get('version')) is not int or r.get('version')!=1:
        return rechazar('version_invalida')
    estados=('preparado','completo','cancelado','fallido','incompleto','resultado_desconocido')
    if type(r.get('estado')) is not str or r['estado'] not in estados:
        return rechazar('estado_invalido')
    # Conservar las condiciones administrativas previas para respuestas completas.
    if r['estado']=='completo':
        if proceso.returncode!=0:return rechazar('codigo_salida_incompatible')
        if peticion and r.get('id')!=peticion['id']:return rechazar('identificador_discordante')
    return r



def actualizar(plan):
    comprobar_plan(plan)
    return invocar('ejecutar',crear_peticion(plan,os.getuid()))


def descargar(plan,archivos):
    from autorizacion_apt import OPERACION_DESCARGA
    return invocar('descargar',crear_peticion(plan,os.getuid(),operacion=OPERACION_DESCARGA,archivos=archivos))
