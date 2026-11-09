"""Contrato de ejecución separado del plan de solo lectura; sin autoridad implícita."""
from contextlib import contextmanager, ExitStack
import io
import os
import hashlib
import json
import re
import secrets
import time
from contratos_mantenimiento import validar, serializar

OPERACION = 'apt_actualizar_cacheados_v1'
OPERACION_DESCARGA='apt_descargar_plan_v1'
POLITICA_DESCARGA={'solo_descarga':True,'sin_instalacion':True,'sin_refresco_indices':True,'repositorios_configurados':True}
VIGENCIA = 300
MAX_PETICION = 4 * 1024 * 1024
POLITICA = {'solo_actualizaciones': True, 'solo_cache': True, 'sin_reparaciones': True,
            'conffiles': 'confdef_confold', 'reinicio_automatico': False}


def comprobar_plan(plan):
    validar(plan)
    if (plan['distribucion'] != 'debian13' or plan['gestor'] != 'apt'
            or plan['operacion'] != 'plan' or plan['estado'] != 'completo'
            or plan['simulacion']['estado'] != 'completo' or plan['huella'] is None):
        raise ValueError('plan_no_ejecutable')
    s = plan['simulacion']
    if s['instalaciones'] or s['eliminaciones'] or not s['actualizaciones']:
        raise ValueError('alcance_no_admitido')
    retenidos = {(r['nombre'],r['arquitectura']) for r in s['retenciones']}
    for r in s['actualizaciones']:
        if not re.fullmatch(r'[a-z0-9][a-z0-9+.-]*',r['nombre']) or not re.fullmatch(r'[a-z0-9][a-z0-9-]*',r['arquitectura']):
            raise ValueError('identidad_debian_invalida')
        if (r['nombre'],r['arquitectura']) in retenidos:
            raise ValueError('paquete_retenido')
    return plan


def crear_peticion(plan, uid, *, operacion=OPERACION, archivos=None):
    comprobar_plan(plan)
    if operacion not in (OPERACION,OPERACION_DESCARGA):raise ValueError('operacion_no_autorizada')
    politica=POLITICA if operacion==OPERACION else POLITICA_DESCARGA
    p = dict(version=1, operacion=operacion, id=secrets.token_hex(16), uid=uid,
             creado=int(time.time()), politica=dict(politica), plan=plan, digest=None)
    if operacion==OPERACION_DESCARGA:
        from archivos_apt import validar_manifiesto
        p['archivos']=validar_manifiesto(archivos,plan)
    p['digest'] = digest(p)
    return p


def digest(p):
    return hashlib.sha256(serializar(dict(p,digest=None)).encode()).hexdigest()


def crear_sobre(plan,uid,operacion,politica):
    """Identidad de una solicitud; no concede permisos ni valida su política."""
    p=dict(version=1,operacion=operacion,id=secrets.token_hex(16),uid=uid,
           creado=int(time.time()),politica=dict(politica),plan=plan,digest=None)
    p['digest']=digest(p)
    return p


def validar_sobre(p,uid,operacion,politica,ahora=None,*,campos=None):
    campos={'version','operacion','id','uid','creado','politica','plan','digest'} if campos is None else campos
    if type(p) is not dict or set(p)!=campos:raise ValueError('peticion_invalida')
    if type(p['version']) is not int or p['version']!=1 or p['operacion']!=operacion:
        raise ValueError('operacion_no_autorizada')
    if type(p['uid']) is not int or p['uid']!=uid or uid<=0:raise ValueError('identidad_no_coincidente')
    if type(p['creado']) is not int or not 0<=(time.time() if ahora is None else ahora)-p['creado']<=VIGENCIA:
        raise ValueError('autorizacion_caducada')
    if type(p['id']) is not str or not re.fullmatch(r'[0-9a-f]{32}',p['id']):raise ValueError('identificador_invalido')
    if serializar(p['politica'])!=serializar(politica) or p['digest']!=digest(p):raise ValueError('autorizacion_alterada')
    if len(serializar(p).encode())>MAX_PETICION:raise ValueError('peticion_demasiado_grande')
    return p


def validar_peticion(p, uid, ahora=None, *, operacion=OPERACION):
    campos={'version','operacion','id','uid','creado','politica','plan','digest'}
    if operacion==OPERACION_DESCARGA:campos.add('archivos')
    if operacion not in (OPERACION,OPERACION_DESCARGA):raise ValueError('operacion_no_autorizada')
    politica=POLITICA if operacion==OPERACION else POLITICA_DESCARGA
    validar_sobre(p,uid,operacion,politica,ahora,campos=campos)
    comprobar_plan(p['plan'])
    if operacion==OPERACION_DESCARGA:
        from archivos_apt import validar_manifiesto
        validar_manifiesto(p['archivos'],p['plan'])
    if len(serializar(p).encode()) > MAX_PETICION:
        raise ValueError('peticion_demasiado_grande')
    return p


def frase(p):
    return ('AUTORIZAR DESCARGA APT ' if p['operacion']==OPERACION_DESCARGA else 'AUTORIZAR APT ') + p['digest']


def leer_json(texto):
    def unico(pares):
        d={}
        for k,v in pares:
            if k in d: raise ValueError('clave_duplicada')
            d[k]=v
        return d
    return json.loads(texto, object_pairs_hook=unico,
                      parse_constant=lambda x: (_ for _ in ()).throw(ValueError('json_invalido')))


@contextmanager
def abrir_tty_confirmacion():
    """Canales separados: una TTY no admite el seek del modo textual r+."""
    with ExitStack() as recursos:
        try:
            lectura = recursos.enter_context(open('/dev/tty', 'rb', buffering=0))
            escritura = recursos.enter_context(open('/dev/tty', 'wb', buffering=0))
        except OSError:
            raise ValueError('terminal_requerida') from None
        if not (os.isatty(lectura.fileno()) and os.isatty(escritura.fileno())):
            raise ValueError('terminal_requerida')
        try:
            with io.TextIOWrapper(io.BufferedRWPair(lectura, escritura),
                                  encoding='utf-8', errors='strict') as tty:
                yield tty
        except (OSError, UnicodeError):
            raise ValueError('terminal_io_error') from None
