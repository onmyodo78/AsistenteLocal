"""Diagnóstico factual APT v1. Una recomendación nunca autoriza una operación."""
import json
import os
from pathlib import Path
import time
import sqlite3
from autorizacion_apt import comprobar_plan
from archivos_apt import validar_manifiesto
from contratos_mantenimiento import serializar
from mantenimiento import consultar
from mantenimiento_transporte import ejecutar

ESTADOS=('APTO_PARA_PREPARAR','PENDIENTE_DE_DESCARGA','APTO_PARA_EJECUCION_CONTROLADA','BLOQUEADO','NO_VERIFICABLE')
LIMITACIONES=[
    'Observación sin bloqueos exclusivos: el estado puede cambiar después del diagnóstico.',
    'Ausencia de locks/procesos observados no garantiza exclusión; el helper debe adquirir los bloqueos nativos.',
    'Confiable según APT local no acredita firmas, vigencia Release ni frescura revalidadas en esta consulta.',
    'APT puede considerar confiables repositorios con trusted=yes: este diagnóstico no acredita validación criptográfica nueva.',
    'mtime indica antigüedad local, no publicación ni sincronización completa de índices.',
    'El umbral de espacio es conservador; scripts, hooks, snapshots y otros procesos pueden requerir más.',
    'La instalación exige nueva autorización, simulación bajo bloqueos y comprobación de archivos.',
]


def observar_concurrencia():
    """Solo /proc y stat: no crear ni tomar locks para una observación."""
    rutas=('/var/lib/dpkg/lock-frontend','/var/lib/dpkg/lock','/var/lib/apt/lists/lock','/var/cache/apt/archives/lock')
    try:
        identidades={}
        for ruta in rutas:
            try:s=os.stat(ruta)
            except FileNotFoundError:continue
            identidades[(os.major(s.st_dev),os.minor(s.st_dev),s.st_ino)]=ruta
        locks=[]
        with open('/proc/locks',encoding='ascii') as f:
            for linea in f:
                campos=linea.split()
                if '->' in campos:campos.remove('->')
                if len(campos)<6:continue
                partes=campos[5].split(':')
                if len(partes)!=3:continue
                clave=(int(partes[0],16),int(partes[1],16),int(partes[2]))
                if clave in identidades:locks.append(dict(archivo=identidades[clave],pid=int(campos[4])))
        procesos=[]
        for p in Path('/proc').iterdir():
            if not p.name.isdecimal():continue
            try:nombre=(p/'comm').read_text().strip()
            except FileNotFoundError:continue
            if nombre in ('apt','apt-get','dpkg','unattended-upgr','packagekitd'):
                procesos.append(dict(pid=int(p.name),nombre=nombre))
        return dict(estado='observado',locks=locks,procesos=procesos,garantia=False)
    except (OSError,ValueError):return dict(estado='no_verificable',locks=[],procesos=[],garantia=False)


def observar_diario():
    # No escalar privilegios para leer el diario. EACCES nunca equivale a vacío.
    from registro_mantenimiento import historial
    try:
        operaciones=historial()
        # historial limita a 20: no permite garantizar ausencia de pendientes antiguos.
        if operaciones:return dict(estado='no_verificable',motivo='revision_privilegiada_del_diario_necesaria')
        return dict(estado='sin_operaciones_observadas')
    except (OSError,ValueError,sqlite3.Error):return dict(estado='no_verificable',motivo='diario_no_accesible')


def observar_ejecutor():
    from cliente_ejecucion_apt import invocar
    try:return invocar('comprobar')  # Nunca sudo: el sondeo existente no lo requiere.
    except (OSError,ValueError):return dict(estado='no_verificable',error='ejecutor_no_comprobado')


def espacio(archivos):
    faltantes=sum(r['bytes'] for r in archivos if r['comprobacion']['estado']!='verificado')
    umbral=faltantes+sum(r['bytes_instalados'] for r in archivos)+256*1024*1024
    montajes=[]
    for ruta in ('/','/usr','/var/lib/dpkg','/var/cache/apt/archives','/tmp'):
        try:
            s=os.statvfs(ruta)
            montajes.append(dict(ruta=ruta,disponible_bytes=s.f_bavail*s.f_frsize,umbral_bytes=umbral))
        except OSError:return dict(estado='no_verificable',montajes=montajes,descarga_bytes=faltantes)
    return dict(estado='suficiente' if all(m['disponible_bytes']>=umbral for m in montajes) else 'insuficiente',
                montajes=montajes,descarga_bytes=faltantes,criterio='umbral_conservador_no_garantia')


def evaluar(d):
    h=d['hechos'];bloqueos=[];no_verificados=[]
    if h['plan']['estado']!='completo':no_verificados.append('plan_no_verificable')
    if h['dpkg']['estado']=='incidencias':bloqueos.append('dpkg_con_incidencias')
    elif h['dpkg']['estado']!='limpio':no_verificados.append('dpkg_no_verificado')
    if h['nativo']['estado']=='diferente':bloqueos.append('plan_nativo_diferente')
    elif h['nativo']['estado']!='coincidente':no_verificados.append('metadatos_o_resolvedor_no_verificados')
    if h['espacio']['estado']=='insuficiente':bloqueos.append('espacio_insuficiente')
    elif h['espacio']['estado']!='suficiente':no_verificados.append('espacio_no_verificado')
    c=h['concurrencia']
    if c['locks'] or c['procesos']:bloqueos.append('actividad_apt_observada')
    if c['estado']!='observado':no_verificados.append('concurrencia_no_observable')
    archivos=h['nativo'].get('archivos',[])
    malos=[r for r in archivos if r['comprobacion']['estado'] not in ('ausente','verificado')]
    if malos:bloqueos.append('archivos_no_verificados')
    faltan=sum(r['comprobacion']['estado']=='ausente' for r in archivos)
    d['impedimentos']=bloqueos;d['no_comprobado']=no_verificados
    if bloqueos:estado='BLOQUEADO';paso='Resolver administrativamente las incidencias y repetir el diagnóstico.'
    elif no_verificados:estado='NO_VERIFICABLE';paso='Completar las comprobaciones que fallaron; no descargar ni instalar.'
    elif faltan:estado='PENDIENTE_DE_DESCARGA';paso='Revisar plan-descarga-apt; autorizar descargar-apt únicamente si se aprueban versiones y orígenes.'
    elif h['ejecutor'].get('estado')!='preparado':
        estado='APTO_PARA_PREPARAR';paso='Validar e instalar administrativamente el helper protegido en una VM; repetir el diagnóstico.'
    elif h['nativo'].get('entorno_ejecucion')!='protegido':
        estado='NO_VERIFICABLE';d['no_comprobado'].append('entorno_privilegiado_no_verificado');paso='Revisar custodia de directorios y archivos de bloqueo antes de ejecutar.'
    elif h['diario']['estado']!='sin_operaciones_observadas':
        estado='NO_VERIFICABLE';d['no_comprobado'].append('diario_no_verificado');paso='Revisar el diario administrativo; no inferir ausencia de operaciones pendientes.'
    else:estado='APTO_PARA_EJECUCION_CONTROLADA';paso='Revisar actualizar-apt en una VM; exige autorización nueva y revalidación bajo bloqueos.'
    d['pendiente_ejecucion']=[nombre for nombre,verificado in (('entorno_privilegiado',h['nativo'].get('entorno_ejecucion')=='protegido'),('ejecutor_protegido',h['ejecutor'].get('estado')=='preparado'),('diario_administrativo',h['diario']['estado']=='sin_operaciones_observadas')) if not verificado]
    d['evaluacion']=estado;d['recomendacion']=paso
    d['preparacion_permitida']=not bloqueos and not no_verificados
    return d


def diagnosticar(*,plan=None,sondeo=ejecutar,ejecutor=observar_ejecutor,concurrencia=observar_concurrencia,diario=observar_diario,medir=espacio,deadline=None):
    p=consultar('plan', **({'deadline':deadline} if deadline is not None else {})) if plan is None else plan
    d=dict(version=1,tipo='diagnostico_mantenimiento_apt',evaluacion='NO_VERIFICABLE',autorizacion=False,
           hechos={},riesgos=['Scripts y hooks de paquetes pueden modificar el sistema y reiniciar servicios.'],
           limitaciones=list(LIMITACIONES),impedimentos=[],no_comprobado=[],recomendacion='')
    try:comprobar_plan(p)
    except (ValueError,KeyError,TypeError):
        d.update(hechos={'plan':p},no_comprobado=['plan_incompleto_o_fuera_del_alcance_debian13'],preparacion_permitida=False,
                 recomendacion='Obtener un plan Debian 13 completo de actualizaciones sin instalaciones ni eliminaciones.')
        # Un plan válido sin cambios no es un plan de instalación autorizado.
        # Precisar el motivo sin debilitar comprobar_plan ni habilitar descargas.
        from contratos_mantenimiento import validar
        try:
            validar(p)
            s=p['simulacion']
            vacio=(p['distribucion']=='debian13' and p['gestor']=='apt'
                   and p['operacion']=='plan' and p['estado']=='completo'
                   and p['candidatas']['estado']=='completo' and not p['candidatas']['paquetes']
                   and s['estado']=='completo' and s['retenciones_estado']=='completo'
                   and s['no_actualizados_total']==0
                   and not any(s[k] for k in ('actualizaciones','instalaciones','eliminaciones','retenciones','errores')))
            if vacio:
                d.update(no_comprobado=['sin_operacion_de_actualizacion_que_validar'],
                         recomendacion='El plan local no prevé cambios ni candidatas pendientes. No hay una operación APT que preparar; dpkg, espacio y demás precondiciones no se han comprobado en esta ruta.')
        except (ValueError,KeyError,TypeError):
            pass
        return d
    fin=min(deadline,time.monotonic()+90) if deadline is not None else time.monotonic()+90
    if fin <= time.monotonic():raise TimeoutError("plazo_agotado")
    dpkg=sondeo('apt-dpkg-audit',fin)
    h=dict(plan=p,dpkg=dict(estado=('limpio' if not dpkg['stdout'].strip() else 'incidencias') if dpkg['estado']=='completo' else 'no_verificable'),
           nativo=dict(estado='no_verificable',archivos=[],error='sondeo_nativo_no_completado'),espacio=dict(estado='no_verificable'),
           ejecutor=ejecutor(),concurrencia=concurrencia(),diario=diario())
    h['dpkg'].update(salida=dpkg['stdout'][:8192],salida_truncada=len(dpkg['stdout'])>8192,error=dpkg.get('error'))
    d['hechos']=h
    if time.monotonic()>=fin:raise TimeoutError('plazo_agotado')
    resultado=sondeo('apt-diagnostico',fin)
    h['nativo']['error']=resultado.get('error') or 'protocolo_nativo_no_validado'
    if resultado['estado']=='completo':
        try:
            n=json.loads(resultado['stdout'])
            if type(n['version']) is not int or n['version']!=1:raise ValueError()
            filas=[{k:v for k,v in r.items() if k!='comprobacion'} for r in n['archivos']]
            validar_manifiesto(filas,p)
            for r in n['archivos']:
                if r['comprobacion']['estado'] not in ('ausente','verificado','inseguro','tamano_incorrecto','hash_incorrecto','cabecera_incorrecta','archivo_cambiado','no_verificable'):raise ValueError()
            coincide=serializar(sorted(n['acciones'],key=serializar))==serializar(p['simulacion']['actualizaciones'])
            h['nativo']=dict(n,estado='coincidente' if coincide and not n['roto'] else 'diferente')
            h['espacio']=medir(n['archivos'])
        except (ValueError,KeyError,TypeError):pass
    return evaluar(d)


def informe(d):
    h=d['hechos'];p=h['plan'];s=p.get('simulacion',{})
    lineas=['Diagnóstico factual APT: '+d['evaluacion'], 'No autoriza descargas ni instalaciones.',
            'Plan: '+str(len(s.get('actualizaciones',[])))+' actualizaciones; '+str(len(s.get('instalaciones',[])))+' instalaciones; '+str(len(s.get('eliminaciones',[])))+' eliminaciones; '+str(len(s.get('retenciones',[])))+' retenciones.']
    for clave in ('dpkg','nativo','espacio','ejecutor','concurrencia','diario'):
        lineas.append(clave+': '+h.get(clave,{}).get('estado','no_verificable'))
    n=h.get('nativo',{})
    if n.get('python_apt'):lineas.append('python3-apt: '+n['python_apt'])
    for m in h.get('espacio',{}).get('montajes',[]):
        lineas.append(f"Espacio {m['ruta']}: {m['disponible_bytes']} bytes disponibles; umbral {m['umbral_bytes']} bytes.")
    archivos=n.get('archivos',[])
    lineas.append(f"Archivos verificados: {sum(r['comprobacion']['estado']=='verificado' for r in archivos)}/{len(archivos)}; descarga estimada: {h.get('espacio',{}).get('descarga_bytes','no comprobada')} bytes.")
    for r in archivos:
        origen=', '.join(f"{o['sitio']} {o['archivo']} (APT confiable={o['confiable']})" for o in r['origenes'])
        lineas.append(f"{r['nombre']}:{r['arquitectura']} propuesta {r['version']} | {r['bytes']} bytes esperados | SHA256 esperado {r['sha256']} | caché: {r['comprobacion']['estado']} | {origen}")
    lineas+=['Impedimentos: '+', '.join(d['impedimentos']), 'No comprobado: '+', '.join(d['no_comprobado']),
             'Pendiente para ejecutar: '+', '.join(d.get('pendiente_ejecucion',[])), 'Siguiente paso: '+d['recomendacion'],'Riesgos: '+' '.join(d['riesgos']),
             'Limitaciones: '+' '.join(d['limitaciones'])]
    return '\n'.join(lineas)


def plan_descarga(d):
    if d['version']!=1 or not d['preparacion_permitida']:
        raise ValueError('preparacion_no_verificable')
    p=d['hechos']['plan']
    filas=[{k:v for k,v in r.items() if k!='comprobacion'} for r in d['hechos']['nativo']['archivos']]
    validar_manifiesto(filas,p)
    return dict(version=1,tipo='plan_descarga_apt',autorizacion=False,plan=p,archivos=filas,
                estimacion_maxima_bytes=sum(r['bytes'] for r in filas),
                descarga_pendiente_bytes=d['hechos']['espacio']['descarga_bytes'],
                limitaciones=d['limitaciones'],instalacion_autorizada=False)
