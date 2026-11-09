"""Evidencia DNF5 de lectura, nunca una autorización ni un ejecutor.

La única entrada nativa es recoger(), llamada por el worker DESPUÉS del
aislamiento. No contiene download/run/test/store ni comandos de transacción.
El contrato separado evita cambiar la versión 1 del plan Debian/APT.
"""
import hashlib
import re
import time
from contratos_mantenimiento import MAX_FILAS, paquete, serializar
from autorizacion_apt import leer_json, VIGENCIA, MAX_PETICION

ACCIONES = ('INSTALL', 'UPGRADE', 'DOWNGRADE', 'REINSTALL', 'REMOVE', 'REPLACED', 'REASON_CHANGE')
MOTIVOS_RECHAZO = ('accion_rpm_desconocida', 'grupo', 'entorno', 'modulo',
                  'motivo_rpm_no_representable', 'operacion_no_representable')
MAX_DIAGNOSTICOS = 8
MAX_CODIGOS = 8
PENDIENTES = ('retenciones_no_comprobadas', 'avisos_no_correlacionados',
              'metadatos_no_identificados', 'configuracion_no_identificada',
              'rpm_no_verificados', 'continuidad_bloqueo_no_verificada')
ERRORES = ('binding_no_disponible', 'api_dnf5_no_admitida', 'resolucion_dnf5_fallida',
           'permisos_insuficientes', 'repositorios_no_verificados', 'conflictos_dnf5',
           'acciones_dnf5_no_admitidas', 'evidencia_dnf5_invalida',
           'inventario_no_coincidente', 'inventario_incompleto', 'tiempo_agotado',
           'aislamiento_no_disponible', 'dependencia_ausente', 'consulta_nativa_fallida',
           'avisos_no_verificados', 'error_gestor', 'error_sistema', 'limite_salida',
           'ejecucion_root_rechazada', 'temporal_no_disponible',
           'terminacion_no_confirmada', 'dnf5_no_disponible')


def huella(d):
    return hashlib.sha256(serializar(dict(d, huella=None)).encode()).hexdigest()


def codigo_diagnostico(valor):
    # No convertir objetos, nombres, repr, mensajes o texto nativo a cadenas.
    return valor if type(valor) is int and -(2**31)<=valor<2**31 else None


def detalle_rechazo(motivo, *, cantidad=1, codigos=None, truncado=False,
                    codigos_truncados=False, verdad_contenedor=True, representacion='iterable'):
    return dict(motivo=motivo,cantidad=cantidad,codigos=codigos or [],
                truncado=truncado,codigos_truncados=codigos_truncados,
                verdad_contenedor=verdad_contenedor,representacion=representacion)


class OperacionNoRepresentable(ValueError):
    def __init__(self,motivo,codigo=None):
        super().__init__('acciones_dnf5_no_admitidas')
        self.diagnostico=[detalle_rechazo(motivo,codigos=[codigo_diagnostico(codigo)])]


def resultado(error=None, *, acciones=None, inventario=None, repositorios=None, ahora=None, diagnostico=None):
    if diagnostico is None:
        diagnostico=([detalle_rechazo('operacion_no_representable')]
                     if error=='acciones_dnf5_no_admitidas' else [])
    d = dict(version=2, tipo='preparacion_dnf5', estado='no_verificable',
             acciones_estado='no_comprobada' if error else 'completo',
             creado=int(time.time() if ahora is None else ahora), vigencia=VIGENCIA,
             acciones=acciones or [], inventario=inventario or [], repositorios=repositorios or [],
             pendientes=list(PENDIENTES), errores=[error] if error else [],
             ejecucion_habilitada=False, diagnostico=diagnostico, huella=None)
    d['huella']=huella(d)
    return validar(d)


def validar_paquete(p):
    if type(p) is not dict or set(p)!={'nombre','arquitectura','evr'}:
        raise ValueError('evidencia_dnf5_invalida')
    paquete(p['nombre'],p['arquitectura'],p['evr'],None)
    if (p['arquitectura'] is None or type(p['evr']) is not str
            or not re.fullmatch(r'[0-9]+:[A-Za-z0-9.+~^%_\-]+',p['evr'])):
        raise ValueError('evidencia_dnf5_invalida')


def lista(filas, validar_fila):
    if type(filas) is not list or len(filas)>MAX_FILAS:
        raise ValueError('evidencia_dnf5_invalida')
    vistos=set()
    for fila in filas:
        validar_fila(fila)
        clave=serializar(fila)
        if clave in vistos:raise ValueError('evidencia_dnf5_invalida')
        vistos.add(clave)


def validar_repo(repo):
    if type(repo) is not str or not re.fullmatch(r'[A-Za-z0-9_@.+:\-]{1,256}',repo):
        raise ValueError('evidencia_dnf5_invalida')


def validar(d):
    campos={'version','tipo','estado','acciones_estado','creado','vigencia','acciones',
            'inventario','repositorios','pendientes','errores','ejecucion_habilitada','huella'}
    if type(d) is not dict:
        raise ValueError('evidencia_dnf5_invalida')
    # Lectura compatible con v1; toda evidencia nueva usa v2 y campo cerrado.
    if d.get('version')==2:campos.add('diagnostico')
    if set(d)!=campos:
        raise ValueError('evidencia_dnf5_invalida')
    if (type(d['version']) is not int or d['version'] not in (1,2) or d['tipo']!='preparacion_dnf5'
            or d['estado']!='no_verificable' or d['ejecucion_habilitada'] is not False
            or d['pendientes']!=list(PENDIENTES) or type(d['vigencia']) is not int
            or d['vigencia']!=VIGENCIA or type(d['creado']) is not int or d['creado']<0):
        raise ValueError('evidencia_dnf5_invalida')
    if type(d['errores']) is not list or len(d['errores'])>1 or any(e not in ERRORES for e in d['errores']):
        raise ValueError('evidencia_dnf5_invalida')
    if d['acciones_estado']!=('no_comprobada' if d['errores'] else 'completo'):
        raise ValueError('evidencia_dnf5_invalida')
    if d['errores'] and any(d[k] for k in ('acciones','inventario','repositorios')):
        raise ValueError('evidencia_dnf5_invalida')
    if d['version']==2:
        diagnostico=d['diagnostico']
        if (type(diagnostico) is not list or len(diagnostico)>MAX_DIAGNOSTICOS
                or bool(diagnostico)!=(d['errores']==['acciones_dnf5_no_admitidas'])):
            raise ValueError('evidencia_dnf5_invalida')
        for detalle in diagnostico:
            if type(detalle) is not dict or set(detalle)!={
                    'motivo','cantidad','codigos','truncado','codigos_truncados','verdad_contenedor','representacion'}:
                raise ValueError('evidencia_dnf5_invalida')
            if (detalle['motivo'] not in MOTIVOS_RECHAZO
                    or detalle['representacion'] not in ('iterable','no_iterable','lectura_no_disponible')
                    or (detalle['representacion']=='iterable' and (type(detalle['cantidad']) is not int
                        or not 0<=detalle['cantidad']<=MAX_FILAS))
                    or (detalle['representacion']!='iterable' and detalle['cantidad'] is not None)
                    or any(type(detalle[k]) is not bool for k in ('truncado','codigos_truncados','verdad_contenedor'))
                    or type(detalle['codigos']) is not list or len(detalle['codigos'])>MAX_CODIGOS
                    or any(c is not None and (type(c) is not int or codigo_diagnostico(c) is None) for c in detalle['codigos'])
                    or len(set(detalle['codigos']))!=len(detalle['codigos'])):
                raise ValueError('evidencia_dnf5_invalida')
    lista(d['inventario'],validar_paquete)
    lista(d['repositorios'],validar_repo)
    inventario={serializar(p) for p in d['inventario']}
    def accion(a):
        if type(a) is not dict or set(a)!={'accion','paquete','reemplaza','repositorio','motivo'}:
            raise ValueError('evidencia_dnf5_invalida')
        if a['accion'] not in ACCIONES:
            raise OperacionNoRepresentable('accion_rpm_desconocida')
        if type(a['motivo']) is not int or not 0<=a['motivo']<=100:
            raise OperacionNoRepresentable('motivo_rpm_no_representable',a['motivo'])
        validar_paquete(a['paquete']);validar_repo(a['repositorio'])
        lista(a['reemplaza'],validar_paquete)
        if a['repositorio'] not in (*d['repositorios'],'@System'):
            raise ValueError('repositorios_no_verificados')
        if (a['accion'] in ('REMOVE','REPLACED','REASON_CHANGE') and serializar(a['paquete']) not in inventario
                or any(serializar(p) not in inventario for p in a['reemplaza'])):
            raise ValueError('inventario_no_coincidente')
    lista(d['acciones'],accion)
    if not d['errores'] and not d['inventario']:
        raise ValueError('inventario_incompleto')
    if len(serializar(d).encode())>MAX_PETICION or d['huella']!=huella(d):
        raise ValueError('evidencia_dnf5_invalida')
    return d


def leer(texto):
    if len(texto.encode())>MAX_PETICION:raise ValueError('evidencia_dnf5_invalida')
    return validar(leer_json(texto))


def comprobar_identidad(esperada, actual, *, ahora=None):
    """Comparación de evidencia; NO acredita bloqueo, firmas ni autorización."""
    validar(esperada);validar(actual)
    ahora=time.time() if ahora is None else ahora
    for d in (esperada,actual):
        if not 0<=ahora-d['creado']<=VIGENCIA:raise ValueError('autorizacion_caducada')
        if d['acciones_estado']!='completo':raise ValueError('plan_no_verificable')
    claves=('acciones','inventario','repositorios','pendientes')
    if any(serializar(esperada[k])!=serializar(actual[k]) for k in claves):
        raise ValueError('transaccion_nativa_diferente')
    return True


def comprobar_ejecutable(d):
    validar(d)
    # No hay una política administrativa DNF5 validada. Ni siquiera una huella
    # idéntica elimina los pendientes o concede autoridad al informe de lectura.
    raise ValueError('plan_no_verificable')


def _paquete_nativo(p):
    epoch=p.get_epoch() or '0'
    return dict(nombre=p.get_name(),arquitectura=p.get_arch(),
                evr=str(epoch)+':'+p.get_version()+'-'+p.get_release())


def diagnosticar_coleccion(motivo, valores):
    """Solo conteos acotados y códigos numéricos; nunca ID/nombre/URL nativos.

    Conserva la decisión booleana original, incluso si un wrapper SWIG declara
    verdadero un vector vacío. El conteo permite identificar esa discrepancia
    sin aceptar aquí una operación antes rechazada.
    """
    cantidad=0;codigos=[];truncado=False;codigos_truncados=False
    try:
        iterador=iter(valores)
    except Exception as exc:
        return detalle_rechazo(motivo,cantidad=None,
            representacion='no_iterable' if isinstance(exc,TypeError) else 'lectura_no_disponible',
            verdad_contenedor=bool(valores))
    try:
        for item in iterador:
            if cantidad==MAX_FILAS:
                truncado=True;break
            cantidad+=1
            try:codigo=codigo_diagnostico(item.get_action())
            except Exception:codigo=None
            if codigo not in codigos:
                if len(codigos)<MAX_CODIGOS:codigos.append(codigo)
                else:codigos_truncados=True
    except Exception:
        # El diagnóstico nunca convierte una inspección fallida en cantidad cero
        # ni sustituye el rechazo de operaciones por un error genérico de API.
        return detalle_rechazo(motivo,cantidad=None,representacion='lectura_no_disponible',
                               verdad_contenedor=bool(valores))
    return detalle_rechazo(motivo,cantidad=cantidad,codigos=codigos,truncado=truncado,
                           codigos_truncados=codigos_truncados,verdad_contenedor=bool(valores))


def inspeccionar(lib, base, transaccion):
    if transaccion.get_problems()!=lib.base.GoalProblem_NO_PROBLEM:
        return resultado('conflictos_dnf5')
    # También un resultado con avisos u operaciones no RPM queda cerrado.
    if transaccion.get_resolve_logs():return resultado('conflictos_dnf5')
    colecciones=(('grupo',transaccion.get_transaction_groups()),
                 ('entorno',transaccion.get_transaction_environments()),
                 ('modulo',transaccion.get_transaction_modules()))
    if any(valores for _,valores in colecciones):
        return resultado('acciones_dnf5_no_admitidas',diagnostico=[
            diagnosticar_coleccion(motivo,valores) for motivo,valores in colecciones if valores])
    etiquetas={getattr(lib.transaction,'TransactionItemAction_'+a):a for a in ACCIONES}
    consulta=lib.rpm.PackageQuery(base)
    consulta.filter_installed()
    inventario=sorted((_paquete_nativo(p) for p in consulta),key=serializar)
    repos=lib.repo.RepoQuery(base);repos.filter_enabled(True)
    ids=sorted(r.get_id() for r in repos)
    acciones=[]
    for item in transaccion.get_transaction_packages():
        if len(acciones)>=MAX_FILAS:raise ValueError('evidencia_dnf5_invalida')
        codigo=item.get_action()
        accion=etiquetas.get(codigo)
        if accion is None:
            return resultado('acciones_dnf5_no_admitidas',diagnostico=[
                detalle_rechazo('accion_rpm_desconocida',codigos=[codigo_diagnostico(codigo)])])
        p=item.get_package()
        acciones.append(dict(accion=accion,paquete=_paquete_nativo(p),
            reemplaza=sorted((_paquete_nativo(v) for v in item.get_replaces()),key=serializar),
            repositorio=p.get_repo_id(),motivo=int(item.get_reason())))
    return resultado(acciones=sorted(acciones,key=serializar),inventario=inventario,repositorios=ids)


def recoger(temporal):
    """Solo en worker aislado. Imports nativos opcionales del sistema Fedora."""
    try:
        import libdnf5.base
        import libdnf5.conf
        import libdnf5.repo
        import libdnf5.rpm
        import libdnf5.transaction
    except ImportError:
        return resultado('binding_no_disponible')
    try:
        base=libdnf5.base.Base()
        base.load_config()
        conf=base.get_config()
        for nombre,valor in (('plugins',False),('cacheonly','all'),('build_cache',False),
                ('logdir',temporal),('persistdir',temporal),('skip_if_unavailable',False),
                ('skip_broken',False),('skip_unavailable',False),('allow_downgrade',False)):
            getattr(conf,'get_'+nombre+'_option')().set(valor)
        base.setup()
        sack=base.get_repo_sack()
        sack.create_repos_from_system_configuration()
        repos=libdnf5.repo.RepoQuery(base);repos.filter_enabled(True)
        if not list(repos):return resultado('repositorios_no_verificados')
        for repo in repos:
            c=repo.get_config()
            c.get_skip_if_unavailable_option().set(False)
            c.get_build_cache_option().set(False)
        # No solicitar bloqueos de escritura en diagnóstico. Si esta API necesita
        # crearlos, el aislamiento lo rechaza y no se relaja para continuar.
        sack.load_repos()
        goal=libdnf5.base.Goal(base)
        goal.add_rpm_upgrade()
        transaccion=goal.resolve()
        return inspeccionar(libdnf5,base,transaccion)
    except PermissionError:
        return resultado('permisos_insuficientes')
    except OperacionNoRepresentable as exc:
        return resultado('acciones_dnf5_no_admitidas',diagnostico=exc.diagnostico)
    except ValueError as exc:
        return resultado(str(exc) if str(exc) in ERRORES else 'resolucion_dnf5_fallida')
    except (AttributeError,TypeError):
        return resultado('api_dnf5_no_admitida')
    except Exception:
        # Nunca registrar excepciones nativas que puedan incluir URL/credenciales.
        return resultado('resolucion_dnf5_fallida')
