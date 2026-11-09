"""explicacion_compacta_v1, aislada: hechos seleccionados y enlaces a autonomia_v1.

No importa el coordinador, herramientas, proveedor HTTP ni proyección anterior.
No aplica un presupuesto destructivo. Ver PROYECCION_COMPACTA.md.
"""
import copy
import hashlib
from collections import Counter
from contratos_autonomia import validar_traza, json_seguro, puntero
from contratos_mantenimiento import serializar

FORMATO = 'explicacion_compacta_v1'
META_BYTES = 6000
LIMITE_BYTES = 18000
PREFIJOS = {'evidencia':'E','hallazgo':'H','actuacion':'A','decision':'D','capacidad':'C'}
FALTANTE = object()


def _exigir(condicion):
    if not condicion:
        raise ValueError('proyeccion_compacta_invalida')


def _indice(traza):
    conteos=Counter();por_id={};por_alias={}
    for r in traza:
        if r['tipo'] in PREFIJOS:
            prefijo=PREFIJOS[r['tipo']];conteos[prefijo]+=1
            alias=prefijo+str(conteos[prefijo])
            por_id[r['id']]=alias;por_alias[alias]=r
    return por_id,por_alias


def _seleccionar(raiz, rutas):
    """Solo rutas cerradas: diferencia ausencia, null y estructura incorrecta."""
    datos={};ausentes=[]
    for ruta in rutas:
        origen=raiz;partes=ruta.split('/');camino=[]
        for parte in partes:
            if origen is None:break
            _exigir(type(origen) is dict)
            if parte not in origen:
                origen=FALTANTE;break
            origen=origen[parte];camino.append(parte)
        if origen is FALTANTE:
            ausentes.append('/resultado/'+ruta);continue
        # Si una rama es null, conservarla como tal, sin fingir hijos ausentes.
        if origen is not None:
            clave=partes[-1]
            if clave.endswith('_bytes') or clave in ('total_unidades','interfaces_enumeradas_ip','total_instalados','avisos_pendientes','total_resultados'):
                _exigir(type(origen) is int and origen>=0)
            elif clave=='inventario_completo':_exigir(type(origen) is bool)
            elif clave in ('impedimentos','no_comprobado','pendiente_ejecucion'):
                _exigir(type(origen) is list and all(type(x) is str for x in origen))
            else:_exigir(type(origen) is str)
        destino=datos
        for parte in camino[:-1]:destino=destino.setdefault(parte,{})
        if camino:destino[camino[-1]]=copy.deepcopy(origen)
    return datos,ausentes


def _hechos(e):
    """Selección declarada, sin diagnóstico, reclasificación ni adquisición."""
    p=e['datos']['resultado'];op=e['operacion_id']
    if e['estado'] not in ('completo','parcial'):
        return {},[],['resultado_no_utilizable']
    rutas={
        'sistema':(),  # uname -a puede contener hostname; identidad en cabecera/cobertura.
        'disco':(),
        'memoria':('ram/total_bytes','ram/disponible_estimada_bytes','swap/total_bytes','swap/ocupada_bytes','actividad_intercambio/estado'),
        'servicios_fallidos':('datos/total_unidades',),
        'interfaces_red':('alcance/interfaces_enumeradas_ip','alcance/conectividad','alcance/radio'),
        'auditoria_seguridad':('inventario_completo','total_instalados','estado_inventario','estado_seguridad','recuentos/avisos_pendientes'),
        'plan_mantenimiento':('candidatas/estado','simulacion/estado','simulacion/retenciones_estado'),
        'diagnostico_mantenimiento_apt':('evaluacion','impedimentos','no_comprobado','pendiente_ejecucion',
            'hechos/dpkg/estado','hechos/nativo/estado','hechos/espacio/estado','hechos/ejecutor/estado','hechos/diario/estado','hechos/concurrencia/estado'),
        'correlacion_seguridad':('detalle_dnf5','total_resultados','cisa_kev/estado'),
    }[op]
    datos,ausentes=_seleccionar(p,rutas)
    if op=='disco':
        filas=p.get('montajes',FALTANTE)
        if type(filas) is list:
            datos['montajes']=[]
            for i,m in enumerate(filas):
                if type(m) is not dict:raise ValueError('montaje_no_estructurado')
                if m.get('ruta') not in ('/','/usr','/var','/tmp'):continue
                fila,faltan=_seleccionar(m,('ruta','disponible_bytes','total_bytes'))
                datos['montajes'].append(fila)
                ausentes += ['/resultado/montajes/'+str(i)+r[len('/resultado'):] for r in faltan]
        elif filas is FALTANTE:ausentes.append('/resultado/montajes')
        elif filas is None:datos['montajes']=None
        else:raise ValueError('montajes_no_estructurados')
    if op=='plan_mantenimiento':
        # Son recuentos de las listas nativas, no nuevas decisiones del resolvedor.
        datos['recuentos']={}
        for bloque,campo in (('candidatas','paquetes'),('simulacion','actualizaciones'),('simulacion','instalaciones'),('simulacion','eliminaciones'),('simulacion','retenciones')):
            rama=p.get(bloque,{})
            filas=rama.get(campo) if type(rama) is dict else None
            conocido=type(rama) is dict and rama.get('estado')=='completo' and type(filas) is list
            if campo=='retenciones':conocido=conocido and rama.get('retenciones_estado')=='completo'
            datos['recuentos'][campo]=len(filas) if conocido else None
    estados=[]
    if e['estado']=='parcial':estados.append('adquisicion_parcial')
    return datos,ausentes,estados


def _desconocidos(datos):
    resultado=[]
    def recorrer(v,ruta):
        if v is None:resultado.append([ruta,'null'])
        elif type(v) is str and v in ('desconocido','desconocida','no_verificable','no_comprobado','no_comprobada','no_medida','no_evaluada','no_implementado'):
            resultado.append([ruta,v])
        elif type(v) is dict:
            for k,x in v.items():recorrer(x,ruta+'/'+k.replace('~','~0').replace('/','~1'))
        elif type(v) is list:
            for i,x in enumerate(v):recorrer(x,ruta+'/'+str(i))
    recorrer(datos,'')
    return resultado


def _construir(traza):
    ids,_=_indice(traza);objetivo=traza[0];cierre=traza[-1]
    limitaciones=[];posiciones={}
    def limites(textos):
        referencias=[]
        for texto in textos:
            if texto not in posiciones:
                posiciones[texto]=len(limitaciones);limitaciones.append(texto)
            referencias.append(posiciones[texto])
        return referencias
    def refs(referencias):
        return [[ids[r['evidencia_id']],r['campo']] for r in referencias]
    prioridades=Counter(r['prioridad'] for r in traza if r['tipo']=='hallazgo')
    salida=dict(formato=FORMATO,version=1,objetivo=objetivo['id'],
        huella_traza=hashlib.sha256(serializar(traza).encode()).hexdigest(),
        distribucion={k:objetivo['distribucion'][k] for k in ('id','version_id','estado')},
        estado=cierre['estado'],motivo=cierre['motivo_parada'],
        alcance=list(objetivo['alcance']),exclusiones=list(objetivo['exclusiones']),
        cobertura={area:dict(estado=f['estado'],motivo=f['motivo'],e=[ids[e] for e in f['evidencias']]) for area,f in cierre['cobertura'].items()},
        prioridades={p:prioridades[p] for p in ('P1','P2','P3','informativa')},
        hallazgos=[],informativas=[],operaciones={},no_realizadas=[],desconocidos={},
        limitaciones=limitaciones,pendientes=list(cierre['pendientes']),
        omisiones=dict(por_presupuesto=False,detalle_fuera_del_resumen=[]),autoriza_actuaciones=False)
    grupos={}
    for r in traza:
        tipo=r['tipo']
        if tipo=='hallazgo':
            comun=dict(regla=r['regla_id'],prioridad=r['prioridad'],verificacion=r['verificabilidad'],
                texto=r['conclusion_python'],lim=limites(r['limitaciones']),paso=r['siguiente_paso'])
            miembro=dict(h=ids[r['id']],refs=refs(r['evidencias']))
            if r['prioridad']=='informativa':
                # Comparación exacta, incluyendo orden/multiplicidad de limitaciones.
                clave=serializar(comun)
                if clave not in grupos:
                    grupos[clave]=dict(comun,miembros=[]);salida['informativas'].append(grupos[clave])
                grupos[clave]['miembros'].append(miembro)
            else:salida['hallazgos'].append(dict(comun,**miembro))
        elif tipo in ('evidencia','actuacion'):
            op=r['operacion_id'];operacion=salida['operaciones'].setdefault(op,dict(evidencias={},actuaciones={}))
            if tipo=='evidencia':
                datos,ausentes,estados=_hechos(r);alias=ids[r['id']]
                textos=list(r['limitaciones'])
                nativos=r['datos']['resultado'].get('limitaciones',[])
                _exigir(type(nativos) is list and all(type(x) is str for x in nativos))
                textos+=nativos
                operacion['evidencias'][alias]=dict(estado=r['estado'],truncado=r['truncado'],
                    procedencia=r['procedencia'],lim=limites(textos),datos=datos)
                desconocidos=dict(ausentes=ausentes,valores=_desconocidos(datos),estados=estados)
                if r['truncado']:desconocidos['estados'].append('fuente_truncada')
                if ausentes or desconocidos['valores'] or desconocidos['estados']:
                    salida['desconocidos'][alias]=desconocidos
                salida['omisiones']['detalle_fuera_del_resumen'].append(alias)
            else:
                operacion['actuaciones'][ids[r['id']]]=dict(decision=ids[r['decision_id']],estado=r['estado'],
                    e=[ids[e] for e in r['evidencias_generadas']],error=r['error_codigo'])
                # Invariantes que ya exige autonomia_v1: no se deducen del modelo.
                _exigir(r['efectos']=='lectura_local' and r['reintentada'] is False)
        elif tipo=='decision' and r['resultado'] in ('denegada','omitida'):
            salida['no_realizadas'].append(dict(d=ids[r['id']],operacion=r['operacion_id'],
                estado=r['resultado'],motivo=r['motivo'],refs=refs(r['evidencias'])))
        elif tipo=='capacidad' and r['estado']!='disponible':
            salida['no_realizadas'].append(dict(c=ids[r['id']],operacion=r['operacion_id'],estado=r['estado'],motivo=r['motivo']))
    for area,fila in cierre['cobertura'].items():
        if fila['estado'] in ('excluida','pendiente_por_presupuesto'):
            salida['no_realizadas'].append(dict(area=area,estado=fila['estado'],motivo=fila['motivo']))
    salida['efectos_comunes']=dict(tipo='lectura_local',reintentada=False)
    return salida


def proyectar(traza):
    """Devuelve el documento completo, aunque exceda la meta. No recorta datos."""
    return _construir(validar_traza(traza))


def validar(proyeccion, traza):
    """Compara tipos, valores, relaciones y agrupación con la fuente original.

    La representación es canónica: también se rechazan reordenaciones no previstas.
    No acepta una tabla de alias proporcionada por el modelo.
    """
    _exigir(type(proyeccion) is dict)
    json_seguro(proyeccion)
    esperado=_construir(validar_traza(traza))
    _exigir(serializar(proyeccion)==serializar(esperado))
    return copy.deepcopy(proyeccion)


def resolver_alias(proyeccion, alias, traza):
    """Resuelve solo dentro de la traza vinculada y tras validar todo el documento."""
    fuente=validar_traza(traza);validar(proyeccion,fuente)
    _exigir(type(alias) is str)
    _,indice=_indice(fuente)
    _exigir(alias in indice)
    r=indice[alias]
    return dict(id=r['id'],tipo=r['tipo'],objetivo_id=fuente[0]['id'])


def resolver_referencia(proyeccion, referencia, traza):
    """Referencia tipada [E<n>, JSON Pointer relativo a evidencia.datos]."""
    _exigir(type(referencia) is list and len(referencia)==2 and all(type(x) is str for x in referencia))
    fuente=validar_traza(traza);validar(proyeccion,fuente)
    _,indice=_indice(fuente);alias,ruta=referencia
    _exigir(alias in indice and indice[alias]['tipo']=='evidencia')
    e=indice[alias]
    return dict(evidencia_id=e['id'],campo=ruta,valor=copy.deepcopy(puntero(e['datos'],ruta)))


def evaluar_presupuesto(proyeccion, meta_bytes=META_BYTES, limite_bytes=LIMITE_BYTES):
    """Información de tamaño, no autorización de envío ni nuevo límite de política."""
    _exigir(type(meta_bytes) is int and type(limite_bytes) is int and 0<meta_bytes<=limite_bytes<=LIMITE_BYTES)
    json_seguro(proyeccion)
    usados=len(serializar(proyeccion).encode('utf-8'))
    return dict(bytes=usados,meta_bytes=meta_bytes,excede_meta=usados>meta_bytes,
                limite_bytes=limite_bytes,excede_limite=usados>limite_bytes,
                recortada=False)
