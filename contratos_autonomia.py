"""autonomia_v1: contratos y referencias estrictas de la traza factual en memoria."""
import copy
from datetime import datetime, timezone
import hashlib
import re
from contratos_mantenimiento import serializar

POLITICA = 'auditoria_basica_local_v1'
AREAS = ('identidad','disco','memoria','servicios','red','seguridad','mantenimiento')
OPERACIONES = ('sistema','disco','memoria','servicios_fallidos','interfaces_red',
               'auditoria_seguridad','plan_mantenimiento','diagnostico_mantenimiento_apt',
               'correlacion_seguridad')
LIMITES = dict(segundos=120, segundos_modelo=45, rondas=4, por_ronda=4,
               llamadas=8, salida=18000, salida_total=60000)
PARADAS = ('cobertura_completada','tiempo_agotado','rondas_agotadas','llamadas_agotadas',
           'salida_agotada','registro_agotado','sin_ampliacion_permitida',
           'capacidad_insuficiente','evidencia_insuficiente','cancelacion_usuario','error_interno')
ESTADOS = ('completo','parcial','error','no_disponible','no_verificable')
CAMPOS = {
 'objetivo_auditoria':'id creado_utc alcance exclusiones distribucion politica_id politica_version permisos limites estado motivo_parada',
 'capacidad':'id objetivo_id operacion_id estado fuentes motivo observado_utc',
 'evidencia':'id objetivo_id operacion_id subconsulta_id adquirido_utc duracion_ms estado contrato_origen version_origen datos sha256_payload limitaciones truncado procedencia',
 'decision':'id objetivo_id secuencia creado_utc proponente operacion_id argumentos_validados evidencias regla_id politica_id resultado motivo ganancia_esperada presupuesto_antes presupuesto_despues',
 'hallazgo':'id objetivo_id regla_id prioridad verificabilidad evidencias conclusion_python limitaciones siguiente_paso',
 'actuacion':'id objetivo_id decision_id operacion_id inicio_utc duracion_ms estado evidencias_generadas error_codigo efectos reintentada',
 'cierre':'objetivo_id terminado_utc estado motivo_parada cobertura hallazgos actuaciones pendientes presupuesto_final',
}


def utc():
    return datetime.now(timezone.utc).isoformat()


def exigir(condicion):
    if not condicion:
        raise ValueError('contrato_autonomia_invalido')


def texto(v):
    return type(v) is str and 0 < len(v) <= 18000 and all(
        ord(c) >= 32 or c in '\n\t' for c in v) and not any(
        0x7f <= ord(c) <= 0x9f or 0x202a <= ord(c) <= 0x202e or 0x2066 <= ord(c) <= 0x2069 for c in v)


def entero(v, minimo=0):
    return type(v) is int and v >= minimo


def lista_textos(v):
    return type(v) is list and all(texto(x) for x in v)


def fecha(v):
    exigir(texto(v))
    try:
        d = datetime.fromisoformat(v)
        exigir(d.utcoffset() is not None and d.utcoffset().total_seconds() == 0)
    except (TypeError, ValueError):
        raise ValueError('fecha_autonomia_invalida') from None


def presupuesto(v):
    exigir(type(v) is dict and set(v) == {'llamadas','rondas','salida','restante_ms'})
    for k in v:
        exigir(entero(v[k]))
    exigir(v['llamadas'] <= 8 and v['rondas'] <= 4 and v['salida'] <= 60000 and v['restante_ms'] <= 120000)


def puntero(datos, ruta):
    exigir(type(ruta) is str and (ruta == '' or ruta.startswith('/')))
    actual = datos
    for token in ruta.split('/')[1:] if ruta else []:
        exigir(not re.search(r'~(?![01])', token))
        token = token.replace('~1','/').replace('~0','~')
        if type(actual) is dict:
            exigir(token in actual)
            actual = actual[token]
        elif type(actual) is list:
            exigir(bool(re.fullmatch(r'0|[1-9][0-9]*', token)) and int(token) < len(actual))
            actual = actual[int(token)]
        else:
            raise ValueError('referencia_autonomia_invalida')
    return actual


def json_seguro(v, profundidad=0):
    exigir(profundidad <= 40)
    if v is None or type(v) in (bool,int):
        return
    if type(v) is str:
        # Payloads ya normalizados pueden conservar cadenas vacías, nunca controles.
        exigir(v == '' or texto(v))
    elif type(v) is list:
        for x in v:json_seguro(x, profundidad+1)
    elif type(v) is dict:
        for k,x in v.items():
            exigir(texto(k));json_seguro(x, profundidad+1)
    elif type(v) is float:
        serializar(v)  # rechaza NaN e infinitos
    else:
        raise ValueError('json_autonomia_invalido')


def validar(r, evidencias=None):
    exigir(type(r) is dict and type(r.get('tipo')) is str and r['tipo'] in CAMPOS)
    tipo = r['tipo']
    exigir(set(r) == {'version','tipo',*CAMPOS[tipo].split()})
    exigir(type(r['version']) is int and r['version'] == 1)
    json_seguro(r)
    for k in ('id','objetivo_id','operacion_id','decision_id','regla_id','conclusion_python','ganancia_esperada','motivo'):
        if k in r:exigir(texto(r[k]))
    for k in ('creado_utc','observado_utc','adquirido_utc','inicio_utc','terminado_utc'):
        if k in r:fecha(r[k])
    if 'operacion_id' in r and tipo != 'decision':exigir(r['operacion_id'] in OPERACIONES)
    if 'politica_id' in r:exigir(r['politica_id'] == POLITICA)
    if 'limitaciones' in r:exigir(lista_textos(r['limitaciones']))
    if tipo == 'objetivo_auditoria':
        exigir(type(r['politica_version']) is int and r['politica_version'] == 1)
        exigir(type(r['permisos']) is dict and r['permisos'] == dict(nivel1_local=True,nivel2_local=True,externo=False))
        exigir(all(type(v) is bool for v in r['permisos'].values()))
        exigir(type(r['limites']) is dict and r['limites'] == LIMITES and all(type(v) is int for v in r['limites'].values()))
        for k in ('alcance','exclusiones'):
            exigir(lista_textos(r[k]) and len(r[k]) == len(set(r[k])) and set(r[k]) <= set(AREAS))
        exigir(not set(r['alcance']) & set(r['exclusiones']) and set(r['alcance']) | set(r['exclusiones']) == set(AREAS))
        exigir(type(r['distribucion']) is dict and set(r['distribucion']) == {'estado','id','version_id','version_codename','origen','motivo'})
        exigir(r['distribucion']['estado'] in ('soportado','no_soportado'))
        for k,v in r['distribucion'].items():exigir(v is None or texto(v))
        if r['distribucion']['estado'] == 'soportado':
            exigir((r['distribucion']['id']=='debian' and r['distribucion']['version_id']=='13') or
                   (r['distribucion']['id']=='fedora' and bool(re.fullmatch(r'[0-9]+(?:\.[0-9]+)*',r['distribucion']['version_id'] or ''))))
        exigir(r['estado'] in ('activo','completo','parcial','cancelado','error'))
        exigir((r['estado']=='activo' and r['motivo_parada'] is None) or (r['estado']!='activo' and r['motivo_parada'] in PARADAS))
    elif tipo == 'capacidad':
        exigir(r['estado'] in ('disponible','no_disponible','no_verificable') and lista_textos(r['fuentes']))
    elif tipo == 'evidencia':
        exigir(r['estado'] in ESTADOS and entero(r['duracion_ms']))
        exigir(r['subconsulta_id'] is None or texto(r['subconsulta_id']))
        exigir(texto(r['contrato_origen']) and entero(r['version_origen'],1))
        exigir(type(r['datos']) is dict and type(r['truncado']) is bool and r['procedencia'] in ('local','cache_local'))
        exigir(r['contrato_origen']=='observacion_autonomia_v1' and r['version_origen']==1)
        datos=r['datos']
        exigir(set(datos)=={'estado','resultado','subconsultas'} and datos['estado']==r['estado'])
        exigir(type(datos['resultado']) is dict and type(datos['subconsultas']) is list)
        for sub in datos['subconsultas']:
            exigir(type(sub) is dict and set(sub)=={'operacion','estado','duracion_ms'})
            exigir(texto(sub['operacion']) and texto(sub['estado']) and entero(sub['duracion_ms']))
        exigir(r['sha256_payload'] == hashlib.sha256(serializar(r['datos']).encode()).hexdigest())
    elif tipo == 'decision':
        exigir(entero(r['secuencia'],1) and r['proponente'] in ('python','modelo'))
        exigir(type(r['argumentos_validados']) is dict and r['argumentos_validados'] == {})
        exigir(r['resultado'] in ('permitida','denegada','omitida'))
        if r['resultado']=='permitida':exigir(r['operacion_id'] in OPERACIONES)
        presupuesto(r['presupuesto_antes']);presupuesto(r['presupuesto_despues'])
        a,b=r['presupuesto_antes'],r['presupuesto_despues']
        exigir(b['llamadas']==a['llamadas']+1 and b['rondas']>=a['rondas'] and b['salida']>=a['salida'] and b['restante_ms']<=a['restante_ms'])
    elif tipo == 'hallazgo':
        exigir(r['regla_id'] in ('PRI-01','PRI-02','PRI-03','PRI-04','PRI-05'))
        exigir(r['prioridad'] == {'PRI-01':'P1','PRI-02':'P2','PRI-03':'P3','PRI-04':'P3','PRI-05':'informativa'}[r['regla_id']])
        exigir(r['verificabilidad'] in ('comprobada','parcial','no_verificable'))
        exigir(r['siguiente_paso'] is None or r['siguiente_paso'] in OPERACIONES)
    elif tipo == 'actuacion':
        exigir(r['estado'] in (*ESTADOS,'cancelado') and entero(r['duracion_ms']))
        exigir(lista_textos(r['evidencias_generadas']) and (r['error_codigo'] is None or texto(r['error_codigo'])))
        exigir(r['efectos']=='lectura_local' and r['reintentada'] is False)
    elif tipo == 'cierre':
        exigir(r['estado'] in ('completo','parcial','cancelado','error') and r['motivo_parada'] in PARADAS)
        exigir(type(r['cobertura']) is dict and set(r['cobertura'])==set(AREAS))
        for fila in r['cobertura'].values():
            exigir(type(fila) is dict and set(fila)=={'estado','evidencias','motivo'})
            exigir(fila['estado'] in ('comprobada','parcial','no_disponible','excluida','pendiente_por_presupuesto'))
            exigir(lista_textos(fila['evidencias']) and texto(fila['motivo']))
        exigir(lista_textos(r['hallazgos']) and lista_textos(r['actuaciones']) and lista_textos(r['pendientes']))
        presupuesto(r['presupuesto_final'])
        if r['estado']=='completo':exigir(all(f['estado'] in ('comprobada','excluida') for f in r['cobertura'].values()))
    if 'evidencias' in r:
        exigir(type(r['evidencias']) is list)
        for ref in r['evidencias']:
            exigir(type(ref) is dict and set(ref)=={'evidencia_id','campo'} and texto(ref['evidencia_id']))
            exigir(type(ref['campo']) is str and (ref['campo']=='' or ref['campo'].startswith('/')) and not re.search(r'~(?![01])',ref['campo']))
            if evidencias is not None:
                exigir(ref['evidencia_id'] in evidencias)
                e=evidencias[ref['evidencia_id']]
                exigir(e['objetivo_id']==r['objetivo_id'] and not e['truncado'])
                puntero(e['datos'],ref['campo'])
    return r


def validar_traza(registros):
    exigir(type(registros) is list and bool(registros))
    exigir(len(serializar(registros).encode()) <= 4*1024*1024)
    evidencias={};decisiones={};hallazgos={};actuaciones={};identificadores=set()
    objetivo=registros[0];validar(objetivo)
    exigir(objetivo['tipo']=='objetivo_auditoria')
    exigir(sum(r.get('tipo')=='objetivo_auditoria' for r in registros)==1)
    exigir(sum(r.get('tipo')=='cierre' for r in registros)==1 and registros[-1]['tipo']=='cierre')
    for r in registros:
        validar(r,evidencias)
        if 'id' in r:
            exigir(r['id'] not in identificadores);identificadores.add(r['id'])
        if 'objetivo_id' in r:exigir(r['objetivo_id']==objetivo['id'])
        if r['tipo']=='evidencia':evidencias[r['id']]=r
        if r['tipo']=='decision':
            exigir(r['secuencia']==len(decisiones)+1);decisiones[r['id']]=r
        if r['tipo']=='hallazgo':hallazgos[r['id']]=r
        if r['tipo']=='actuacion':
            exigir(r['decision_id'] in decisiones)
            d=decisiones[r['decision_id']]
            exigir(d['resultado']=='permitida' and d['operacion_id']==r['operacion_id'])
            exigir(not any(a['decision_id']==r['decision_id'] for a in actuaciones.values()))
            exigir(all(e in evidencias and evidencias[e]['operacion_id']==r['operacion_id'] for e in r['evidencias_generadas']))
            actuaciones[r['id']]=r
    exigir(len(evidencias)<=64 and len(decisiones)+len(actuaciones)<=128)
    cierre=registros[-1]
    exigir(cierre['hallazgos']==list(hallazgos) and cierre['actuaciones']==list(actuaciones))
    exigir(objetivo['estado']==cierre['estado'] and objetivo['motivo_parada']==cierre['motivo_parada'])
    exigir(cierre['presupuesto_final']['llamadas']==len(decisiones))
    exigir(cierre['presupuesto_final']['rondas']==(len(decisiones)+3)//4)
    for indice,d in enumerate(decisiones.values()):
        exigir(d['presupuesto_antes']['llamadas']==indice and d['presupuesto_despues']['llamadas']==indice+1)
        if d['resultado']=='permitida':
            exigir(any(a['decision_id']==d['id'] for a in actuaciones.values()))
            op=d['operacion_id'];regla=d['regla_id']
            if regla=='BASE-01':
                exigir(op in OPERACIONES[:7] and AREAS[OPERACIONES.index(op)] in objetivo['alcance'] and not d['evidencias'])
            else:
                exigir(len(d['evidencias'])==1)
                e=evidencias[d['evidencias'][0]['evidencia_id']]
                exigir(e['estado']=='completo')
                p=e['datos']['resultado']
                if regla=='INV-APT-01':
                    s=p.get('simulacion',{})
                    exigir(op=='diagnostico_mantenimiento_apt' and objetivo['distribucion']['id']=='debian' and e['operacion_id']=='plan_mantenimiento')
                    exigir(s.get('estado')=='completo' and bool(s.get('actualizaciones')) and not s.get('instalaciones') and not s.get('eliminaciones'))
                elif regla=='INV-FED-01':
                    exigir(op=='correlacion_seguridad' and objetivo['distribucion']['id']=='fedora' and e['operacion_id']=='auditoria_seguridad')
                    exigir(any(type(a) is dict and a.get('id') and a.get('paquetes') for a in p.get('avisos_pendientes',[]) or []))
                else:raise ValueError('regla_autonomia_no_permitida')
    permitidas=[d['operacion_id'] for d in decisiones.values() if d['resultado']=='permitida']
    exigir(len(set(permitidas))==len(permitidas))
    for area,fila in cierre['cobertura'].items():
        exigir(all(e in evidencias for e in fila['evidencias']))
        if fila['estado']=='comprobada':
            exigir(bool(fila['evidencias']) and all(evidencias[e]['estado']=='completo' for e in fila['evidencias']))
        exigir((area in objetivo['exclusiones']) == (fila['estado']=='excluida'))
    return copy.deepcopy(registros)
