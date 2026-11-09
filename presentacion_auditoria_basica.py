"""Informe terminal puro: lee copias de autonomia_v1; no adquiere ni decide."""
from collections import Counter, defaultdict
from contratos_autonomia import validar_traza

ETIQUETAS = {'identidad':'Identidad','disco':'Disco','memoria':'Memoria',
             'servicios':'Servicios','red':'Red','seguridad':'Seguridad','mantenimiento':'Mantenimiento'}
ESTADOS = {'completo':'completa','parcial':'parcial','cancelado':'cancelada','error':'con errores'}


def cantidad(valor):
    if type(valor) is not int or valor < 0:
        return 'desconocido'
    unidades=('B','KiB','MiB','GiB','TiB')
    indice=0;numero=valor
    while numero >= 1024 and indice<len(unidades)-1:
        numero/=1024;indice+=1
    return f'{numero:.1f} {unidades[indice]}' if indice else f'{valor} B'


def estado_visible(estado):
    return estado.replace('_',' ')


def grupos_actualizaciones(filas):
    """Agrupación exclusivamente léxica: no infiere origen, riesgo ni función."""
    familias=defaultdict(list)
    for fila in filas:
        familias[fila['nombre'].split('-',1)[0]].append(fila)
    lineas=[]
    for prefijo,paquetes in sorted(familias.items()):
        pares={(p['anterior'],p['propuesta']) for p in paquetes}
        if len(paquetes)>1 and len(prefijo)>=3:
            detalle=(str(next(iter(pares))[0])+' -> '+str(next(iter(pares))[1])
                     if len(pares)==1 else 'versiones diversas; detalle en JSON')
            lineas.append(f'{prefijo}* (por nombre): {len(paquetes)} actualizaciones; {detalle}.')
        else:
            for p in paquetes:
                lineas.append(f"{p['nombre']}:{p['arquitectura']} {p['anterior']} -> {p['propuesta']}")
    if len(lineas)>10:
        return lineas[:10]+[f'Otros {len(lineas)-10} grupos/paquetes: detalle completo en JSON.']
    return lineas


def detalles(operacion,p,estado):
    """No sustituir datos ausentes por ceros, ni usar resultados fallidos."""
    if estado not in ('completo','parcial'):
        return ['Sin resultados utilizables; datos desconocidos.']
    if operacion=='sistema':
        return ['Kernel observado: '+p['kernel']] if p.get('kernel') else ['Kernel no comprobado.']
    if operacion=='disco':
        filas=p.get('montajes',[])
        return [f"{m.get('ruta','ruta desconocida')}: {cantidad(m.get('disponible_bytes'))} disponibles de {cantidad(m.get('total_bytes'))}."
                for m in filas] or ['Espacio disponible no comprobado.']
    if operacion=='memoria':
        ram=p.get('ram',{});swap=p.get('swap',{})
        return [f"RAM: {cantidad(ram.get('total_bytes'))} total; {cantidad(ram.get('disponible_estimada_bytes'))} disponibles (estimación).",
                f"Swap: {cantidad(swap.get('ocupada_bytes'))} ocupada de {cantidad(swap.get('total_bytes'))}.",
                'Actividad de intercambio no medida; una muestra no demuestra presión sostenida.']
    if operacion=='servicios_fallidos':
        datos=p.get('datos',{});unidades=datos.get('unidades')
        total=datos.get('total_unidades')
        if total is None and estado=='completo' and type(unidades) is list:total=len(unidades)
        if type(total) is not int or total<0:return ['Número de servicios fallidos desconocido; no equivale a cero.']
        lineas=[f'Servicios fallidos observados: {total}.']
        for u in (unidades or [])[:10]:
            nombre=u.get('nombre',u.get('Id'))
            if nombre:lineas.append('Unidad: '+nombre)
        if total>10:lineas.append('Listado abreviado; resto en JSON.')
        lineas.append('Estado del gestor del sistema; no se han consultado logs ni impacto funcional.')
        return lineas
    if operacion=='interfaces_red':
        filas=p.get('interfaces',[])
        lineas=[]
        for r in filas[:10]:
            lineas.append(f"{r.get('nombre','interfaz desconocida')}: administrativo {r.get('administrativo','desconocido')}; operativo {r.get('operativo','desconocido')}.")
            nm=r.get('networkmanager')
            if type(nm) is dict:
                lineas.append('  NetworkManager: '+str(nm.get('estado_observado') or 'desconocido')+'.')
        if not filas:lineas.append('No hay interfaces utilizables en el resultado; no demuestra ausencia de red.')
        if len(filas)>10:lineas.append('Interfaces restantes en JSON.')
        lineas.append('Conectividad externa no comprobada; radio no medida.')
        return lineas
    if operacion=='plan_mantenimiento':
        candidatas=p.get('candidatas',{});s=p.get('simulacion',{})
        lineas=['Candidatas APT/DNF: '+(str(len(candidatas.get('paquetes',[]))) if candidatas.get('estado')=='completo' else 'desconocidas o parciales')+'.']
        if s.get('estado')=='completo':
            lineas.append(f"Resolvedor: {len(s['actualizaciones'])} actualizaciones, {len(s['instalaciones'])} instalaciones adicionales, {len(s['eliminaciones'])} eliminaciones.")
            lineas.append('Retenciones: '+(str(len(s['retenciones'])) if s.get('retenciones_estado')=='completo' else 'no comprobadas')+'.')
            lineas+=grupos_actualizaciones(s['actualizaciones'])
        else:
            lineas.append('Simulación '+estado_visible(s.get('estado','no_verificable'))+'; transacción prevista no comprobada.')
        lineas.append('Plan de lectura: no se han descargado ni instalado paquetes.')
        return lineas
    if operacion=='diagnostico_mantenimiento_apt':
        hechos=p.get('hechos',{});archivos=hechos.get('nativo',{}).get('archivos')
        lineas=['Preparación APT: '+p.get('evaluacion','NO_VERIFICABLE')+'.']
        for clave,etiqueta in (('dpkg','dpkg'),('espacio','Espacio para mantenimiento'),('ejecutor','Helper'),('diario','Diario')):
            lineas.append(etiqueta+': '+estado_visible(hechos.get(clave,{}).get('estado','no_verificable'))+'.')
        if type(archivos) is list:
            verificados=sum(r.get('comprobacion',{}).get('estado')=='verificado' for r in archivos)
            lineas.append(f'Archivos .deb verificados: {verificados}/{len(archivos)}.')
        else:lineas.append('Archivos .deb: comprobación desconocida.')
        for motivo in p.get('impedimentos',[]):lineas.append('Impedimento: '+motivo)
        for motivo in p.get('no_comprobado',[]):lineas.append('No comprobado: '+motivo)
        lineas.append('La evaluación no autoriza descargas ni instalación.')
        return lineas
    if operacion=='auditoria_seguridad':
        if 'inventario_dpkg' in p:
            estado=p.get('estado_inventario','no_verificable')
            lineas=['Inventario dpkg: '+estado_visible(estado)+'.']
            lineas.append('Correlación CVE Debian no implementada; seguridad global no evaluada.')
        else:
            recuentos=p.get('recuentos',{})
            total=recuentos.get('avisos_pendientes')
            lineas=['Avisos Fedora pendientes: '+(str(total) if type(total) is int and total>=0 else 'desconocidos')+'.',
                    'Un aviso no demuestra vulnerabilidad efectiva.']
        return lineas
    if operacion=='correlacion_seguridad':
        return ['Correlación local: '+estado_visible(p.get('detalle_dnf5','no_verificable'))+'.',
                'KEV: '+estado_visible(p.get('cisa_kev',{}).get('estado','no_consultado'))+'.',
                'La correlación no acredita explotabilidad del paquete.']
    return ['Sin datos de presentación para esta operación.']


def informe(traza):
    from auditoria_basica import BASE
    registros=validar_traza(traza);cierre=registros[-1]
    evidencias={r['id']:r for r in registros if r['tipo']=='evidencia'}
    hallazgos=[r for r in registros if r['tipo']=='hallazgo']
    actuaciones=[r for r in registros if r['tipo']=='actuacion']
    comprobadas=sum(f['estado']=='comprobada' for f in cierre['cobertura'].values())
    excluidas=sum(f['estado']=='excluida' for f in cierre['cobertura'].values())
    conteos=Counter(r['prioridad'] for r in hallazgos)
    lineas=['Auditoría básica autónoma: '+ESTADOS[cierre['estado']],
            f"Áreas comprobadas: {comprobadas}/7; excluidas: {excluidas}.",
            f"Hallazgos: {conteos['P1']} P1 (impedimentos), {conteos['P2']} P2 (revisión), {conteos['P3']} P3 (mantenimiento/cobertura); {conteos['informativa']} observaciones informativas.",
            f"Pendientes: {len(cierre['pendientes'])} anotaciones; ninguna autoriza operaciones.",
            'Política local: sin red, privilegios ni cambios de paquetes.',
            'Motivo de parada: '+estado_visible(cierre['motivo_parada'])+'.', '', 'RESULTADOS']
    mostradas=set();limitaciones=[]
    for area,fila in cierre['cobertura'].items():
        lineas.append(ETIQUETAS[area]+': '+estado_visible(fila['estado'])+'.')
        for eid in fila['evidencias']:
            e=evidencias[eid]
            # Una referencia a adquisición fallida de otra área no es un resultado propio.
            if e['operacion_id']!=BASE[area] or eid in mostradas:continue
            mostradas.add(eid)
            lineas+=['  '+t for t in detalles(e['operacion_id'],e['datos']['resultado'],e['estado'])]
        if not fila['evidencias'] or not any(evidencias[e]['operacion_id']==BASE[area] for e in fila['evidencias']):
            lineas.append('  Comprobación no realizada o sin datos propios: '+estado_visible(fila['motivo'])+'.')
    for e in evidencias.values():
        if e['id'] not in mostradas and e['operacion_id'] in ('diagnostico_mantenimiento_apt','correlacion_seguridad'):
            lineas.append('Ampliación '+e['operacion_id']+' ('+estado_visible(e['estado'])+'):')
            lineas+=['  '+t for t in detalles(e['operacion_id'],e['datos']['resultado'],e['estado'])]
        limitaciones+=e['limitaciones']
        p=e['datos']['resultado']
        if e['estado'] in ('completo','parcial'):
            limitaciones+=p.get('limitaciones',[])+p.get('avisos',[])
            for clave in ('candidatas','simulacion'):
                for error in p.get(clave,{}).get('errores',[]):limitaciones.append(clave+': '+error)
    lineas+=['','HALLAZGOS Y REFERENCIAS']
    grupos=defaultdict(list)
    for r in hallazgos:grupos[(r['prioridad'],r['regla_id'],r['conclusion_python'])].append(r)
    for (prioridad,regla,conclusion),filas in sorted(grupos.items()):
        refs=[ref['evidencia_id']+ref['campo'] for fila in filas for ref in fila['evidencias']]
        etiqueta=f' ({len(filas)} observaciones agrupadas)' if len(filas)>1 else ''
        lineas.append(prioridad+' | '+conclusion+etiqueta)
        refs=list(dict.fromkeys(refs))
        if prioridad=='informativa':
            lineas.append(f'  Referencias: {len(refs)} evidencias; identificadores completos en JSON.')
        else:lineas.append('  Referencias: '+', '.join(refs))
    if not hallazgos:lineas.append('Sin hallazgos registrados; no equivale a ausencia de problemas.')
    lineas+=['','COMPROBACIONES Y PENDIENTES']
    for r in actuaciones:
        lineas.append('Comprobación realizada: '+r['operacion_id']+' — '+estado_visible(r['estado']))
        if r['error_codigo']:lineas.append('  Error: '+r['error_codigo'])
    if not actuaciones:lineas.append('No se ejecutaron comprobaciones.')
    lineas+=['Pendiente: '+p for p in cierre['pendientes']]
    if not cierre['pendientes']:lineas.append('Sin operaciones pendientes registradas; no implica autorización para actuar.')
    lineas+=['','LIMITACIONES Y DATOS DESCONOCIDOS']
    lineas+=list(dict.fromkeys(limitaciones))[:20]
    if len(set(limitaciones))>20:lineas.append('Limitaciones adicionales en la traza JSON.')
    lineas.append('Instantáneas locales: frescura de índices, CVE e impacto no acreditados globalmente. Detalle y referencias completos en JSON.')
    texto='\n'.join(lineas)
    if len(texto)>18000:
        texto=texto[:17900]+'\n[Informe abreviado; limitaciones y referencias completas en la traza JSON.]'
    return texto
