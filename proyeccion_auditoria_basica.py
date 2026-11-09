"""Proyección explicativa pura: selecciona hechos de autonomia_v1, sin autoridad."""
from collections import Counter
from contratos_autonomia import validar_traza, exigir
from contratos_mantenimiento import serializar


def proyectar(traza, limite=18000):
    exigir(type(limite) is int and 0<limite<=18000)
    registros=validar_traza(traza);cierre=registros[-1]
    abreviada=False
    def breve(texto,maximo=240):
        nonlocal abreviada
        if len(texto)>maximo:
            abreviada=True
            return texto[:maximo]+' [abreviado]'
        return texto
    prioridades=Counter(r['prioridad'] for r in registros if r['tipo']=='hallazgo')
    salida=dict(version=1,tipo='proyeccion_explicativa_auditoria_basica',
        objetivo_id=registros[0]['id'],estado=cierre['estado'],motivo_parada=cierre['motivo_parada'],
        distribucion={k:registros[0]['distribucion'][k] for k in ('id','version_id','estado')},
        cobertura={k:dict(estado=v['estado'],motivo=breve(v['motivo']),evidencias=list(v['evidencias'])) for k,v in cierre['cobertura'].items()},
        prioridades={p:prioridades[p] for p in ('P1','P2','P3','informativa')},
        hallazgos=[],hechos=[],actuaciones=[],pendientes=[],desconocidos=[],limitaciones=[],
        autoriza_actuaciones=False,abreviada=False,
        omisiones=dict(hallazgos=0,hechos=0,actuaciones=0,pendientes=0,desconocidos=0,limitaciones=0))
    limites=[]
    for r in registros:
        if r['tipo']=='hallazgo':
            salida['hallazgos'].append(dict(id=r['id'],regla_id=r['regla_id'],prioridad=r['prioridad'],
                verificabilidad=r['verificabilidad'],conclusion_python=breve(r['conclusion_python']),
                referencias=[dict(evidencia_id=x['evidencia_id'],campo=x['campo']) for x in r['evidencias']],
                siguiente_paso=r['siguiente_paso']))
            limites+=r['limitaciones']
        elif r['tipo']=='actuacion':
            salida['actuaciones'].append({k:r[k] for k in ('operacion_id','estado','error_codigo','evidencias_generadas','efectos')})
        elif r['tipo']=='evidencia':
            p=r['datos']['resultado'];op=r['operacion_id']
            hecho=dict(evidencia_id=r['id'],operacion_id=op,estado=r['estado'])
            if r['estado'] not in ('completo','parcial'):
                salida['desconocidos'].append(dict(evidencia_id=r['id'],operacion_id=op,motivo=r['estado']))
            else:
                if op=='memoria':
                    hecho.update(ram={k:p.get('ram',{}).get(k) for k in ('total_bytes','disponible_estimada_bytes')},
                                 swap={k:p.get('swap',{}).get(k) for k in ('total_bytes','ocupada_bytes')},
                                 actividad_intercambio='no_medida')
                elif op=='disco':
                    hecho['montajes']=[{k:m.get(k) for k in ('ruta','disponible_bytes','total_bytes')}
                                       for m in p.get('montajes',[]) if m.get('ruta') in ('/','/usr','/var','/tmp')]
                elif op=='servicios_fallidos':
                    hecho['total_unidades']=p.get('datos',{}).get('total_unidades')
                elif op=='interfaces_red':
                    hecho['interfaces_enumeradas_ip']=p.get('alcance',{}).get('interfaces_enumeradas_ip')
                    hecho['conectividad']='no_comprobada'
                elif op=='plan_mantenimiento':
                    s=p.get('simulacion',{});c=p.get('candidatas',{})
                    hecho.update(candidatas_estado=c.get('estado'),simulacion_estado=s.get('estado'),
                        candidatas_total=len(c.get('paquetes',[])) if c.get('estado')=='completo' else None,
                        retenciones_estado=s.get('retenciones_estado'))
                    for nombre in ('actualizaciones','instalaciones','eliminaciones','retenciones'):
                        hecho[nombre+'_total']=len(s.get(nombre,[])) if s.get('estado')=='completo' and (nombre!='retenciones' or s.get('retenciones_estado')=='completo') else None
                elif op=='auditoria_seguridad':
                    hecho.update(inventario_completo=p.get('inventario_completo'),
                        total_instalados=p.get('total_instalados'),
                        avisos_pendientes_total=p.get('recuentos',{}).get('avisos_pendientes'),
                        estado_seguridad=p.get('estado_seguridad'))
                elif op=='diagnostico_mantenimiento_apt':
                    hecho['evaluacion']=p.get('evaluacion')
                    hecho['comprobaciones']={k:p.get('hechos',{}).get(k,{}).get('estado')
                                            for k in ('dpkg','nativo','espacio','ejecutor','diario','concurrencia')}
                    hecho['impedimentos']=[breve(x) for x in p.get('impedimentos',[])]
                    for x in p.get('no_comprobado',[]):
                        salida['desconocidos'].append(dict(evidencia_id=r['id'],motivo=breve(x)))
                elif op=='correlacion_seguridad':
                    hecho.update(detalle=p.get('detalle_dnf5'),total_resultados=p.get('total_resultados'))
                limites+=p.get('limitaciones',[])
            salida['hechos'].append(hecho)
            limites+=r['limitaciones']
    salida['pendientes']=[breve(x) for x in cierre['pendientes']]
    salida['limitaciones']=[breve(x) for x in dict.fromkeys(limites)]
    salida['limitaciones'].append('Proyección de hechos seleccionados; no contiene inventarios ni la totalidad de los datos. Un dato ausente o null no significa cero ni ausencia de problemas.')
    salida['abreviada']=abreviada
    # Mantener JSON íntegro y contadores explícitos, no cortar la serialización.
    while len(serializar(salida))>limite:
        for campo in ('hechos','hallazgos','limitaciones','pendientes','desconocidos','actuaciones'):
            if salida[campo]:
                salida[campo].pop();salida['omisiones'][campo]+=1;salida['abreviada']=True
                break
        else:raise ValueError('proyeccion_no_cabe_en_presupuesto')
    return salida
