"""Coordinador determinista local, acotado y sin autoridad administrativa."""
import copy
import hashlib
import math
import re
import time
import unicodedata
import uuid
from contratos_mantenimiento import serializar
from contratos_autonomia import (
    AREAS, OPERACIONES, LIMITES, POLITICA, ESTADOS, utc, exigir, validar,
    validar_traza,
)
from distribucion_linux import detectar_distribucion
from autonomia_herramientas import HerramientasLocales

BASE = dict(zip(AREAS,OPERACIONES[:7]))


def es_objetivo_basico(texto):
    texto=''.join(c for c in unicodedata.normalize('NFD',texto.lower()) if unicodedata.category(c)!='Mn')
    # Reconocer la adquisición y sus modificadores de presentación, sin convertir
    # preguntas conceptuales, referencias al pasado o auditorías de seguridad en
    # una auditoría básica nueva. No aceptar sufijos administrativos ni exclusiones.
    objetivo = r'(?:(?:realiza|haz|ejecuta)\s+(?:una\s+)?)?auditoria basica(?: completa)?(?: del sistema)?'
    explicacion = (
        r'(?:\s*(?:y|[,;:])\s*(?:explica(?:me)?|resume|presenta|muestra|detalla)\s+'
        r'(?:los\s+)?(?:problemas|hallazgos|resultados)(?:\s+encontrados)?'
        r'(?:\s*,?\s*(?:ordenados\s+por\s+prioridad|por\s+prioridad))?)?'
    )
    return bool(re.fullmatch(r'\s*'+objetivo+explicacion+r'[.!]?\s*',texto))


def referencias(e, campo=''):
    return [dict(evidencia_id=e['id'],campo=campo)]


class RegistroAgotado(ValueError):
    pass


class Coordinador:
    def __init__(self, *, herramientas=None, detectar=detectar_distribucion,
                 reloj=time.monotonic, cancelado=lambda:False, deadline=None):
        self.herramientas=herramientas if herramientas is not None else HerramientasLocales()
        exigir(deadline is None or type(deadline) in (int,float) and math.isfinite(deadline))
        self.deadline=deadline
        self.detectar=detectar;self.reloj=reloj;self.cancelado=cancelado
        self._usado=False;self.cerrado=False

    def presupuesto(self):
        return dict(llamadas=self.llamadas,rondas=(self.llamadas+3)//4,
                    salida=self.salida,restante_ms=max(0,min(120000,int((self.fin-self.reloj())*1000))))

    def nuevo(self,tipo,**datos):
        r=dict(version=1,tipo=tipo,**datos)
        if tipo!='cierre':r['id']=uuid.uuid4().hex
        if tipo!='objetivo_auditoria':r['objetivo_id']=self.objetivo['id']
        return r

    def agregar(self,r):
        validar(r,self.evidencias)
        if len(serializar(self.registros+[r]).encode())>4*1024*1024-65536-(8192 if r['tipo']=='evidencia' else 0):
            raise RegistroAgotado('registro_agotado')
        self.registros.append(copy.deepcopy(r))
        if r['tipo']=='evidencia':self.evidencias[r['id']]=copy.deepcopy(r)
        return r

    def parada(self):
        if self.cancelado():return 'cancelacion_usuario'
        if self.reloj()>=self.fin:return 'tiempo_agotado'
        if self.llamadas>=8:return 'llamadas_agotadas'
        if self.salida>=60000:return 'salida_agotada'
        return None

    def capacidad(self,op):
        try:
            estado,fuentes,motivo=self.herramientas.capacidad(op,self.objetivo['distribucion'])
        except (OSError,ValueError,TypeError,KeyError):
            estado,fuentes,motivo='no_verificable',[],'sondeo_fallido'
        r=self.nuevo('capacidad',operacion_id=op,estado=estado,fuentes=fuentes,
                     motivo=motivo,observado_utc=utc())
        self.agregar(r)
        return estado=='disponible'

    def decision(self,op,regla,refs,permitida,motivo):
        antes=self.presupuesto();self.llamadas+=1
        r=self.nuevo('decision',secuencia=1+sum(x['tipo']=='decision' for x in self.registros),
            creado_utc=utc(),proponente='python',operacion_id=op,argumentos_validados={},
            evidencias=refs,regla_id=regla,politica_id=POLITICA,
            resultado='permitida' if permitida else 'denegada',motivo=motivo,
            ganancia_esperada='Adquirir evidencia local nueva en el alcance autorizado.' if permitida else 'Ninguna: operación rechazada.',
            presupuesto_antes=antes,presupuesto_despues=self.presupuesto())
        return self.agregar(r)

    def adquirir(self,op,regla,refs):
        # Las propuestas externas no añaden operaciones al catálogo ni permisos.
        if self.cerrado or self.parada():return None
        basica=(regla=='BASE-01' and any(operacion==op and area in self.objetivo['alcance'] for area,operacion in BASE.items()))
        ampliacion=any(op==c_op and regla==c_regla and refs==c_refs for c_op,c_regla,c_refs in self.candidatos())
        if op not in OPERACIONES or op in self.intentadas or not (basica or ampliacion):
            # No incorporar referencias arbitrarias del proponente a la traza.
            self.decision(op,regla,[],False,'operacion_no_permitida_o_repetida')
            return None
        self.intentadas.add(op)
        d=self.decision(op,regla,refs,True,'politica_local_y_evidencias_validas')
        inicio=self.reloj();error=None
        try:
            valor=self.herramientas.ejecutar(op,self.fin,copy.deepcopy(self.previos))
            exigir(type(valor) is dict and set(valor)=={'estado','resultado','subconsultas'})
            exigir(valor['estado'] in ESTADOS and type(valor['resultado']) is dict and type(valor['subconsultas']) is list)
            for sub in valor['subconsultas']:
                exigir(type(sub) is dict and set(sub)=={'operacion','estado','duracion_ms'})
                exigir(type(sub['operacion']) is str and type(sub['estado']) is str and type(sub['duracion_ms']) is int and sub['duracion_ms']>=0)
            # Validar payload antes de darle categoría de evidencia.
            from contratos_autonomia import json_seguro
            json_seguro(valor)
            if op=='plan_mantenimiento' and valor['estado']=='completo':
                from contratos_mantenimiento import validar as validar_plan
                validar_plan(valor['resultado'])
            if self.reloj()>=self.fin:raise TimeoutError('plazo_agotado')
        except KeyboardInterrupt:
            self.interrumpida=True;error='cancelacion_usuario'
            valor=dict(estado='error',resultado=dict(error=error),subconsultas=[])
        except (OSError,ValueError,TypeError,KeyError,RuntimeError) as exc:
            error='tiempo_agotado' if isinstance(exc,TimeoutError) else 'adquisicion_fallida'
            valor=dict(estado='error',resultado=dict(error=error),subconsultas=[])
        duracion=max(0,int((self.reloj()-inicio)*1000))
        e=self.nuevo('evidencia',operacion_id=op,subconsulta_id=None,adquirido_utc=utc(),
            duracion_ms=duracion,estado=valor['estado'],contrato_origen='observacion_autonomia_v1',version_origen=1,
            datos=valor,sha256_payload=hashlib.sha256(serializar(valor).encode()).hexdigest(),
            limitaciones=['Observación local no transaccional; no garantiza ausencia de vulnerabilidades.'],
            truncado=False,procedencia='cache_local' if op in ('auditoria_seguridad','plan_mantenimiento','correlacion_seguridad') else 'local')
        try:self.agregar(e)
        except RegistroAgotado:
            self.motivo='registro_agotado'
            e=None
        if e is not None:
            self.por_operacion[op]=e
            if e['estado'] in ('completo','parcial'):self.previos[op]=copy.deepcopy(valor['resultado'])
        a=self.nuevo('actuacion',decision_id=d['id'],operacion_id=op,inicio_utc=d['creado_utc'],
            duracion_ms=duracion,estado=valor['estado'] if e else 'no_verificable',
            evidencias_generadas=[e['id']] if e else [],error_codigo=error or ('registro_agotado' if not e else None),
            efectos='lectura_local',reintentada=False)
        self.agregar(a)
        # Proyección cerrada y pequeña; no truncar contratos ni enviar inventarios.
        resumen=serializar(dict(operacion=op,estado=a['estado'],evidencia=e['id'] if e else None))
        if len(resumen)>18000 or self.salida+len(resumen)>60000:self.motivo='salida_agotada'
        else:self.salida+=len(resumen)
        return e

    def hallazgo(self,e,regla,texto,campo='',siguiente=None):
        prioridad={'PRI-01':'P1','PRI-02':'P2','PRI-03':'P3','PRI-04':'P3','PRI-05':'informativa'}[regla]
        self.agregar(self.nuevo('hallazgo',regla_id=regla,prioridad=prioridad,
            verificabilidad='comprobada' if e['estado']=='completo' else 'no_verificable',
            evidencias=referencias(e,campo),conclusion_python=texto,
            limitaciones=copy.deepcopy(e['limitaciones']),siguiente_paso=siguiente))

    def evaluar(self,e):
        op=e['operacion_id'];p=e['datos']['resultado']
        if e['estado']!='completo':
            self.hallazgo(e,'PRI-04','Cobertura incompleta: no se confirma ausencia de incidencias.')
            return
        hay=False
        if op=='servicios_fallidos' and p.get('datos',{}).get('unidades'):
            self.hallazgo(e,'PRI-02','Unidades fallidas observadas; impacto pendiente de investigar.','/resultado/datos/unidades')
            self.pendientes.append('INV-SVC-01: herramienta específica de unidad no implementada.');hay=True
        if op=='disco':
            for i,m in enumerate(p.get('montajes',[])):
                if type(m.get('disponible_bytes')) is int and m['disponible_bytes']==0:
                    self.hallazgo(e,'PRI-02','Filesystem relevante sin espacio disponible.','/resultado/montajes/'+str(i));hay=True
        if op=='interfaces_red':
            for i,r in enumerate(p.get('interfaces',[])):
                if r.get('nombre')!='lo' and r.get('administrativo')=='UP' and r.get('operativo') in ('DOWN','LOWERLAYERDOWN','down','lowerlayerdown'):
                    self.pendientes.append('INV-RED-01: inspección específica de enlace/rutas no implementada.');hay=True
                    self.hallazgo(e,'PRI-04','Estado operativo requiere investigación local; conectividad no comprobada.','/resultado/interfaces/'+str(i))
        if op=='auditoria_seguridad' and self.objetivo['distribucion']['id']=='fedora':
            avisos=[a for a in p.get('avisos_pendientes',[]) or [] if a.get('id') and a.get('paquetes')]
            if avisos:
                self.hallazgo(e,'PRI-02','Avisos locales pendientes con paquetes identificados; vulnerabilidad efectiva no demostrada.','/resultado/avisos_pendientes');hay=True
        if op=='plan_mantenimiento' and p.get('simulacion',{}).get('estado')=='completo' and p['simulacion']['actualizaciones']:
            self.hallazgo(e,'PRI-03','Actualizaciones previstas por el resolvedor; no se autoriza ejecución.','/resultado/simulacion/actualizaciones');hay=True
        if op=='diagnostico_mantenimiento_apt':
            if p.get('impedimentos'):
                self.hallazgo(e,'PRI-01','Impedimentos comprobados: no continuar mantenimiento.','/resultado/impedimentos');hay=True
            if p.get('no_comprobado'):
                self.hallazgo(e,'PRI-04','Precondiciones no verificadas; no autoriza mantenimiento.','/resultado/no_comprobado');hay=True
        if not hay:self.hallazgo(e,'PRI-05','Consulta completada dentro del alcance medido; no certifica seguridad global.')

    def candidatos(self):
        candidatos=[]
        e=self.por_operacion.get('plan_mantenimiento')
        if e and e['estado']=='completo' and self.objetivo['distribucion']['id']=='debian':
            p=e['datos']['resultado'];s=p.get('simulacion',{})
            seguridad=self.por_operacion.get('auditoria_seguridad')
            if s.get('estado')=='completo' and s.get('actualizaciones') and not s.get('instalaciones') and not s.get('eliminaciones') and not (seguridad and seguridad['estado']!='completo'):
                candidatos.append(('diagnostico_mantenimiento_apt','INV-APT-01',referencias(e,'/resultado/simulacion')))
        e=self.por_operacion.get('auditoria_seguridad')
        if e and e['estado']=='completo' and self.objetivo['distribucion']['id']=='fedora' and any(
                a.get('id') and a.get('paquetes') for a in e['datos']['resultado'].get('avisos_pendientes',[]) or []):
            candidatos.append(('correlacion_seguridad','INV-FED-01',referencias(e,'/resultado/avisos_pendientes')))
        return candidatos

    def ejecutar(self,exclusiones=()):
        exigir(not self._usado);self._usado=True
        exigir(type(exclusiones) in (tuple,list) and all(type(a) is str and a in AREAS for a in exclusiones) and len(set(exclusiones))==len(exclusiones))
        self.fin=self.reloj()+120
        if self.deadline is not None:self.fin=min(self.fin,self.deadline)
        self.llamadas=0;self.salida=0;self.motivo=None;self.interrumpida=False
        self.registros=[];self.evidencias={};self.previos={};self.por_operacion={};self.intentadas=set();self.pendientes=[]
        self.objetivo=dict(version=1,tipo='objetivo_auditoria',id=uuid.uuid4().hex,creado_utc=utc(),
            alcance=[a for a in AREAS if a not in exclusiones],exclusiones=list(exclusiones),distribucion=self.detectar(),
            politica_id=POLITICA,politica_version=1,permisos=dict(nivel1_local=True,nivel2_local=True,externo=False),
            limites=dict(LIMITES),estado='activo',motivo_parada=None)
        self.agregar(self.objetivo)
        cobertura={a:dict(estado='excluida' if a in exclusiones else 'pendiente_por_presupuesto',evidencias=[],
                          motivo='exclusion_usuario' if a in exclusiones else 'no_adquirida') for a in AREAS}
        try:
            for area,op in BASE.items():
                if area in exclusiones:continue
                self.motivo=self.motivo or self.parada()
                if self.motivo or self.interrumpida:break
                previa=self.por_operacion.get('auditoria_seguridad')
                if op=='plan_mantenimiento' and previa and previa['estado'] not in ('completo','parcial'):
                    cobertura[area]=dict(estado='parcial',evidencias=[previa['id']],motivo='adquisicion_previa_fallida_no_se_repite')
                    continue
                if not self.capacidad(op):
                    cobertura[area]=dict(estado='no_disponible',evidencias=[],motivo='capacidad_no_disponible')
                    continue
                e=self.adquirir(op,'BASE-01',[])
                if e:
                    cobertura[area]=dict(estado='comprobada' if e['estado']=='completo' else 'parcial',
                                        evidencias=[e['id']],motivo=e['estado'])
                    self.evaluar(e)
            if not self.interrumpida and not self.motivo:
                for op,regla,refs in self.candidatos():
                    self.motivo=self.motivo or self.parada()
                    if self.motivo:
                        self.pendientes.append(regla+': pendiente por presupuesto.');continue
                    if not self.capacidad(op):
                        self.pendientes.append(regla+': capacidad no disponible.');continue
                    e=self.adquirir(op,regla,refs)
                    if e:
                        self.evaluar(e)
                        if e['estado']!='completo':
                            area='mantenimiento' if op=='diagnostico_mantenimiento_apt' else 'seguridad'
                            cobertura[area]['estado']='parcial'
                            cobertura[area]['evidencias'].append(e['id'])
                            cobertura[area]['motivo']='ampliacion_no_completada'
        except RegistroAgotado:self.motivo='registro_agotado'
        except KeyboardInterrupt:self.interrumpida=True
        except (ValueError,TypeError,KeyError,RuntimeError):self.motivo='error_interno'
        if self.interrumpida or self.cancelado():self.motivo='cancelacion_usuario'
        elif self.reloj()>=self.fin:self.motivo=self.motivo or 'tiempo_agotado'
        if not self.motivo:
            self.motivo='cobertura_completada' if all(f['estado'] in ('comprobada','excluida') for f in cobertura.values()) else 'capacidad_insuficiente' if any(f['estado']=='no_disponible' for f in cobertura.values()) else 'evidencia_insuficiente'
        for area,fila in cobertura.items():
            if fila['estado'] not in ('comprobada','excluida'):
                self.pendientes.append(area+': '+fila['motivo'])
        if self.objetivo['distribucion']['id']=='debian' and 'seguridad' not in exclusiones:
            self.pendientes.append('Correlación CVE Debian no implementada; seguridad no evaluada globalmente.')
        estado='error' if self.motivo=='error_interno' else 'cancelado' if self.motivo=='cancelacion_usuario' else 'completo' if self.motivo=='cobertura_completada' else 'parcial'
        self.registros[0].update(estado=estado,motivo_parada=self.motivo)
        cierre=self.nuevo('cierre',terminado_utc=utc(),estado=estado,motivo_parada=self.motivo,
            cobertura=cobertura,hallazgos=[r['id'] for r in self.registros if r['tipo']=='hallazgo'],
            actuaciones=[r['id'] for r in self.registros if r['tipo']=='actuacion'],
            pendientes=list(dict.fromkeys(self.pendientes)),presupuesto_final=self.presupuesto())
        self.registros.append(cierre)
        resultado=validar_traza(self.registros)
        self.cerrado=True
        return resultado


def auditar(**opciones):
    exclusiones=opciones.pop('exclusiones',())
    return Coordinador(**opciones).ejecutar(exclusiones)


def informe(traza):
    """Presentación pura, separada del coordinador y de la traza factual."""
    from presentacion_auditoria_basica import informe as presentar
    return presentar(traza)
