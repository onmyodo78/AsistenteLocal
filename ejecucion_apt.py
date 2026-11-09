"""Coordinación privilegiada de una operación exacta; dependencias inyectables en tests."""
import time
from autorizacion_apt import validar_peticion, VIGENCIA
from contratos_mantenimiento import serializar


def ejecutar(p,uid,nativo,registro,confirmar,*,estrategia=None):
    validar_solicitud=validar_peticion if estrategia is None else estrategia.validar_peticion
    revalidar=revalidar_plan if estrategia is None else estrategia.revalidar_plan
    validar_solicitud(p,uid)
    if not confirmar(p):
        return dict(version=1,id=p['id'],estado='cancelado',error='confirmacion_rechazada')
    inicio=time.monotonic()
    iniciado=False
    instalando=False
    estado='cancelado'
    error=None
    detalles={}
    try:
        registro.iniciar(p)  # Debe ser duradero antes de tocar APT.
        iniciado=True
        with nativo.bloqueo():
            registro.fase(p['id'],'revalidando')
            nativo.comprobar_sistema()
            revalidar(p['plan'],nativo)
            nativo.preparar_archivos()  # Sin descargas; valida confianza y hashes.
            validar_solicitud(p,uid)
            if time.monotonic()-inicio > VIGENCIA:raise ValueError('autorizacion_caducada')
            registro.fase(p['id'],'preparada',dict(huella=p['plan']['huella']))
            registro.fase(p['id'],'ejecutando')
            instalando=True
            correcto, progreso=nativo.instalar()
            if estrategia is not None:detalles={'progreso':progreso}
            registro.fase(p['id'],'verificando',progreso)
            verificado=nativo.verificar(p['plan'])
            detalles=dict(instalador_correcto=correcto,verificacion=verificado,progreso=progreso)
            estado='completo' if correcto and verificado else 'incompleto'
            error=None if estado=='completo' else 'transaccion_incompleta'
            if estrategia is not None:
                estado,error,detalles=estrategia.resultado(correcto,verificado,progreso,nativo)
    except BaseException as exc:
        # Tras empezar, el resultado requiere revisión; nunca se reintenta.
        estado='resultado_desconocido' if instalando else 'cancelado'
        if instalando and estrategia is None:
            salida=getattr(nativo,'ultima_salida','')
            if type(salida) is str:detalles['salida_nativa_no_interpretada']=salida[-65536:]
        permitidos={
            'plan_modificado','candidatas_modificadas','alcance_no_admitido','autorizacion_caducada',
            'dpkg_incompleto','paquetes_no_cacheados','archivos_no_verificados',
            'transaccion_nativa_diferente','paquete_retenido','version_no_superior',
            'autorizacion_consumida','operacion_pendiente_revision','configuracion_no_admitida'}
        if estrategia is not None:permitidos.update(estrategia.ERRORES)
        if isinstance(exc,ValueError) and str(exc) in permitidos:
            error=str(exc)
        elif isinstance(exc,BlockingIOError):error='gestor_bloqueado'
        elif isinstance(exc,KeyboardInterrupt):error='operacion_interrumpida'
        else:error='ejecucion_fallida'
    if iniciado:
        try:registro.finalizar(p['id'],estado,error,detalles)
        except Exception:
            estado='resultado_desconocido' if instalando else 'cancelado'
            error='registro_final_no_confirmado'
    return dict(version=1,id=p['id'],estado=estado,error=error,resultado=detalles)


def revalidar_plan(plan,nativo):
    nuevo=nativo.simular()
    if serializar(nuevo['simulacion'])!=serializar(plan['simulacion']):raise ValueError('plan_modificado')
    if serializar(sorted(nuevo['candidatas'],key=serializar))!=serializar(plan['candidatas']['paquetes']):
        raise ValueError('candidatas_modificadas')
    nativo.marcar_y_comprobar(plan)


def descargar(p,uid,nativo,registro,confirmar):
    """Autorización de red y caché; nunca llama al instalador ni cambia dpkg."""
    from autorizacion_apt import OPERACION_DESCARGA
    from archivos_apt import manifiesto
    validar_peticion(p,uid,operacion=OPERACION_DESCARGA)
    if not confirmar(p):return dict(version=1,id=p['id'],estado='cancelado',error='confirmacion_rechazada')
    iniciado=False;descargando=False;detalles={};estado='cancelado';error=None
    try:
        registro.iniciar(p);iniciado=True
        with nativo.bloqueo():
            registro.fase(p['id'],'revalidando_descarga',dict(operacion='descarga',archivos_autorizados=p['archivos']))
            nativo.comprobar_sistema()
            revalidar_plan(p['plan'],nativo)
            if serializar(manifiesto(nativo.versiones))!=serializar(p['archivos']):
                raise ValueError('manifiesto_modificado')
            validar_peticion(p,uid,operacion=OPERACION_DESCARGA)
            registro.fase(p['id'],'descargando')
            descargando=True
            detalles=nativo.descargar(p['archivos'])
            estado='completo'
    except BaseException as exc:
        estado='resultado_desconocido' if descargando else 'cancelado'
        if descargando:
            salida=getattr(nativo,'ultima_salida','')
            if type(salida) is str:detalles['salida_nativa_no_interpretada']=salida[-65536:]
        permitidos={'plan_modificado','candidatas_modificadas','manifiesto_modificado','autorizacion_caducada',
                    'dpkg_incompleto','espacio_insuficiente','archivos_no_verificados','descarga_incompleta',
                    'transaccion_nativa_diferente','autorizacion_consumida','operacion_pendiente_revision'}
        error=str(exc) if isinstance(exc,ValueError) and str(exc) in permitidos else ('gestor_bloqueado' if isinstance(exc,BlockingIOError) else 'descarga_no_confirmada')
    if iniciado:
        try:registro.finalizar(p['id'],estado,error,detalles)
        except Exception:estado='resultado_desconocido';error='registro_final_no_confirmado'
    return dict(version=1,id=p['id'],operacion='descarga',estado=estado,error=error,
                instalacion_realizada=False,resultado=detalles)
