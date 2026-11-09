"""Perfil interactivo Fedora: autoriza abrir DNF5, no un plan simulado exacto.

La transacción definitiva y su confirmación pertenecen al DNF5 conectado a TTY.
No importa ni relaja dnf5_preparacion. No se expone como herramienta del modelo.
"""
import os
import time
from autorizacion_apt import crear_sobre, validar_sobre, VIGENCIA, abrir_tty_confirmacion
from contratos_mantenimiento import validar, serializar
from distribucion_linux import detectar_distribucion

OPERACION='dnf5_actualizar_interactivo_v1'
POLITICA={'confirmacion_nativa':True,'comando_fijo':'upgrade','plugins':False,
          'descarga_permitida':True,'plan_previo_vinculante':False,'reinicio_automatico':False}
ERRORES={'fedora45_requerido','dnf5_no_disponible','terminal_requerida',
         'inventario_rpm_no_verificado','permisos_insuficientes'}


def exigir_fedora45(distro=None):
    d=detectar_distribucion() if distro is None else distro
    if d['estado']!='soportado' or d['id']!='fedora' or d['version_id']!='45':
        raise ValueError('fedora45_requerido')


def comprobar_consulta(plan):
    validar(plan)
    if plan['distribucion']!='fedora' or plan['gestor']!='dnf5' or plan['operacion']!='actualizaciones':
        raise ValueError('consulta_dnf5_requerida')
    # Se admite consulta parcial/error, identificándola como tal en el terminal.
    # Su lista nunca limita ni certifica la transacción que DNF5 presentará.
    return plan


def crear_peticion(consulta,uid):
    exigir_fedora45()
    return crear_sobre(comprobar_consulta(consulta),uid,OPERACION,POLITICA)


def validar_peticion(p,uid,ahora=None):
    validar_sobre(p,uid,OPERACION,POLITICA,ahora)
    comprobar_consulta(p['plan'])
    return p


def informe(consulta):
    comprobar_consulta(consulta)
    c=consulta['candidatas']
    filas=c['paquetes']
    lineas=['Consulta DNF5 en caché: '+c['estado']+'. Candidatas observadas: '+str(len(filas))+'.']
    if c['estado']!='completo':lineas.append('Lista incompleta o no verificada; no permite concluir ausencia de actualizaciones.')
    lineas.append('No es la transacción definitiva: dependencias, eliminaciones y frescura no acreditadas.')
    for p in filas:
        lineas.append(p['nombre']+':'+str(p['arquitectura'])+' '+str(p['anterior'])+' -> '+str(p['propuesta']))
    if c['errores']:lineas.append('Motivos: '+', '.join(c['errores']))
    return '\n'.join(lineas)


def frase(p):return 'ABRIR DNF5 INTERACTIVO '+p['digest']


def confirmar_tty(p):
    with abrir_tty_confirmacion() as tty:
        tty.write('\nSESIÓN ADMINISTRATIVA DNF5 — Fedora 45\n'+informe(p['plan'])+'\n'
            'La consulta anterior es informativa y NO congela la transacción.\n'
            'DNF5 resolverá y mostrará su transacción definitiva aquí; revísela y confirme en su propia pregunta.\n'
            'Puede descargar metadatos y paquetes, instalar dependencias, reemplazar paquetes y retirar kernels antiguos.\n'
            'Los paquetes pueden ejecutar scripts y reiniciar servicios; no se solicita reiniciar el equipo.\n'
            'Se registrarán código de salida y comprobaciones RPM; no se graba esta terminal.\n'
            'Para autorizar únicamente el inicio de esta sesión escriba:\n'+frase(p)+'\n> ')
        tty.flush()
        return tty.readline(200).strip()==frase(p)


def revalidar_plan(plan,nativo):
    comprobar_consulta(plan)
    # No comparar con una simulación estricta incompleta ni atribuirle autoridad.
    # El inventario real se adquiere antes de iniciar DNF5; sus propios bloqueos
    # y confirmación protegen la transacción nativa presentada al usuario.


def resultado(correcto,verificado,progreso,nativo):
    detalles={'progreso':progreso,'verificacion':nativo.verificacion,
              'confirmacion_definitiva':'gestionada_por_dnf5_no_capturada',
              'equivalencia_con_plan_previo':'no_afirmada'}
    if not verificado:return 'resultado_desconocido','comprobacion_posterior_no_verificada',detalles
    if progreso.get('error')=='permisos_insuficientes':return 'cancelado','permisos_insuficientes',detalles
    if correcto:return 'completo',None,detalles
    if progreso['codigo_dnf5'] in (130,-2) and nativo.verificacion['cambios_total']==0:
        return 'cancelado','operacion_interrumpida',detalles
    return ('incompleto' if nativo.verificacion['cambios_total'] else 'fallido'), 'dnf5_no_completo_o_cancelado',detalles


def actualizar(consulta):
    from cliente_ejecucion_apt import invocar
    return invocar('ejecutar',crear_peticion(consulta,os.getuid()),backend='dnf5')


def main_helper(args):
    """Solo desde el helper instalado y verificado, nunca desde el checkout."""
    import sys
    from autorizacion_apt import MAX_PETICION,leer_json
    from registro_mantenimiento import Registro,historial
    from dnf5_interactivo import Dnf5Interactivo,ENTORNO
    exigir_fedora45()
    uid=os.environ.get('SUDO_UID','')
    os.environ.clear();os.environ.update(ENTORNO)
    if args==['comprobar']:
        Dnf5Interactivo.comprobar_binarios()
        return dict(version=1,estado='preparado',ejecucion=False)
    if os.geteuid()!=0 or not uid.isdecimal() or int(uid)<=0:
        raise PermissionError('sudo_interactivo_requerido')
    uid=int(uid)
    if args==['historial']:return dict(version=1,estado='completo',operaciones=historial())
    if args!=['ejecutar']:raise ValueError('operacion_no_autorizada')
    contenido=sys.stdin.buffer.read(MAX_PETICION+1)
    if len(contenido)>MAX_PETICION:raise ValueError('peticion_demasiado_grande')
    p=leer_json(contenido);validar_peticion(p,uid)
    if not confirmar_tty(p):return dict(version=1,id=p['id'],estado='cancelado',error='confirmacion_rechazada')
    # La confirmación y sudo no conceden permiso para reintentar una operación.
    from ejecucion_apt import ejecutar
    with Registro() as registro:
        return ejecutar(p,uid,Dnf5Interactivo(),registro,lambda p:True,estrategia=sys.modules[__name__])
