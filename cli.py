#!/usr/bin/env python3
"""CLI independiente; consultas sin privilegios y ejecución APT con helper autorizado."""
import argparse
import json
import os
import sys
import unicodedata
from mantenimiento import consultar
from motor_auditoria import consultar as auditar
from informes_factuales import resumen_factual_debian, informe_correlacion_debian, informe_plan
from auditoria_seguridad import informe as informe_fedora
from contratos_mantenimiento import serializar


def sanear(texto):
    return ''.join(c if c in '\n\t' or not unicodedata.category(c).startswith('C')
                   else f'\\u{ord(c):04x}' for c in str(texto))


def main(argv=None):
    parser = argparse.ArgumentParser(description='AsistenteLocal sin LM Studio: auditoría y planificación local')
    parser.add_argument('--formato', choices=('texto','json'), default='texto')
    sub = parser.add_subparsers(dest='operacion', required=True)
    sub.add_parser('diagnostico-mantenimiento',help='Diagnóstico APT factual sin red ni modificaciones')
    sub.add_parser('plan-descarga-apt',help='Muestra paquetes, hashes, tamaños y orígenes; no descarga')
    sub.add_parser('descargar-apt',help='Descarga solo tras autorización explícita independiente de instalación')
    sub.add_parser('comprobar-ejecucion-apt', help='Comprueba el helper instalado; no ejecuta cambios')
    sub.add_parser('actualizar-apt', help='Actualiza solo con autorización explícita en terminal')
    sub.add_parser('historial-apt', help='Consulta el diario protegido mediante sudo')
    sub.add_parser('mantenimiento',help='Diagnóstico de mantenimiento según la distribución, sin privilegios')
    sub.add_parser('actualizar-dnf5',help='Abre DNF5 en terminal tras sudo y autorización explícita; DNF5 confirma su transacción')
    sub.add_parser('comprobar-ejecucion-dnf5',help='Comprueba el helper protegido DNF5; no instala ni actualiza')
    sub.add_parser('historial-dnf5',help='Consulta el diario protegido mediante sudo')
    basica=sub.add_parser('auditoria-basica',help='Auditoría autónoma local sin modelo ni cambios del sistema')
    basica.add_argument('--excluir',action='append',default=[],choices=('identidad','disco','memoria','servicios','red','seguridad','mantenimiento'))
    semanal=sub.add_parser('auditoria-semanal',help='Auditoría factual no interactiva con informes privados')
    semanal.add_argument('--directorio',required=True,help='Directorio privado de resultados')
    unidades=sub.add_parser('unidades-auditoria-semanal',help='Imprime plantillas systemd; no las instala ni activa')
    unidades.add_argument('--directorio',required=True,help='Ruta absoluta de resultados')
    sub.add_parser('capacidades')
    sub.add_parser('actualizaciones')
    sub.add_parser('plan', help='Simula una actualización completa; nunca ejecuta cambios')
    sub.add_parser('preparar-dnf5',help='Inspecciona acciones libdnf5 en aislamiento; no autoriza ejecución')
    auditoria = sub.add_parser('auditoria')
    auditoria.add_argument('--herramienta', choices=('auditoria_seguridad','correlacion_seguridad'), default='auditoria_seguridad')
    args = parser.parse_args(argv)
    if os.geteuid() == 0:
        print(json.dumps({'version':1,'estado':'error','error':'ejecucion_root_rechazada'}))
        return 1
    ejecucion_solicitada=False
    tipo_solicitud="actualizacion"
    historial_solicitado='historial-apt'
    try:
        if args.operacion in ('mantenimiento','actualizar-dnf5','comprobar-ejecucion-dnf5','historial-dnf5'):
            from distribucion_linux import detectar_distribucion
            from mantenimiento_dnf5 import exigir_fedora45,informe,actualizar
            distro=detectar_distribucion()
            if args.operacion=='mantenimiento' and distro['estado']=='soportado' and distro['id']=='debian' and distro['version_id']=='13':
                return main(['--formato',args.formato,'diagnostico-mantenimiento'])
            exigir_fedora45(distro)
            if args.operacion in ('mantenimiento','actualizar-dnf5'):
                consulta=consultar('actualizaciones')
                if args.operacion=='mantenimiento':
                    print(serializar(consulta) if args.formato=='json' else sanear(informe(consulta)))
                    return 0 if consulta['estado']=='completo' else 3
                print(sanear(informe(consulta)),file=sys.stderr)
                print('La transacción definitiva se mostrará y confirmará en DNF5, dentro del terminal administrativo.',file=sys.stderr)
                ejecucion_solicitada=True;tipo_solicitud='dnf5';historial_solicitado='historial-dnf5'
                r=actualizar(consulta)
            else:
                from cliente_ejecucion_apt import invocar
                r=invocar('comprobar' if args.operacion=='comprobar-ejecucion-dnf5' else 'historial',backend='dnf5')
            print(serializar(r))
            return 0 if r['estado'] in ('completo','preparado') else 1
        if args.operacion=='preparar-dnf5':
            import time
            from distribucion_linux import detectar_distribucion
            from adaptadores.fedora import Fedora
            from dnf5_preparacion import resultado as no_verificable
            distro=detectar_distribucion()
            d=(Fedora().preparar(time.monotonic()+120) if distro['estado']=='soportado' and distro['id']=='fedora'
               else no_verificable('dnf5_no_disponible'))
            print(serializar(d) if args.formato=='json' else sanear(
                'Preparación DNF5: '+d['estado']+'\nAcciones: '+d['acciones_estado']+
                '\nEjecución bloqueada. Pendientes: '+', '.join(d['pendientes'])+
                '\nErrores: '+', '.join(d['errores'])+'\n'+serializar(d)))
            return 3
        if args.operacion in ('auditoria-semanal','unidades-auditoria-semanal'):
            from auditoria_semanal import ejecutar,unidades
            resultado=ejecutar(args.directorio) if args.operacion=='auditoria-semanal' else unidades(args.directorio)
            print(serializar(resultado) if args.formato=='json' else sanear('\n'.join(k+'\n'+v for k,v in resultado.items()) if args.operacion=='unidades-auditoria-semanal' else str(resultado)))
            return 0 if args.operacion=='unidades-auditoria-semanal' or resultado['estado']=='completo' else 3
        if args.operacion=='auditoria-basica':
            from auditoria_basica import auditar as auditar_basica,informe
            traza=auditar_basica(exclusiones=args.excluir)
            print(serializar(traza) if args.formato=='json' else sanear(informe(traza)))
            return 0 if traza[-1]['estado']=='completo' else 130 if traza[-1]['estado']=='cancelado' else 3
        if args.operacion in ('diagnostico-mantenimiento','plan-descarga-apt','descargar-apt'):
            from diagnostico_mantenimiento import diagnosticar,informe,plan_descarga
            diagnostico=diagnosticar()
            if args.operacion=='diagnostico-mantenimiento':
                print(serializar(diagnostico) if args.formato=='json' else sanear(informe(diagnostico)))
                return 1 if diagnostico['evaluacion'] in ('BLOQUEADO','NO_VERIFICABLE') else 0
            if not diagnostico['preparacion_permitida']:
                print(serializar(diagnostico) if args.formato=='json' else sanear(informe(diagnostico)))
                return 1
            propuesta=plan_descarga(diagnostico)
            if args.operacion=='plan-descarga-apt':
                print(serializar(propuesta) if args.formato=='json' else sanear(informe(diagnostico)))
                return 0
            print(sanear(informe(diagnostico)),file=sys.stderr)
            from cliente_ejecucion_apt import descargar
            tipo_solicitud='descarga';ejecucion_solicitada=True
            resultado=descargar(propuesta['plan'],propuesta['archivos'])
            print(serializar(resultado) if args.formato=='json' else sanear('Descarga APT: '+resultado['estado']+'. Instalación no realizada. Error: '+str(resultado.get('error') or 'ninguno')))
            return 0 if resultado['estado']=='completo' else 1
        if args.operacion in ('comprobar-ejecucion-apt','actualizar-apt','historial-apt'):
            from cliente_ejecucion_apt import invocar,actualizar
            if args.operacion=='actualizar-apt':
                from autorizacion_apt import comprobar_plan
                plan=consultar('plan')
                comprobar_plan(plan)
                print(sanear(informe_plan(plan)),file=sys.stderr)
                print('Se solicitará autenticación administrativa y confirmación del plan exacto en el terminal.',file=sys.stderr)
                ejecucion_solicitada=True
                resultado=actualizar(plan)
            else:
                resultado=invocar('comprobar' if args.operacion=='comprobar-ejecucion-apt' else 'historial')
            print(serializar(resultado))
            return 0 if resultado['estado'] in ('completo','preparado') else 1
        if args.operacion == 'auditoria':
            d = auditar(args.herramienta)
            if args.formato == 'json':
                print(serializar(d))
            else:
                if d.get('backend') == 'debian' and args.herramienta == 'auditoria_seguridad':
                    texto = resumen_factual_debian(d)
                elif d.get('estado') in ('no_implementado','no_soportado'):
                    texto = informe_correlacion_debian(json.dumps(d)) if args.herramienta == 'correlacion_seguridad' else 'Comprobación no realizada: distribución no soportada.'
                elif args.herramienta == 'auditoria_seguridad':
                    texto = informe_fedora(d)
                else:
                    texto = serializar(d)
                print(sanear(texto))
            estado = d.get('estado_adquisicion', 'completo' if d.get('inventario_completo') and d.get('detalle_dnf5') == 'correcto' else 'parcial')
            return 0 if estado == 'completo' else 3 if estado == 'parcial' else 1
        d = consultar(args.operacion)
        print(serializar(d) if args.formato == 'json' else sanear(informe_plan(d)))
        return 0 if d['estado'] == 'completo' else 3 if d['estado'] == 'parcial' else 1
    except KeyboardInterrupt:
        print('Comunicación interrumpida; consultar '+historial_solicitado+' antes de reintentar.' if ejecucion_solicitada
              else 'Operación interrumpida; no se reintenta.', file=sys.stderr)
        return 130
    except (OSError, ValueError, TypeError, KeyError, TimeoutError):
        if ejecucion_solicitada:
            print(serializar(dict(version=1,estado='resultado_desconocido',error=tipo_solicitud+'_no_confirmada')))
            return 1
        print(json.dumps({'version':1,'estado':'error','error':'operacion_fallida'}) if args.formato == 'json'
              else 'Operación fallida; no se reintenta ni se modifican paquetes.')
        return 1


if __name__ == '__main__':
    sys.exit(main())
