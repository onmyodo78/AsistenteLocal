#!/usr/bin/python3
"""Entrada protegida: solo cargar módulos locales después de verificar instalación.

El cliente invoca este archivo instalado, nunca el checkout editable, mediante
sudo normal. No se necesita una regla NOPASSWD ni un servicio administrativo.
"""
# Comprobar antes de importar incluso json/pathlib: -I elimina PYTHONPATH y el
# directorio del script; -S impide ejecutar .pth/sitecustomize al arrancar.
import sys
if __name__=='__main__' and not (sys.flags.isolated and sys.flags.no_site):
    sys.stdout.write('{"version":1,"estado":"cancelado","error":"python_no_aislado"}\n')
    sys.exit(1)
# Tampoco escribir cachés si un administrador omite -B en una invocación manual.
sys.dont_write_bytecode=True
import json
import os
from pathlib import Path
import stat
import sqlite3

INSTALACION=Path('/usr/local/lib/asistentelocal')
ARCHIVOS=('ejecutor_apt.py','ejecucion_apt.py','apt_ejecucion_nativa.py',
          'autorizacion_apt.py','registro_mantenimiento.py','contratos_mantenimiento.py',
          'apt_simulacion.py','distribucion_linux.py','archivos_apt.py')
INSTALACION_DNF5=Path('/usr/local/lib/asistentelocal-dnf5')
ARCHIVOS_DNF5=('ejecutor_apt.py','ejecucion_apt.py','mantenimiento_dnf5.py','dnf5_interactivo.py',
              'autorizacion_apt.py','registro_mantenimiento.py','contratos_mantenimiento.py','distribucion_linux.py')


def preparar_imports():
    if not (sys.flags.isolated and sys.flags.no_site):
        raise PermissionError('python_no_aislado')
    # Solo biblioteca estándar del intérprete de Debian y python3-apt del sistema.
    # No procesar site, .pth ni rutas heredadas del usuario.
    biblioteca=Path('/usr/lib')/('python'+str(sys.version_info.major)+'.'+str(sys.version_info.minor))
    rutas=[biblioteca,biblioteca/'lib-dynload',Path('/usr/lib/python3/dist-packages')]
    for ruta in rutas:
        for d in (ruta,*ruta.parents):
            st=d.lstat()
            if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022:
                raise PermissionError('instalacion_no_protegida')
    sys.path[:]=[str(INSTALACION),*(str(p) for p in rutas)]
    # Comprobar el código de python3-apt antes de importarlo (también sus pyc).
    from importlib.machinery import PathFinder
    for nombre in ('apt','apt_pkg','apt_inst'):
        spec=PathFinder.find_spec(nombre,[str(rutas[-1])])
        if spec is None or not spec.origin:raise ImportError(nombre)
        origen=Path(spec.origin)
        nodos=[origen]
        if spec.submodule_search_locations:
            raiz=origen.parent
            nodos=[raiz,*raiz.rglob('*')]
        for nodo in nodos:
            st=nodo.lstat()
            if (not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode))
                    or st.st_uid!=0 or st.st_mode&0o022
                    or (stat.S_ISREG(st.st_mode) and st.st_nlink!=1)):
                raise PermissionError('instalacion_no_protegida')


def verificar_instalacion(*,instalacion=None,archivos=None):
    instalacion=INSTALACION if instalacion is None else instalacion
    archivos=ARCHIVOS if archivos is None else archivos
    if Path(__file__).absolute()!=instalacion/'ejecutor_apt.py':
        raise PermissionError('instalacion_no_protegida')
    for p in (instalacion,*instalacion.parents):
        s=p.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022:
            raise PermissionError('instalacion_no_protegida')
    if {p.name for p in instalacion.iterdir()}!=set(archivos):
        raise PermissionError('instalacion_no_protegida')
    for nombre in archivos:
        s=(instalacion/nombre).lstat()
        if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022 or s.st_nlink!=1:
            raise PermissionError('instalacion_no_protegida')


def main_dnf5(args):
    ejecucion_posible=False
    estado='cancelado'
    try:
        if args not in (['comprobar'],['ejecutar'],['historial']):raise ValueError('operacion_no_autorizada')
        if not (sys.flags.isolated and sys.flags.no_site):raise PermissionError('python_no_aislado')
        verificar_instalacion(instalacion=INSTALACION_DNF5,archivos=ARCHIVOS_DNF5)
        # DNF5 es un ejecutable nativo; no importar site-packages ni bindings.
        # Mantener solo la biblioteca estándar de Python -I -S, con rutas protegidas.
        for ruta in sys.path:
            p=Path(ruta)
            if not p.is_absolute():raise PermissionError('instalacion_no_protegida')
            nodos=(p,*p.parents) if p.exists() else p.parents
            for nodo in nodos:
                s=nodo.lstat()
                if not (stat.S_ISDIR(s.st_mode) or stat.S_ISREG(s.st_mode)) or s.st_uid!=0 or s.st_mode&0o022:
                    raise PermissionError('instalacion_no_protegida')
        sys.path.insert(0,str(INSTALACION_DNF5))
        from mantenimiento_dnf5 import main_helper
        ejecucion_posible=args==['ejecutar']
        r=main_helper(args)
        print(json.dumps(r,ensure_ascii=True,sort_keys=True))
        return 0 if r['estado'] in ('completo','preparado') else 1
    except KeyboardInterrupt:
        error='operacion_interrumpida'
        if ejecucion_posible:estado='resultado_desconocido'
    except BlockingIOError:error='ejecutor_ocupado'
    except (OSError,ValueError,TypeError,KeyError,ImportError,RuntimeError,sqlite3.Error) as exc:
        permitidos={'operacion_no_autorizada','python_no_aislado','instalacion_no_protegida','fedora45_requerido',
                    'sudo_interactivo_requerido','dnf5_no_disponible','autorizacion_caducada','autorizacion_alterada',
                    'peticion_invalida','peticion_demasiado_grande','identidad_no_coincidente','consulta_dnf5_requerida',
                    'terminal_requerida','terminal_io_error'}
        error=str(exc) if str(exc) in permitidos else 'ejecutor_no_disponible'
        if ejecucion_posible and str(exc) not in permitidos:estado='resultado_desconocido'
    print(json.dumps(dict(version=1,estado=estado,error=error)))
    return 1


def confirmar_tty(p):
    from autorizacion_apt import frase, abrir_tty_confirmacion
    # La autorización ocurre dentro de la frontera privilegiada; stdin JSON no
    # sirve como confirmación y no hay opción --yes ni token aceptado por argv.
    with abrir_tty_confirmacion() as tty:
        from autorizacion_apt import OPERACION_DESCARGA
        if p['operacion']==OPERACION_DESCARGA:
            return confirmar_descarga_tty(tty,p)
        tty.write('\nPLAN APT A AUTORIZAR — Debian 13, solo paquetes cacheados\n')
        for r in p['plan']['simulacion']['actualizaciones']:
            tty.write(f"{r['nombre']}:{r['arquitectura']} {r['anterior']} -> {r['propuesta']}\n")
        tty.write('Sin instalaciones adicionales, eliminaciones ni descargas.\n'
                  'Los paquetes ejecutarán scripts de mantenimiento y pueden reiniciar servicios.\n'
                  'Se conservarán conffiles existentes (confdef/confold). No se reinicia el equipo.\n'
                  'Se escribirán los registros SQLite y, tras revalidar, los paquetes aprobados.\n'
                  'Huella del plan: '+p['plan']['huella']+'\n'
                  'Para autorizar esta operación exacta escriba:\n'+frase(p)+'\n> ')
        tty.flush()
        respuesta=tty.readline(200).strip()
    return respuesta==frase(p)


def confirmar_descarga_tty(tty,p):
    from autorizacion_apt import frase
    tty.write('\nDESCARGA APT: NO AUTORIZA INSTALACIÓN\n')
    for r in p['archivos']:
        origen=', '.join(o['sitio']+' '+o['archivo'] for o in r['origenes'])
        tty.write(f"{r['nombre']}:{r['arquitectura']} {r['version']} | {r['bytes']} bytes | {origen} | SHA256 {r['sha256']}\n")
    tty.write('Máximo estimado: '+str(sum(r['bytes'] for r in p['archivos']))+' bytes.\n'
              'Solo repositorios configurados; sin apt update ni instalación.\n'
              'Se revalidarán plan y manifiesto bajo bloqueos. Pueden quedar descargas parciales.\n'
              'Huella del plan: '+p['plan']['huella']+'\n'+frase(p)+'\n> ')
    tty.flush()
    return tty.readline(200).strip()==frase(p)


def main(argv=None):
    args=sys.argv[1:] if argv is None else argv
    if Path(__file__).absolute()==INSTALACION_DNF5/'ejecutor_apt.py':return main_dnf5(args)
    if args not in (['comprobar'],['ejecutar'],['historial'],['descargar']):
        print(json.dumps(dict(version=1,estado='cancelado',error='operacion_no_autorizada')))
        return 1
    try:
        verificar_instalacion()
        preparar_imports()
        from distribucion_linux import detectar_distribucion
        d=detectar_distribucion()
        if d['estado']!='soportado' or d['id']!='debian' or d['version_id']!='13':
            raise ValueError('debian13_requerido')
        uid=os.environ.get('SUDO_UID','')
        from apt_ejecucion_nativa import ENTORNO
        os.environ.clear();os.environ.update(ENTORNO)
        import apt,apt_pkg  # Dependencia nativa necesaria para la transacción bloqueada.
        if not all(hasattr(apt_pkg,n) for n in ('SystemLock','FileLock','PackageManager','pkgsystem_unlock_inner')):
            raise ValueError('api_apt_no_admitida')
        if args==['comprobar']:
            print(json.dumps(dict(version=1,estado='preparado',ejecucion=False)))
            return 0
        if os.geteuid()!=0 or not uid.isdecimal() or int(uid)<=0:
            raise PermissionError('sudo_interactivo_requerido')
        uid=int(uid)
        if args==['historial']:
            from registro_mantenimiento import historial
            print(json.dumps(dict(version=1,estado='completo',operaciones=historial()),ensure_ascii=True))
            return 0
        from autorizacion_apt import MAX_PETICION,leer_json,validar_peticion
        contenido=sys.stdin.buffer.read(MAX_PETICION+1)
        if len(contenido)>MAX_PETICION:raise ValueError('peticion_demasiado_grande')
        p=leer_json(contenido)
        from autorizacion_apt import OPERACION,OPERACION_DESCARGA
        operacion=OPERACION_DESCARGA if args==['descargar'] else OPERACION
        validar_peticion(p,uid,operacion=operacion)
        if not confirmar_tty(p):
            print(json.dumps(dict(version=1,id=p['id'],estado='cancelado',error='confirmacion_rechazada')))
            return 1
        # Solo después de la autorización pueden crearse el diario y bloqueos.
        from registro_mantenimiento import Registro
        from ejecucion_apt import ejecutar,descargar
        from apt_ejecucion_nativa import AptNativo
        with Registro() as registro:
            accion=descargar if args==['descargar'] else ejecutar
            resultado=accion(p,uid,AptNativo(),registro,lambda p:True)
        print(json.dumps(resultado,ensure_ascii=True,sort_keys=True))
        return 0 if resultado['estado']=='completo' else 1
    except KeyboardInterrupt:
        error='operacion_interrumpida'
    except BlockingIOError:
        error='ejecutor_ocupado'
    except (OSError,ValueError,TypeError,KeyError,ImportError,RuntimeError,sqlite3.Error) as e:
        permitidos={'python_no_aislado','instalacion_no_protegida','debian13_requerido','api_apt_no_admitida',
                    'sudo_interactivo_requerido','peticion_demasiado_grande','peticion_invalida',
                    'autorizacion_caducada','autorizacion_alterada','plan_no_ejecutable','alcance_no_admitido',
                    'terminal_requerida','terminal_io_error'}
        error=str(e) if str(e) in permitidos else 'ejecutor_no_disponible'
    print(json.dumps(dict(version=1,estado='cancelado',error=error)))
    return 1


if __name__=='__main__':
    sys.exit(main())
