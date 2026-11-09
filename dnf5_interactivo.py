"""Backend administrativo CLI: comando cerrado, DNF5 y humano comparten TTY.

Solo se instancia desde el helper protegido tras autorización explícita.
No hay parser de tablas humanas, respuestas automáticas ni captura del terminal.
"""
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import stat
import subprocess
from contratos_mantenimiento import MAX_FILAS,paquete,serializar

# DNF5 5.4.7: --no-plugins solo desactiva plugins de libdnf5.
# La variable vacía impide cargar plugins de aplicación; NO retirarla para
# silenciar avisos de alias. Sin alternativa documentada, fallar cerrado.
ENTORNO={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/root','LC_ALL':'C','LANG':'C',
         'DNF5_PLUGINS_DIR':'','DNF5_FORCE_INTERACTIVE':'1'}
COMANDO=('/usr/bin/dnf5','--no-plugins','--setopt=assumeyes=False',
         '--setopt=assumeno=False','--setopt=defaultyes=False',
         '--setopt=skip_broken=False','--setopt=skip_unavailable=False',
         '--setopt=skip_system_repo_lock=False',
         '--setopt=tsflags=','upgrade','--no-allow-downgrade')
RPM=('/usr/bin/rpm','-qa','--qf','%{NAME}\t%{ARCH}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n')
CHECK=('/usr/bin/dnf5','-q','--cacheonly','--no-plugins','check')
MAX_SALIDA=4*1024*1024
MAX_CAMBIOS=500


def proteger_binario(nombre):
    p=Path(nombre)
    for ruta in (p.parent,*p.parent.parents,p.resolve().parent,*p.resolve().parent.parents):
        s=ruta.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022:
            raise ValueError('configuracion_no_admitida')
    s=p.resolve().lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022 or not os.access(p,os.X_OK):
        raise ValueError('dnf5_no_disponible')


def lectura(comando):
    if comando not in (RPM,CHECK):raise ValueError('operacion_no_autorizada')
    r=subprocess.run(comando,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                     env=ENTORNO,timeout=45,check=False)
    if len(r.stdout)+len(r.stderr)>MAX_SALIDA:raise ValueError('inventario_rpm_no_verificado')
    return r


def inventario():
    r=lectura(RPM)
    if r.returncode or r.stderr:raise ValueError('inventario_rpm_no_verificado')
    filas=[];vistos=set()
    for linea in r.stdout.decode('utf-8',errors='strict').splitlines():
        campos=linea.split('\t')
        if len(campos)!=3 or len(filas)>=MAX_FILAS:raise ValueError('inventario_rpm_no_verificado')
        n,a,v=campos
        if n=='gpg-pubkey' and a=='(none)':continue
        p=paquete(n,a,v,None)
        clave=serializar(p)
        if clave in vistos:raise ValueError('inventario_rpm_no_verificado')
        vistos.add(clave);filas.append(p)
    if not filas:raise ValueError('inventario_rpm_no_verificado')
    return sorted(filas,key=serializar)


def resumen(antes,despues):
    a={serializar(p):p for p in antes};d={serializar(p):p for p in despues}
    salidas=sorted(a.keys()-d.keys());entradas=sorted(d.keys()-a.keys())
    total=len(salidas)+len(entradas)
    return dict(inventario_anterior_sha256=hashlib.sha256(serializar(antes).encode()).hexdigest(),
        inventario_posterior_sha256=hashlib.sha256(serializar(despues).encode()).hexdigest(),
        registros_antes=len(antes),registros_despues=len(despues),cambios_total=total,
        versiones_que_salen=[a[k] for k in salidas[:MAX_CAMBIOS]],
        versiones_que_entran=[d[k] for k in entradas[:MAX_CAMBIOS]],
        lista_cambios_completa=len(salidas)<=MAX_CAMBIOS and len(entradas)<=MAX_CAMBIOS,
        alcance='inventario_y_consistencia_rpm; no acredita transaccion exacta, ausencia de actualizaciones ni seguridad global')


class Dnf5Interactivo:
    @staticmethod
    def comprobar_binarios():
        proteger_binario('/usr/bin/dnf5');proteger_binario('/usr/bin/rpm')

    @contextmanager
    def bloqueo(self):
        # Registro excluye otras sesiones AsistenteLocal. DNF5 adquiere sus
        # bloqueos nativos durante su propio proceso; no fingir un lock RPM aquí.
        yield

    def comprobar_sistema(self):
        from mantenimiento_dnf5 import exigir_fedora45
        exigir_fedora45()
        if os.geteuid()!=0:raise ValueError('permisos_insuficientes')
        self.comprobar_binarios()
        with open('/dev/tty','r+b',buffering=0) as tty:
            if not os.isatty(tty.fileno()):raise ValueError('terminal_requerida')

    def preparar_archivos(self):
        # Equivalente al punto de preparación común, sin congelar ni descargar RPM.
        self.antes=inventario()

    def instalar(self):
        with open('/dev/tty','r+b',buffering=0) as tty:
            if not os.isatty(tty.fileno()):raise ValueError('terminal_requerida')
            try:proceso=subprocess.Popen(COMANDO,stdin=tty,stdout=tty,stderr=tty,env=ENTORNO)
            except PermissionError:return False,dict(codigo_dnf5=None,error='permisos_insuficientes')
            while True:
                try:codigo=proceso.wait();break
                except KeyboardInterrupt:
                    # Ctrl-C también llega a DNF5. Esperar su salida; no matar,
                    # reenviar respuestas, volver a arrancar ni repetir transacción.
                    continue
        return codigo==0,dict(codigo_dnf5=codigo)

    def verificar(self,plan):
        self.verificacion={'estado':'no_verificable','cambios_total':None}
        try:
            despues=inventario()
            self.verificacion.update(resumen(self.antes,despues))
            r=lectura(CHECK)
            self.verificacion.update(codigo_check=r.returncode,stdout_check_bytes=len(r.stdout),stderr_check_bytes=len(r.stderr))
            correcto=r.returncode==0 and not r.stdout and not r.stderr
            self.verificacion['estado']='comprobado' if correcto else 'no_verificable'
            return correcto
        except (OSError,ValueError,UnicodeError,subprocess.TimeoutExpired):return False
