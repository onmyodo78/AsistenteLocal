"""Aplicación de una transacción congelada APT. Solo se instancia tras autorización.

Requiere python3-apt del sistema. No usa Cache.commit(): evitar su bucle de
reintentos y cualquier descarga implícita. InstallArchives conserva el bloqueo
frontend y entrega el bloqueo interior a dpkg mediante la API nativa.
"""
from contextlib import contextmanager, ExitStack
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import signal
import sys
import threading
from apt_simulacion import COMANDO_SIMULACION, parsear_simulacion
from contratos_mantenimiento import paquete, serializar

ENTORNO = {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/root','LC_ALL':'C',
           'LANG':'C','DEBIAN_FRONTEND':'noninteractive','DEBCONF_NONINTERACTIVE_SEEN':'true'}
INVENTARIO = ('/usr/bin/dpkg-query','--admindir=/var/lib/dpkg','--show',
              '--showformat=${Package}\t${Architecture}\t${Version}\t${Status}\n')
MAX_SALIDA = 4*1024*1024


def lectura(comando):
    # Catálogo privado; ningún argumento procede de un texto del modelo.
    if tuple(comando) not in (COMANDO_SIMULACION,INVENTARIO,('/usr/bin/dpkg','--audit')):
        raise ValueError('operacion_no_autorizada')
    r=subprocess.run(comando,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE,env=ENTORNO,timeout=45,check=False)
    if r.returncode or r.stderr or len(r.stdout)>MAX_SALIDA:
        raise ValueError('lectura_nativa_fallida')
    return r.stdout.decode('utf-8',errors='strict')


def verificar_directorio_root(ruta):
    p=Path(ruta)
    for d in (p,*p.parents):
        st=d.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022:
            raise ValueError('configuracion_no_admitida')


def verificar_entorno_root():
    for ruta in ('/var/lib/dpkg','/var/lib/apt/lists','/var/cache/apt/archives'):
        verificar_directorio_root(ruta)
    # APT abre estos nombres por ruta. Los padres protegidos no bastan si
    # ya existe un enlace o un lock modificable por otro usuario.
    for ruta in ('/var/lib/dpkg/lock-frontend','/var/lib/dpkg/lock',
                 '/var/lib/apt/lists/lock','/var/cache/apt/archives/lock'):
        try:st=Path(ruta).lstat()
        except FileNotFoundError:continue  # La API nativa lo crea como root.
        if (not stat.S_ISREG(st.st_mode) or st.st_uid!=0
                or st.st_mode&0o022 or st.st_nlink!=1):
            raise ValueError('configuracion_no_admitida')


def inventario_local():
    filas=[]
    for linea in lectura(INVENTARIO).splitlines():
        campos=linea.split('\t')
        if len(campos)!=4:raise ValueError('dpkg_incompleto')
        n,a,v,estado=campos
        seleccion,ok,actual=estado.split(' ') if len(estado.split(' '))==3 else ('','','')
        if ok!='ok' or actual not in ('installed','config-files','not-installed'):
            raise ValueError('dpkg_incompleto')
        if actual=='not-installed':continue
        paquete(n,a,v,None)
        filas.append(dict(nombre_binario=n,arquitectura=a,version=v,
                          estado_instalacion=estado,categoria='instalado' if actual=='installed' else 'residual'))
    if not filas:raise ValueError('dpkg_incompleto')
    return filas


@contextmanager
def capturar_salida():
    """Drena stdout/stderr nativos sin bloquear dpkg ni guardar una salida ilimitada."""
    sys.stdout.flush();sys.stderr.flush()
    lectura_fd,escritura_fd=os.pipe()
    guardados=(os.dup(1),os.dup(2))
    cola=bytearray()
    sincronizar=threading.Lock()
    def drenar():
        try:
            while True:
                bloque=os.read(lectura_fd,4096)
                if not bloque:break
                with sincronizar:
                    cola.extend(bloque)
                    if len(cola)>65536:del cola[:-65536]
        except OSError:pass
        finally:os.close(lectura_fd)
    hilo=threading.Thread(target=drenar,daemon=True)
    hilo.start()
    os.dup2(escritura_fd,1);os.dup2(escritura_fd,2);os.close(escritura_fd)
    try:yield cola
    finally:
        sys.stdout.flush();sys.stderr.flush()
        os.dup2(guardados[0],1);os.dup2(guardados[1],2)
        for fd in guardados:os.close(fd)
        hilo.join(timeout=2)


class AptNativo:
    def __init__(self):
        self.cache=None
        self.pm=None
        self.fetcher=None
        self.plan=None
        self.antes=None

    @contextmanager
    def bloqueo(self):
        import apt
        import apt_pkg
        verificar_entorno_root()
        self.apt=apt
        self.pkg=apt_pkg
        apt_pkg.init_config()
        for k,v in {'RootDir':'','Dir':'/','Dir::State':'/var/lib/apt/',
                    'Dir::State::lists':'/var/lib/apt/lists/',
                    'Dir::State::status':'/var/lib/dpkg/status','Dir::Bin::dpkg':'/usr/bin/dpkg',
                    'Dir::Cache':'/var/cache/apt/',
                    'Dir::Cache::archives':'/var/cache/apt/archives/',
                    'Dir::Cache::pkgcache':'','Dir::Cache::srcpkgcache':'',
                    'Debug::NoLocking':'false','DPkg::Lock::Timeout':'0',
                    'APT::Get::Simulate':'false',
                    'APT::Get::AllowUnauthenticated':'false'}.items():apt_pkg.config.set(k,v)
        apt_pkg.config.clear('DPkg::Options')
        apt_pkg.config.set('DPkg::Options::','--force-confdef')
        apt_pkg.config.set('DPkg::Options::','--force-confold')
        apt_pkg.init_system()
        with ExitStack() as pila:
            try:
                pila.enter_context(apt_pkg.SystemLock())
                pila.enter_context(apt_pkg.FileLock('/var/lib/apt/lists/lock'))
                pila.enter_context(apt_pkg.FileLock('/var/cache/apt/archives/lock'))
            except (SystemError,OSError) as e:
                raise BlockingIOError('gestor_bloqueado') from e
            self.cache=apt.Cache()
            try:yield
            finally:
                if self.fetcher is not None:self.fetcher.shutdown()
                self.cache.close()

    def comprobar_sistema(self):
        if lectura(('/usr/bin/dpkg','--audit')).strip():raise ValueError('dpkg_incompleto')
        if self.cache.broken_count:raise ValueError('dpkg_incompleto')
        self.antes=inventario_local()

    def simular(self):
        s=parsear_simulacion(lectura(COMANDO_SIMULACION),self.antes)
        s.update(estado='completo',retenciones_estado='completo',errores=[])
        for k,v in s.items():
            if isinstance(v,list):s[k]=sorted(v,key=serializar)
        politica=self.pkg.Policy(self.cache._cache)
        for clave,metodo in (('Dir::Etc::preferences',politica.read_pinfile),
                              ('Dir::Etc::preferencesparts',politica.read_pindir)):
            ruta=self.pkg.config.find_file(clave) if clave.endswith('preferences') else self.pkg.config.find_dir(clave)
            if os.path.exists(ruta) and not metodo(ruta):raise ValueError('configuracion_no_admitida')
        filas=[]
        for p in self.cache._cache.packages:
            v=p.current_ver
            if v is None or p.current_state!=self.pkg.CURSTATE_INSTALLED or p.inst_state not in (self.pkg.INSTSTATE_OK,self.pkg.INSTSTATE_HOLD):continue
            nueva=politica.get_candidate_ver(p)
            if nueva is not None and self.pkg.version_compare(nueva.ver_str,v.ver_str)>0:
                filas.append(paquete(p.name,v.arch,v.ver_str,nueva.ver_str))
        return dict(simulacion=s,candidatas=filas)

    def marcar_y_comprobar(self,plan):
        self.plan=plan
        for r in plan['simulacion']['actualizaciones']:
            if self.pkg.version_compare(r['propuesta'],r['anterior'])<=0:raise ValueError('version_no_superior')
        self.cache.upgrade(dist_upgrade=True)
        observadas=[]
        self.versiones=[]
        for p in self.cache.get_changes():
            if (not p.marked_upgrade or p.marked_delete or p.marked_downgrade or p.marked_reinstall
                    or p.installed is None or p.candidate is None):
                raise ValueError('transaccion_nativa_diferente')
            observadas.append(paquete(p.name.split(':')[0],p.candidate.architecture,
                                     p.installed.version,p.candidate.version))
            self.versiones.append(p.candidate)
        if serializar(sorted(observadas,key=serializar))!=serializar(plan['simulacion']['actualizaciones']):
            raise ValueError('transaccion_nativa_diferente')

    def preparar_archivos(self):
        # No se invoca Acquire.run ni Cache.commit: no existe descarga implícita.
        esperado={}
        for v in self.versiones:
            if not any(o.trusted for o in v.origins) or not re.fullmatch('[0-9a-fA-F]{64}',v.sha256):
                raise ValueError('archivos_no_verificados')
            esperado[v.sha256.lower()]=v.size
        self.pm=self.pkg.PackageManager(self.cache._depcache)
        self.fetcher=self.pkg.Acquire()
        if not self.pm.get_archives(self.fetcher,self.cache._list,self.cache._records):
            raise ValueError('paquetes_no_cacheados')
        encontrados=set()
        almacen=Path('/var/cache/apt/archives')
        # Verificar los destinos EXACTOS seleccionados por PackageManager. Un
        # .deb correcto con otro nombre no acredita el archivo que dpkg recibirá.
        for item in self.fetcher.items:
            if not item.complete or not item.is_trusted:
                raise ValueError('paquetes_no_cacheados')
            p=Path(item.destfile)
            if p.parent!=almacen or p.suffix!='.deb':
                raise ValueError('archivos_no_verificados')
            fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
            try:
                st=os.fstat(fd)
                if (not stat.S_ISREG(st.st_mode) or st.st_uid!=0
                        or st.st_mode&0o022 or st.st_nlink!=1):
                    raise ValueError('archivos_no_verificados')
                h=hashlib.sha256()
                while True:
                    bloque=os.read(fd,1024*1024)
                    if not bloque:break
                    h.update(bloque)
                checksum=h.hexdigest()
                if esperado.get(checksum)!=st.st_size:
                    raise ValueError('paquetes_no_cacheados')
                encontrados.add(checksum)
            finally:os.close(fd)
        if encontrados!=set(esperado):raise ValueError('paquetes_no_cacheados')

    def instalar(self):
        import apt.progress.base
        incidencias=[]
        class Progreso(apt.progress.base.InstallProgress):
            def wait_child(self):
                estado=super().wait_child()
                # python3-apt 3.0 convierte con WEXITSTATUS sin WIFEXITED;
                # un hijo muerto por señal podría convertirse en código cero.
                if not os.WIFEXITED(estado):
                    raise RuntimeError('instalador_interrumpido')
                return estado
            def error(self,pkg,errormsg):
                if len(incidencias)<100:incidencias.append(dict(paquete=str(pkg)[:256],error=str(errormsg)[:1024]))
            def conffile(self,current,new):
                # La política fija de dpkg mantiene la configuración existente.
                pass
        # Sin timeout destructivo: dejar que el gestor finalice y comprobar después.
        anteriores={s:signal.getsignal(s) for s in (signal.SIGINT,signal.SIGTERM)}
        for s in anteriores:signal.signal(s,signal.SIG_IGN)
        try:
            with capturar_salida() as salida:
                try:
                    res=self.cache.install_archives(self.pm,Progreso())
                finally:
                    self.ultima_salida=bytes(salida).decode('utf-8',errors='replace')
        finally:
            for s,h in anteriores.items():signal.signal(s,h)
        evidencia=bytes(salida).decode('utf-8',errors='replace')
        return res==self.pm.RESULT_COMPLETED,dict(codigo=res,errores=incidencias,
                                                  salida_nativa_no_interpretada=evidencia)

    def verificar(self,plan):
        if lectura(('/usr/bin/dpkg','--audit')).strip():return False
        despues=inventario_local()
        antes={(r['nombre_binario'],r['arquitectura']):r['version'] for r in self.antes if r['categoria']=='instalado'}
        esperado=dict(antes)
        for r in plan['simulacion']['actualizaciones']:esperado[r['nombre'],r['arquitectura']]=r['propuesta']
        actual={(r['nombre_binario'],r['arquitectura']):r['version'] for r in despues if r['categoria']=='instalado'}
        return actual==esperado


    def descargar(self,archivos):
        from archivos_apt import comprobar_archivo
        # Ningún comando apt-get ni opción del solicitante; Acquire recibe solo
        # la transacción nativa ya marcada, revalidada y bloqueada.
        st=os.statvfs('/var/cache/apt/archives')
        if st.f_bavail*st.f_frsize < sum(r['bytes'] for r in archivos)+64*1024*1024:
            raise ValueError('espacio_insuficiente')
        self.pkg.config.set('Acquire::Retries','0')
        self.pm=self.pkg.PackageManager(self.cache._depcache)
        self.fetcher=self.pkg.Acquire()
        if not self.pm.get_archives(self.fetcher,self.cache._list,self.cache._records):
            raise ValueError('descarga_incompleta')
        esperados={r['archivo']:r for r in archivos}
        vistos=set()
        for item in self.fetcher.items:
            p=Path(item.destfile)
            # Archivos pendientes pueden tener destino partial. Nunca aceptar
            # rutas ajenas al almacén fijo ni nombres distintos del manifiesto.
            if (p.parent not in (Path('/var/cache/apt/archives'),Path('/var/cache/apt/archives/partial'))
                    or p.name not in esperados or not item.is_trusted):
                raise ValueError('archivos_no_verificados')
            vistos.add(p.name)
        if vistos!=set(esperados):raise ValueError('descarga_incompleta')
        with capturar_salida() as salida:
            try:
                codigo=self.fetcher.run()  # Único punto de red, tras autorización explícita.
            finally:self.ultima_salida=bytes(salida).decode('utf-8',errors='replace')
        if codigo!=self.pkg.Acquire.RESULT_CONTINUE or any(not i.complete for i in self.fetcher.items):
            raise ValueError('descarga_incompleta')
        # APT puede dejar archivos propiedad _apt: fallar cerrado; no cambiar
        # permisos ni propietarios automáticamente para satisfacer al instalador.
        resultados=[dict(nombre=r['nombre'],comprobacion=comprobar_archivo(r)) for r in archivos]
        if any(r['comprobacion']['estado']!='verificado' for r in resultados):
            raise ValueError('archivos_no_verificados')
        return dict(archivos=resultados,salida_nativa_no_interpretada=bytes(salida).decode('utf-8',errors='replace'))
