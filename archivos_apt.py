"""Metadatos y comprobación local de .deb compartidos por diagnóstico y helper."""
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import unicodedata
from contratos_mantenimiento import paquete, serializar

ALMACEN=Path('/var/cache/apt/archives')


def manifiesto(versiones):
    import apt_pkg
    filas=[]
    for v in versiones:
        p=paquete(v.package.name.split(':')[0],v.architecture,None,v.version)
        origenes=sorted([dict(origen=o.origin,archivo=o.archive,sitio=o.site,
                              confiable=bool(o.trusted)) for o in v.origins],key=serializar)
        if (not re.fullmatch('[0-9a-fA-F]{64}',v.sha256) or type(v.size) is not int
                or v.size<=0 or not origenes or not any(o['confiable'] for o in origenes)):
            raise ValueError('metadatos_no_verificados')
        archivo='_'.join(apt_pkg.quote_string(x,'_:') for x in
                         (p['nombre'],v.version,v.architecture))+'.deb'
        filas.append(dict(nombre=p['nombre'],arquitectura=v.architecture,version=v.version,
                          archivo=archivo,bytes=v.size,sha256=v.sha256.lower(),origenes=origenes,
                          bytes_instalados=v.installed_size))
    return sorted(filas,key=serializar)


def validar_manifiesto(filas,plan):
    if type(filas) is not list or len(filas)!=len(plan['simulacion']['actualizaciones']):
        raise ValueError('manifiesto_invalido')
    identidades=[]
    for r in filas:
        if type(r) is not dict or set(r)!={'nombre','arquitectura','version','archivo','bytes','sha256','origenes','bytes_instalados'}:
            raise ValueError('manifiesto_invalido')
        paquete(r['nombre'],r['arquitectura'],None,r['version'])
        if (type(r['archivo']) is not str or not re.fullmatch(r'[a-zA-Z0-9+.%~:_-]+\.deb',r['archivo'])
                or type(r['bytes']) is not int or r['bytes']<=0
                or type(r['bytes_instalados']) is not int or r['bytes_instalados']<0
                or type(r['sha256']) is not str or not re.fullmatch('[0-9a-f]{64}',r['sha256'])
                or type(r['origenes']) is not list or not 1<=len(r['origenes'])<=32):
            raise ValueError('manifiesto_invalido')
        for o in r['origenes']:
            if (type(o) is not dict or set(o)!={'origen','archivo','sitio','confiable'}
                    or type(o['confiable']) is not bool
                    or any(type(o[k]) is not str or len(o[k])>512 or any(unicodedata.category(c).startswith('C') for c in o[k]) for k in ('origen','archivo','sitio'))):
                raise ValueError('manifiesto_invalido')
        if not any(o['confiable'] for o in r['origenes']):raise ValueError('metadatos_no_verificados')
        identidades.append((r['nombre'],r['arquitectura'],r['version']))
    esperado=[(r['nombre'],r['arquitectura'],r['propuesta']) for r in plan['simulacion']['actualizaciones']]
    if sorted(identidades)!=sorted(esperado) or len({r['archivo'] for r in filas})!=len(filas):
        raise ValueError('manifiesto_invalido')
    return filas


def comprobar_archivo(r,ruta=None):
    """Sin escribir ni seguir enlaces; hash y cabecera de la misma ruta protegida."""
    p=ALMACEN/r['archivo'] if ruta is None else Path(ruta)
    base=dict(archivo=str(p),estado='no_verificable',sha256_observado=None,
              bytes_observados=None,version_observada=None,proteccion=False)
    try:
        fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
        try:
            st=os.fstat(fd)
            base['bytes_observados']=st.st_size
            if (not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022 or st.st_nlink!=1):
                return dict(base,estado='inseguro')
            base['proteccion']=True
            if st.st_size!=r['bytes']:return dict(base,estado='tamano_incorrecto')
            h=hashlib.sha256()
            with os.fdopen(os.dup(fd),'rb') as f:
                while True:
                    b=f.read(1024*1024)
                    if not b:break
                    h.update(b)
            base['sha256_observado']=h.hexdigest()
            if h.hexdigest()!=r['sha256']:return dict(base,estado='hash_incorrecto')
            with open(os.devnull,'rb') as entrada:
                resultado=subprocess.run(['/usr/bin/dpkg-deb','--show',
                    '--showformat=${Package}\t${Architecture}\t${Version}\n',str(p)],
                    stdin=entrada,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                    env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},timeout=10,check=False)
            esperado=f"{r['nombre']}\t{r['arquitectura']}\t{r['version']}\n".encode()
            if resultado.returncode or resultado.stderr or resultado.stdout!=esperado:
                return dict(base,estado='cabecera_incorrecta')
            # Detectar sustitución entre hash y lectura de cabecera.
            ahora=p.lstat()
            if (ahora.st_dev,ahora.st_ino,ahora.st_size,ahora.st_mtime_ns,ahora.st_ctime_ns)!=(st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns):
                return dict(base,estado='archivo_cambiado')
            return dict(base,estado='verificado',version_observada=r['version'])
        finally:os.close(fd)
    except FileNotFoundError:return dict(base,estado='ausente')
    except (OSError,ValueError,subprocess.TimeoutExpired):return base
