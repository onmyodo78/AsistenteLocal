"""Sondeo ejecutado exclusivamente en el trabajador aislado sin red/escrituras."""
import os
from pathlib import Path
import time
from archivos_apt import manifiesto,comprobar_archivo
from contratos_mantenimiento import paquete


def recoger():
    import apt,apt_pkg
    from apt_ejecucion_nativa import verificar_entorno_root
    try:
        verificar_entorno_root();entorno='protegido'
    except ValueError:entorno='no_protegido'
    except OSError:entorno='no_verificable'
    apt_pkg.init_config()
    for k,v in {'Dir::Cache::pkgcache':'','Dir::Cache::srcpkgcache':'',
                'Debug::NoLocking':'true','Dir::State::status':'/var/lib/dpkg/status'}.items():
        apt_pkg.config.set(k,v)
    apt_pkg.init_system()
    with apt.Cache(memonly=True) as cache:
        cache.upgrade(dist_upgrade=True)  # Solo marcas en memoria, no PackageManager.
        versiones=[];acciones=[]
        for p in cache.get_changes():
            if not p.marked_upgrade or p.marked_delete or p.marked_downgrade or p.marked_reinstall:
                raise ValueError('alcance_no_admitido')
            versiones.append(p.candidate)
            acciones.append(paquete(p.name.split(':')[0],p.candidate.architecture,p.installed.version,p.candidate.version))
        filas=manifiesto(versiones)
        edades=[]
        for archivo in cache._cache.file_list:
            if archivo.filename.startswith('/var/lib/apt/lists/'):
                edades.append(max(0,int(time.time()-os.stat(archivo.filename).st_mtime)))
        return dict(version=1,entorno_ejecucion=entorno,python_apt=apt_pkg.VERSION,roto=cache.broken_count!=0,
                    acciones=acciones,archivos=[dict(r,comprobacion=comprobar_archivo(r)) for r in filas],
                    indices=dict(archivos_observados=len(edades),edad_maxima_mtime_segundos=max(edades) if edades else None,
                                 frescura_verificada=False,firmas_revalidadas=False))
