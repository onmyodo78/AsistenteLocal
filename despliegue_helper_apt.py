"""Despliegue inicial cerrado; no importa ni ejecuta módulos del helper APT."""
import argparse
import ctypes
import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile

MODULOS = (
    'ejecutor_apt.py', 'ejecucion_apt.py', 'apt_ejecucion_nativa.py',
    'autorizacion_apt.py', 'registro_mantenimiento.py',
    'contratos_mantenimiento.py', 'apt_simulacion.py',
    'distribucion_linux.py', 'archivos_apt.py',
)
DESTINO = Path('/usr/local/lib/asistentelocal')
MODULOS_DNF5=('ejecutor_apt.py','ejecucion_apt.py','mantenimiento_dnf5.py','dnf5_interactivo.py',
              'autorizacion_apt.py','registro_mantenimiento.py','contratos_mantenimiento.py','distribucion_linux.py')
DESTINO_DNF5=Path('/usr/local/lib/asistentelocal-dnf5')
MAX_ARCHIVO = 4 * 1024 * 1024


def leer_regular(fd, limite=MAX_ARCHIVO):
    antes = os.fstat(fd)
    if not stat.S_ISREG(antes.st_mode) or antes.st_nlink != 1:
        raise ValueError('Archivo no regular o con enlaces adicionales')
    if antes.st_mode & 0o7002:
        raise ValueError('Bits especiales o escritura para otros en entrada')
    contenido = bytearray()
    while True:
        bloque = os.read(fd, min(65536, limite + 1 - len(contenido)))
        if not bloque:
            break
        contenido.extend(bloque)
        if len(contenido) > limite:
            raise ValueError('Archivo demasiado grande')
    despues = os.fstat(fd)
    if (antes.st_size, antes.st_mtime_ns, antes.st_ctime_ns) != (
            despues.st_size, despues.st_mtime_ns, despues.st_ctime_ns):
        raise ValueError('Entrada modificada durante la lectura')
    return bytes(contenido)


def abrir_directorio(ruta):
    ruta = Path(ruta)
    if not ruta.is_absolute() or '..' in ruta.parts:
        raise ValueError('Se exige una ruta absoluta sin ..')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for parte in ruta.parts[1:]:
            nuevo = os.open(parte, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=fd)
            os.close(fd)
            fd = nuevo
        return fd
    except BaseException:
        os.close(fd)
        raise


def leer_ruta(ruta):
    padre = abrir_directorio(Path(ruta).parent)
    try:
        fd = os.open(Path(ruta).name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=padre)
        try:
            return leer_regular(fd)
        finally:
            os.close(fd)
    finally:
        os.close(padre)


def interpretar_manifiesto(datos, digest,modulos=None):
    modulos=MODULOS if modulos is None else modulos
    if not re.fullmatch('[0-9a-f]{64}', digest):
        raise ValueError('Digest de referencia inválido')
    if hashlib.sha256(datos).hexdigest() != digest:
        raise ValueError('El manifiesto no coincide con el aprobado')
    resultado = {}
    for linea in datos.decode('ascii').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([a-z_][a-z0-9_]*\.py)', linea)
        if not match or match[2] in resultado:
            raise ValueError('Formato o nombre duplicado en manifiesto')
        resultado[match[2]] = match[1]
    if set(resultado) != set(modulos):
        raise ValueError('El manifiesto debe contener exactamente los módulos del backend')
    return resultado


def verificar_antecesores(ruta):
    """Recorrer directorios protegidos sin seguir enlaces ni exigir modo exacto."""
    ruta = Path(ruta)
    if not ruta.is_absolute() or '..' in ruta.parts:
        raise ValueError('Se exige una ruta absoluta sin ..')

    def comprobar(fd):
        info = os.fstat(fd)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or info.st_gid != 0 or info.st_mode & 0o7022
                or not info.st_mode & 0o100):
            raise ValueError('Antecesor no protegido o sin recorrido: ' + str(ruta))

    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        comprobar(fd)
        for parte in ruta.parts[1:]:
            nuevo = os.open(parte, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=fd)
            os.close(fd)
            fd = nuevo
            comprobar(fd)
    finally:
        os.close(fd)


def verificar_directorio(ruta, uid=0, modo=0o755):
    info = os.lstat(ruta)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != uid
            or info.st_gid != (0 if uid == 0 else os.getgid())
            or stat.S_IMODE(info.st_mode) != modo):
        raise ValueError('Propiedad, tipo o permisos de directorio incorrectos: ' + str(ruta))


def verificar_contenido(ruta, hashes, uid=0,modulos=None):
    modulos=MODULOS if modulos is None else modulos
    verificar_directorio(ruta, uid)
    if set(os.listdir(ruta)) != set(modulos):
        raise ValueError('Contenido inesperado o incompleto')
    for nombre in modulos:
        archivo = ruta / nombre
        info = os.lstat(archivo)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != uid
                or info.st_gid != (0 if uid == 0 else os.getgid())
                or stat.S_IMODE(info.st_mode) != 0o644):
            raise ValueError('Propiedad, tipo o permisos incorrectos: ' + nombre)
        if hashlib.sha256(leer_ruta(archivo)).hexdigest() != hashes[nombre]:
            raise ValueError('SHA-256 incorrecto: ' + nombre)


def publicar_sin_reemplazar(origen, destino):
    # renameat2 es atómico y rechaza incluso un destino vacío creado concurrentemente.
    libc = ctypes.CDLL(None, use_errno=True)
    rename = libc.renameat2  # Sin alternativa insegura si no está disponible.
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                       ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(-100, os.fsencode(origen), -100, os.fsencode(destino), 1):
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), str(destino))


def desplegar(origen, manifiesto, digest, destino=DESTINO, uid=0,*,modulos=None):
    """uid/destino internos permiten pruebas sintéticas; la CLI no los acepta."""
    destino = Path(destino)
    opciones_perfil={} if modulos is None else {'modulos':modulos}
    modulos=MODULOS if modulos is None else modulos
    verificar_directorio(destino.parent, uid)
    if os.path.lexists(destino):
        raise ValueError('Destino ya existente; no se reemplaza')
    # Capturar bytes y contrastarlos con la referencia aprobada ANTES de utilizarlos.
    referencia = leer_ruta(manifiesto)
    hashes = interpretar_manifiesto(referencia, digest,**opciones_perfil)
    temporal = Path(tempfile.mkdtemp(prefix='.asistentelocal-despliegue-',
                                    dir=destino.parent))
    publicado = False
    publicacion_iniciada = False
    error_principal = None
    try:
        os.chmod(temporal, 0o700)
        verificar_directorio(temporal, uid, 0o700)
        protegido = temporal / 'manifiesto.sha256'
        with protegido.open('xb') as salida:
            os.chmod(protegido, 0o600)
            salida.write(referencia)
            salida.flush()
            os.fsync(salida.fileno())
        contenido = temporal / 'contenido'
        contenido.mkdir(mode=0o700)
        fuente = abrir_directorio(origen)
        try:
            for nombre in modulos:
                fd = os.open(nombre, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=fuente)
                try:
                    datos = leer_regular(fd)
                finally:
                    os.close(fd)
                with (contenido / nombre).open('xb') as salida:
                    salida.write(datos)
                    salida.flush()
                    os.fchmod(salida.fileno(), 0o644)
                    os.fsync(salida.fileno())
        finally:
            os.close(fuente)
        os.chmod(contenido, 0o755)
        # Se verifican los bytes COPIADOS contra la referencia protegida, nunca
        # contra hashes recalculados de las fuentes actuales.
        hashes = interpretar_manifiesto(leer_ruta(protegido), digest,**opciones_perfil)
        verificar_contenido(contenido, hashes, uid,**opciones_perfil)
        fd = abrir_directorio(contenido)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        # Persistir también la referencia privada antes de intentar publicar.
        fd = abrir_directorio(temporal)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        # Una interrupción puede llegar después del rename y antes de asignar
        # publicado. Desde este punto conservar evidencia incluso si es incierto.
        publicacion_iniciada = True
        publicar_sin_reemplazar(contenido, destino)
        publicado = True
        fd = abrir_directorio(destino.parent)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        verificar_contenido(destino, hashes, uid,**opciones_perfil)
        return hashes
    except BaseException as error:
        error_principal = error
        if publicacion_iniciada:
            estado = 'publicado' if publicado else 'publicación iniciada; resultado incierto'
            error.add_note(
                f'Despliegue {estado}. NO ejecutar el helper hasta revisión '
                f'administrativa. Destino intacto: {destino}. '
                f'Evidencia privada conservada: {temporal}. '
                f'SHA-256 del manifiesto aprobado: {digest}.')
        raise
    finally:
        # Nunca retirar evidencia de una publicación fallida/incierta ni tocar
        # el destino. En éxito, retirar únicamente el área temporal privada.
        if error_principal is None or not publicacion_iniciada:
            try:
                shutil.rmtree(temporal)
            except BaseException as error_limpieza:
                nota = (f'Falló la limpieza de {temporal}; revisar manualmente. '
                        f'Destino intacto: {destino}. '
                        f'SHA-256 del manifiesto aprobado: {digest}.')
                if error_principal is not None:
                    error_principal.add_note(nota)
                    error_principal.add_note(
                        f'Error secundario de limpieza: {error_limpieza!r}')
                else:
                    error_limpieza.add_note(
                        'El destino ya fue publicado y verificado; '
                        'el fallo corresponde únicamente a la limpieza. ' + nota)
                    raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--origen', required=True)
    parser.add_argument('--manifiesto', required=True)
    parser.add_argument('--sha256-manifiesto', required=True)
    parser.add_argument('--backend',choices=('apt','dnf5'),default='apt')
    args = parser.parse_args()
    if not sys.flags.isolated or not sys.flags.no_site or os.geteuid() != 0:
        parser.error('Se exige root temporal y Python -I -S')
    os.umask(0o077)
    verificar_antecesores('/usr/local/lib')
    destino=DESTINO if args.backend=='apt' else DESTINO_DNF5
    modulos=MODULOS if args.backend=='apt' else MODULOS_DNF5
    hashes = desplegar(args.origen, args.manifiesto, args.sha256_manifiesto,destino,modulos=modulos)
    print('PUBLICADO Y VERIFICADO: ' + str(destino))
    for nombre in modulos:
        print(hashes[nombre] + '  ' + str(destino / nombre))


if __name__ == '__main__':
    main()
