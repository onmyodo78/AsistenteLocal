"""Publicación md/csv explícitamente autorizada, sin integración con la aplicación.

Linux/POSIX con openat/linkat y enlaces duros en el mismo directorio. No hay
fallback. Temporal 0600, verificado y sincronizado antes del link sin reemplazo.
No es una barrera frente a código malicioso con el mismo UID o un administrador.
"""
import os
from pathlib import PurePosixPath
import secrets
import stat
import sys

from exportacion_controlador import ControladorExportacion, _destino
from exportacion_generadores import MAX_REPRESENTACION_BYTES


class ErrorEscritura(ValueError):
    """Código cerrado. Nunca incluye rutas, contenido ni mensajes del SO."""


def _fallo(codigo):
    raise ErrorEscritura(codigo) from None


def _plataforma():
    if (sys.platform != 'linux' or any(f not in os.supports_dir_fd for f in
            (os.open, os.link, os.unlink, os.stat)) or
            not all(hasattr(os, k) for k in ('O_NOFOLLOW', 'O_DIRECTORY', 'O_CLOEXEC'))):
        _fallo('publicacion_segura_no_disponible')


def _abrir_padre(destino):
    ruta = PurePosixPath(destino)
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for parte in ruta.parts[1:-1]:
            siguiente = os.open(parte, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = siguiente
            s = os.fstat(fd)
            if s.st_mode & 0o022 and not s.st_mode & stat.S_ISVTX:
                _fallo('directorio_no_admitido')
        s = os.fstat(fd)
        if s.st_uid != os.geteuid() or s.st_mode & 0o022:
            _fallo('directorio_no_admitido')
        return fd
    except BaseException:
        os.close(fd)
        raise


def _identidad(s):
    return s.st_dev, s.st_ino


def _verificar(fd, contenido):
    s = os.fstat(fd)
    if (not stat.S_ISREG(s.st_mode) or s.st_uid != os.geteuid() or
            stat.S_IMODE(s.st_mode) != 0o600 or s.st_size != len(contenido) or s.st_nlink != 1):
        _fallo('verificacion_fallida')
    os.lseek(fd, 0, os.SEEK_SET)
    posicion = 0
    while posicion < len(contenido):
        bloque = os.read(fd, min(65536, len(contenido)-posicion))
        if not bloque or bloque != contenido[posicion:posicion+len(bloque)]:
            _fallo('verificacion_fallida')
        posicion += len(bloque)
    if os.read(fd, 1):
        _fallo('verificacion_fallida')


def _publicar(entrega, vigente):
    _plataforma()
    _destino(entrega.destino, entrega.formato)
    contenido = entrega.contenido
    if type(contenido) is not bytes or not 0 < len(contenido) <= MAX_REPRESENTACION_BYTES:
        _fallo('contenido_no_admitido')
    padre = temporal_fd = None
    temporal = None
    publicado = False
    nombre = PurePosixPath(entrega.destino).name
    try:
        vigente()
        padre = _abrir_padre(entrega.destino)
        # No es la garantía de exclusión: esa la proporciona link(), incluso si
        # alguien crea el destino después de esta comprobación inicial.
        try:
            os.stat(nombre, dir_fd=padre, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            _fallo('destino_existente')
        temporal = '.asistentelocal-export-'+secrets.token_hex(16)+'.tmp'
        temporal_fd = os.open(temporal, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                              0o600, dir_fd=padre)
        # Solo cambia permisos del archivo nuevo propio, nunca del destino.
        os.fchmod(temporal_fd, 0o600)
        vista = memoryview(contenido)
        while vista:
            vigente()
            n = os.write(temporal_fd, vista[:65536])
            if n <= 0:
                _fallo('escritura_fallida')
            vista = vista[n:]
        os.fsync(temporal_fd)
        _verificar(temporal_fd, contenido)
        if _identidad(os.stat(temporal, dir_fd=padre, follow_symlinks=False)) != _identidad(os.fstat(temporal_fd)):
            _fallo('temporal_sustituido')
        comprobacion = _abrir_padre(entrega.destino)
        try:
            if _identidad(os.fstat(comprobacion)) != _identidad(os.fstat(padre)):
                _fallo('directorio_sustituido')
        finally:
            os.close(comprobacion)
        vigente()
        try:
            os.link(temporal, nombre, src_dir_fd=padre, dst_dir_fd=padre, follow_symlinks=False)
        except FileExistsError:
            _fallo('destino_existente')
        publicado = True
        os.unlink(temporal, dir_fd=padre)
        temporal = None
        os.fsync(padre)
        return dict(estado='publicado', formato=entrega.formato, bytes=len(contenido),
                    contenido_verificado=True, durabilidad='sincronizada')
    except ErrorEscritura:
        raise
    except (OSError, ValueError, TypeError):
        _fallo('publicado_finalizacion_no_confirmada' if publicado else 'escritura_fallida')
    finally:
        limpieza_fallida = False
        if temporal is not None and padre is not None:
            try:
                os.unlink(temporal, dir_fd=padre)
            except FileNotFoundError:
                pass
            except OSError:
                limpieza_fallida = True
        for descriptor in (temporal_fd, padre):
            if descriptor is not None:
                os.close(descriptor)
        if limpieza_fallida:
            _fallo('publicado_limpieza_no_confirmada' if publicado else 'limpieza_no_confirmada')


def publicar(controlador, identificador, autorizacion=None):
    """Única API de escritura: consume el token, nunca acepta entregas ni bytes.

    Mantiene el bloqueo del controlador durante la operación. Un fallo consume
    el permiso; no hay reintentos. Comprueba vigencia también antes del link.
    """
    if type(controlador) is not ControladorExportacion:
        _fallo('controlador_no_admitido')
    try:
        with controlador._lock:
            # Leer el plazo del permiso que consumir() verificará íntegramente.
            try:
                permiso = controlador._autorizaciones.get(autorizacion)
            except TypeError:
                permiso = None
            entrega = ControladorExportacion.consumir(controlador, identificador, autorizacion)
            if permiso is None:
                _fallo('autorizacion_no_disponible')
            def vigente():
                if not permiso['inicio'] <= controlador._ahora() < permiso['vence']:
                    _fallo('autorizacion_no_vigente')
            return _publicar(entrega, vigente)
    except ErrorEscritura:
        raise
    except (ValueError, TypeError, KeyError, OSError):
        raise ErrorEscritura('publicacion_no_autorizada_o_fallida') from None
