"""Destino SQLite opcional por instantáneas; no abre archivos al construirse.

SQLite trabaja en memoria y serializa una base estándar; el archivo se publica
atómicamente por descriptores, sin journals de SQLite en rutas reabiertas.
Seguridad frente a otros usuarios; código malicioso con el mismo UID queda fuera
del límite de confianza de Python. No hay migraciones ni adquisiciones.
"""
import fcntl
import json
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import threading

from historial_sqlite import HistorialMemoria, ErrorHistorial, ESQUEMA, _lote, _fecha
from historial_contratos import validar

MAX_BASE_BYTES = 16 * 1024 * 1024
_LOCK = threading.RLock()
NOMBRE = 'historial.sqlite3'


def _fallo():
    raise ErrorHistorial('destino_persistente_no_disponible')


def _ruta(base):
    p = Path(base)
    if not p.is_absolute() or '..' in p.parts or str(p) == '/':
        _fallo()
    return p / 'AsistenteLocal'


def _seguro(fd, directorio=False, privado=False):
    s = os.fstat(fd)
    if not (stat.S_ISDIR(s.st_mode) if directorio else stat.S_ISREG(s.st_mode)):
        _fallo()
    if privado and (s.st_uid != os.geteuid() or stat.S_IMODE(s.st_mode) != (0o700 if directorio else 0o600)):
        _fallo()
    if not directorio and s.st_nlink != 1:
        _fallo()
    return s


def _directorio(ruta, crear=True):
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for i, parte in enumerate(ruta.parts[1:]):
            try:
                siguiente = os.open(parte, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            except FileNotFoundError:
                if not crear:
                    raise
                os.mkdir(parte, 0o700, dir_fd=fd)
                siguiente = os.open(parte, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            try:
                s = _seguro(siguiente, True, i == len(ruta.parts)-2)
            except BaseException:
                os.close(siguiente)
                raise
            # Ancestros escribibles por otros solo si sticky (p.ej. /tmp en tests).
            if s.st_mode & 0o022 and not s.st_mode & stat.S_ISVTX:
                os.close(siguiente)
                _fallo()
            os.close(fd)
            fd = siguiente
        return fd
    except BaseException:
        os.close(fd)
        raise


def _cargar(fd):
    s = _seguro(fd, privado=True)
    if not 0 < s.st_size <= MAX_BASE_BYTES:
        _fallo()
    bloques = []
    restante = s.st_size
    while restante:
        bloque = os.read(fd, min(restante, 65536))
        if not bloque:
            _fallo()
        bloques.append(bloque)
        restante -= len(bloque)
    if os.read(fd, 1):
        _fallo()
    motor = HistorialMemoria()
    try:
        motor._conexion.deserialize(b''.join(bloques))
        conexion = motor._conexion
        conexion.execute('PRAGMA trusted_schema=OFF')
        conexion.execute('PRAGMA foreign_keys=ON')
        conexion.execute('PRAGMA temp_store=MEMORY')
        conexion.execute('PRAGMA journal_mode=MEMORY')
        motor._comprobar()
        if conexion.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
            _fallo()
        esperado = sqlite3.connect(':memory:')
        try:
            for sql in ESQUEMA:
                esperado.execute(sql)
            consulta = "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"
            if conexion.execute(consulta).fetchall() != esperado.execute(consulta).fetchall():
                _fallo()
        finally:
            esperado.close()
        if conexion.execute('PRAGMA foreign_key_check').fetchall():
            _fallo()
        # No confiar en JSON de un archivo preexistente aunque su esquema coincida.
        for aid, inicio, fin, guardado, distro, autorizacion in conexion.execute(
                'SELECT id,inicio_utc,fin_utc,guardado_utc,distribucion,autorizacion FROM auditorias'):
            _fecha(guardado)
            registros = [validar(json.loads(r)) for (r,) in conexion.execute(
                'SELECT registro_json FROM resultados WHERE auditoria_id=? ORDER BY orden', (aid,))]
            eventos = [dict(tipo=t, resultado_orden=o, cantidad=c) for t,o,c in conexion.execute(
                'SELECT e.tipo,r.orden,e.cantidad FROM eventos e LEFT JOIN resultados r ON r.id=e.resultado_id AND r.auditoria_id=e.auditoria_id WHERE e.auditoria_id=? ORDER BY e.orden', (aid,))]
            _lote(dict(inicio_utc=inicio, fin_utc=fin, distribucion=distro,
                       autorizacion=autorizacion), registros, eventos)
        return motor
    except BaseException:
        motor.cerrar()
        raise


class HistorialPersistente:
    """Resolver ruta no crea nada. base_datos permite destinos temporales en tests.

    Por defecto XDG_DATA_HOME absoluto; si falta o es relativo, ~/.local/share.
    No se acepta nombre de archivo alternativo ni se modifican permisos existentes.
    """

    def __init__(self, *, base_datos=None):
        if base_datos is None:
            xdg = os.environ.get('XDG_DATA_HOME', '')
            base_datos = xdg if xdg and Path(xdg).is_absolute() else Path.home()/'.local'/'share'
        self._ruta = _ruta(base_datos)

    def _leer(self):
        directorio = fd = None
        try:
            directorio = _directorio(self._ruta, crear=False)
            fd = os.open(NOMBRE, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directorio)
            return _cargar(fd)
        except FileNotFoundError:
            return None
        except (OSError, sqlite3.Error, ValueError, TypeError, KeyError):
            raise ErrorHistorial('destino_persistente_no_disponible') from None
        finally:
            for descriptor in (fd, directorio):
                if descriptor is not None:
                    os.close(descriptor)

    def disponible(self):
        motor = self._leer()
        if motor is None:
            return False
        motor.cerrar()
        return True

    def listar_auditorias(self, limite=100, despues_id=0):
        return self._consultar('listar_auditorias', limite, despues_id)

    def consultar_resultados(self, auditoria_id):
        return self._consultar('consultar_resultados', auditoria_id)

    def consultar_eventos(self, auditoria_id):
        return self._consultar('consultar_eventos', auditoria_id)

    def _consultar(self, metodo, *args):
        motor = self._leer()
        if motor is None:
            return []
        try:
            return getattr(motor, metodo)(*args)
        finally:
            motor.cerrar()


    def guardar_auditoria(self, *args, **kwargs):
        raise ErrorHistorial('autorizacion_controlador_requerida')

    def _guardar_autorizado(self, permiso):
        # Solo permisos efímeros emitidos por guardar() del controlador.
        from historial_controlador import _consumir_permiso
        d, vigente = _consumir_permiso(permiso, self)
        _lote(d['auditoria'], d['resultados'], d['eventos'])
        with _LOCK:
            vigente()
            directorio = anterior = bloqueo = temporal_fd = None
            temporal = None
            motor = None
            publicado = False
            try:
                directorio = _directorio(self._ruta)
                # Bloqueo estable separado: no se bloquea el inode que se sustituye.
                bloqueo = os.open('.historial.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                                  0o600, dir_fd=directorio)
                _seguro(bloqueo, privado=True)
                fcntl.flock(bloqueo, fcntl.LOCK_EX | fcntl.LOCK_NB)
                try:
                    anterior = os.open(NOMBRE, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directorio)
                except FileNotFoundError:
                    motor = HistorialMemoria()
                else:
                    motor = _cargar(anterior)
                ident = motor.guardar_auditoria(d['auditoria'], d['resultados'], d['eventos'])
                contenido = motor._conexion.serialize()
                if len(contenido) > MAX_BASE_BYTES:
                    _fallo()
                vigente()
                temporal = '.historial-'+secrets.token_hex(16)+'.tmp'
                temporal_fd = os.open(temporal, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                      0o600, dir_fd=directorio)
                _seguro(temporal_fd, privado=True)
                vista = memoryview(contenido)
                while vista:
                    n = os.write(temporal_fd, vista)
                    if n <= 0:
                        _fallo()
                    vista = vista[n:]
                os.fsync(temporal_fd)
                # Revalidar la entrada antes de reemplazarla; nunca seguir un enlace.
                try:
                    actual = os.stat(NOMBRE, dir_fd=directorio, follow_symlinks=False)
                except FileNotFoundError:
                    if anterior is not None:
                        _fallo()
                else:
                    if anterior is None or (actual.st_dev, actual.st_ino) != (os.fstat(anterior).st_dev, os.fstat(anterior).st_ino):
                        _fallo()
                    _seguro(anterior, privado=True)
                vigente()
                os.replace(temporal, NOMBRE, src_dir_fd=directorio, dst_dir_fd=directorio)
                publicado = True
                temporal = None
                try:
                    os.fsync(directorio)
                except OSError:
                    # Publicado: no declarar rollback ni invitar a repetir un guardado.
                    raise ErrorHistorial('publicado_durabilidad_no_confirmada') from None
                return ident
            except ErrorHistorial:
                raise
            except (OSError, sqlite3.Error, ValueError, TypeError, KeyError):
                raise ErrorHistorial('destino_persistente_no_disponible') from None
            finally:
                if motor is not None:
                    motor.cerrar()
                if temporal is not None and not publicado:
                    try:
                        os.unlink(temporal, dir_fd=directorio)
                    except FileNotFoundError:
                        pass
                for fd in (temporal_fd, anterior, bloqueo, directorio):
                    if fd is not None:
                        os.close(fd)
