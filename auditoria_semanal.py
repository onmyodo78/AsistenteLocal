"""Programación opcional: reutiliza el coordinador factual, nunca el modelo."""
import fcntl
import os
from pathlib import Path
import shutil
import stat
import tempfile
from datetime import datetime, timezone


def directorio_privado(ruta):
    ruta = Path(ruta).absolute()
    # No seguir enlaces en los directorios destinados a registros privados.
    for padre in (*reversed(ruta.parents), ruta):
        if padre.is_symlink():
            raise ValueError('directorio_enlazado')
        if padre.exists():
            st = padre.lstat()
            temporal_sistema = st.st_uid == 0 and bool(st.st_mode & stat.S_ISVTX)
            if (not stat.S_ISDIR(st.st_mode) or st.st_uid not in (0, os.getuid())
                    or (st.st_mode & 0o022 and not temporal_sistema)):
                raise ValueError('ruta_no_protegida')
    ruta.mkdir(mode=0o700, parents=True, exist_ok=True)
    st = ruta.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise ValueError('directorio_no_privado')
    return ruta


def ejecutar(directorio):
    """Una ejecución, sin reintentos; publicación conjunta de texto y JSON."""
    if os.geteuid() == 0:
        raise ValueError('ejecucion_root_rechazada')
    from auditoria_basica import auditar, informe
    from contratos_autonomia import validar_traza
    from contratos_mantenimiento import serializar
    from cli import sanear
    raiz = directorio_privado(directorio)
    fd = os.open(raiz / '.auditoria.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    temporal = None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_nlink != 1 or st.st_mode & 0o077:
            raise ValueError('bloqueo_no_protegido')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return dict(version=1, estado='omitido', motivo='ejecucion_en_curso')
        traza = auditar()
        validar_traza(traza)
        texto = sanear(informe(traza))
        temporal = Path(tempfile.mkdtemp(prefix='.en-curso-', dir=raiz))
        for nombre, contenido in [('traza.json', serializar(traza)), ('informe.txt', texto)]:
            with open(temporal / nombre, 'x', encoding='utf-8') as f:
                os.chmod(f.name, 0o600)
                f.write(contenido + '\n'); f.flush(); os.fsync(f.fileno())
        nombre = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ-') + temporal.name.removeprefix('.en-curso-')
        destino = raiz / nombre
        os.rename(temporal, destino)
        temporal = None
        cierre = traza[-1]
        return dict(version=1, estado=cierre['estado'], motivo=cierre['motivo_parada'], directorio=str(destino))
    finally:
        try:
            if temporal is not None:
                try:
                    shutil.rmtree(temporal)
                except OSError:
                    # No ocultar el fallo original ni tocar informes publicados.
                    import sys
                    print('No se pudo limpiar un directorio .en-curso-; requiere revisión local.', file=sys.stderr)
        finally:
            os.close(fd)  # No eliminar el inode del bloqueo: evita carreras entre invocaciones.


def _argumento(valor):
    valor = str(valor)
    if any(ord(c) < 32 or ord(c) == 127 for c in valor):
        raise ValueError('ruta_unidad_invalida')
    return '"' + valor.replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%').replace('$', '$$') + '"'


def unidades(directorio_resultados):
    """Devuelve plantillas; no instala, recarga ni habilita systemd."""
    cli = Path(__file__).resolve().with_name('cli.py')
    resultados = Path(directorio_resultados)
    if not resultados.is_absolute():
        raise ValueError('ruta_absoluta_requerida')
    servicio = '''[Unit]
Description=AsistenteLocal: auditoría factual local de lectura

[Service]
Type=oneshot
UMask=0077
NoNewPrivileges=true
RestrictSUIDSGID=true
TimeoutStartSec=150
ExecStart=/usr/bin/python3 -B ''' + _argumento(cli) + ' auditoria-semanal --directorio ' + _argumento(resultados) + '''
'''
    temporizador = '''[Unit]
Description=AsistenteLocal: auditoría semanal voluntaria

[Timer]
OnCalendar=weekly
Persistent=true
RandomizedDelaySec=30m
Unit=asistentelocal-auditoria.service

[Install]
WantedBy=timers.target
'''
    return {'asistentelocal-auditoria.service': servicio, 'asistentelocal-auditoria.timer': temporizador}
