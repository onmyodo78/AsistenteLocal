"""Lanzador Linux de auditoría. Sin privilegios; falla cerrado antes de exec.

Landlock bloquea escrituras de archivos y cambios de nombres. Seccomp bloquea
sockets y operaciones de metadatos no cubiertas por Landlock. Solo x86_64.
Las restricciones se heredan por exec y solo afectan al subproceso.
"""
import ctypes
import errno
import os
import resource
import sys

ERROR_AISLAMIENTO = 78


def restringir(*, temporal_fd=None):
    if sys.platform != 'linux' or os.uname().machine != 'x86_64':
        raise OSError('aislamiento no disponible')
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
        raise OSError('no_new_privs')
    abi = libc.syscall(444, 0, 0, 1)  # landlock_create_ruleset VERSION
    if abi < 3:  # TRUNCATE imprescindible
        raise OSError('Landlock ABI insuficiente')
    class Ruleset(ctypes.Structure):
        _fields_ = [('handled_access_fs', ctypes.c_uint64)]
    mascara = (1 << 1) | sum(1 << n for n in range(4, 15))
    if abi >= 5:
        mascara |= 1 << 15  # IOCTL_DEV
    reglas = Ruleset(mascara)
    fd = libc.syscall(444, ctypes.byref(reglas), ctypes.sizeof(reglas), 0)
    if fd < 0:
        raise OSError('Landlock ruleset')
    try:
        if temporal_fd is not None:
            # Uso exclusivo del trabajador de mantenimiento: scratch privado,
            # nunca bases de paquetes, índices ni configuración. Las auditorías
            # existentes no pasan este descriptor y siguen sin rutas escribibles.
            import stat
            st = os.fstat(temporal_fd)
            if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o700:
                raise OSError('temporal no privado')
            class PathBeneath(ctypes.Structure):
                _pack_ = 1
                _fields_ = [('allowed_access', ctypes.c_uint64), ('parent_fd', ctypes.c_int)]
            acceso = (1 << 1) | (1 << 5) | (1 << 8) | (1 << 14)
            regla = PathBeneath(acceso, temporal_fd)
            if libc.syscall(445, fd, 1, ctypes.byref(regla), 0) != 0:
                raise OSError('Landlock temporal')
        if libc.syscall(446, fd, 0) != 0:  # restrict_self: ninguna ruta escribible
            raise OSError('Landlock restrict_self')
    finally:
        os.close(fd)

    class Filter(ctypes.Structure):
        _fields_ = [('code', ctypes.c_ushort), ('jt', ctypes.c_ubyte),
                    ('jf', ctypes.c_ubyte), ('k', ctypes.c_uint32)]
    class Program(ctypes.Structure):
        _fields_ = [('len', ctypes.c_ushort), ('filter', ctypes.POINTER(Filter))]
    # Números de syscall Linux x86_64. No aceptar ABI x32 ni otra arquitectura.
    denegadas = (
        16, 41, 53,  # ioctl, socket, socketpair
        90, 91, 92, 93, 94,  # chmod/chown y variantes fd
        101, 132, 165, 166, 167, 168, 169,  # ptrace, utime, mount, reboot...
        188, 189, 190, 197, 198, 199,  # xattrs
        235, 260, 261, 268, 272, 280, 298, 308, 311, 321,
        425, 438, 442, 452,  # io_uring, pidfd_getfd, mount_setattr, fchmodat2
    )
    instrucciones = [Filter(0x20, 0, 0, 4),  # LD arch
                     Filter(0x15, 1, 0, 0xc000003e),
                     Filter(0x06, 0, 0, 0x80000000),  # KILL_PROCESS
                     Filter(0x20, 0, 0, 0),  # LD syscall
                     Filter(0x35, 0, 1, 0x40000000),
                     Filter(0x06, 0, 0, 0x80000000)]
    for numero in denegadas:
        instrucciones.extend((Filter(0x15, 0, 1, numero),
                              Filter(0x06, 0, 0, 0x00050000 | errno.EPERM)))
    instrucciones.append(Filter(0x06, 0, 0, 0x7fff0000))  # ALLOW
    filtros = (Filter * len(instrucciones))(*instrucciones)
    programa = Program(len(filtros), filtros)
    if libc.prctl(22, 2, ctypes.byref(programa), 0, 0) != 0:
        raise OSError('seccomp')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    limite_archivo = 0 if temporal_fd is None else 64 * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_FSIZE, (limite_archivo, limite_archivo))
    resource.setrlimit(resource.RLIMIT_AS, (1024**3, 1024**3))
    resource.setrlimit(resource.RLIMIT_CPU, (10, 11))


def main():
    # Lista blanca independiente: no ejecutar argumentos arbitrarios.
    if sys.argv[1:] not in (['pendientes'], ['instalados'], ['rpm'], ['dpkg'], ['apt-local']):
        return ERROR_AISLAMIENTO
    try:
        restringir()
    except Exception:
        return ERROR_AISLAMIENTO
    if sys.argv[1] == 'apt-local':
        from apt_debian import emitir_local
        return emitir_local()
    from auditoria_seguridad import DNF, FORMATO_RPM
    if sys.argv[1] == 'dpkg':
        from auditoria_debian import COMANDO
        comando = list(COMANDO)
    elif sys.argv[1] == 'rpm':
        comando = ['rpm', '-qa', '--qf', FORMATO_RPM]
    else:
        comando = list(DNF) + ['--available' if sys.argv[1] == 'pendientes' else '--installed']
    try:
        entorno = dict(os.environ, LC_ALL='C', PYTHONDONTWRITEBYTECODE='1')
        os.execvpe(comando[0], comando, entorno)
    except OSError:
        return 69


if __name__ == '__main__':
    sys.exit(main())
