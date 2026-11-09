"""Lista blanca independiente. No contiene instalación ni ejecución de transacciones."""
import json
import os
from pathlib import Path
import sys

# -I elimina el directorio del script; importar solo el código de esta instalación.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from apt_simulacion import COMANDO_SIMULACION as APT

RPM = ('/usr/bin/rpm', '-qa', '--qf', '%{NAME}\t%{ARCH}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n')


def comandos():
    resultado = {'apt-dpkg-audit':('/usr/bin/dpkg','--audit'), 'apt-version': ('/usr/bin/apt-get', '--version'), 'apt-simular': APT,
                 'rpm-inventario': RPM}
    for n in ('dnf', 'dnf5'):
        prefijo = ('/usr/bin/' + n, '--cacheonly', '--no-plugins')
        resultado[n + '-version'] = ('/usr/bin/' + n, '--version')
        consulta = (prefijo[0], '-q', *prefijo[1:]) if n == 'dnf5' else prefijo
        resultado[n + '-consultar'] = consulta + ('repoquery', '--upgrades',
            '--qf', '%{name}\t%{arch}\t%{evr}')
        # El aborto no demuestra una simulación estructurada válida. Solo sondeo
        # del resolvedor DNF5, cuyo texto nunca se acepta como plan completo.
        if n == 'dnf5':
            resultado[n + '-simular'] = prefijo + ('--assumeno', 'upgrade')
    return resultado


def resolver_dnf():
    """API nativa opcional DNF4; resolve() sin download/do_transaction()."""
    try:
        import dnf
        import dnf.transaction as tr
    except ImportError:
        return 70
    try:
        with dnf.Base() as base:
            base.conf.read()
            base.conf.cacheonly = True
            base.conf.plugins = False
            base.conf.logdir = os.environ['TMPDIR']
            base.conf.persistdir = os.environ['TMPDIR']
            base.read_all_repos()
            base.fill_sack(load_system_repo=True)
            base.upgrade_all()
            if not base.resolve():
                return 72
            acciones = []
            etiquetas = {getattr(tr, clave): valor for clave, valor in (
                ('PKG_INSTALL','instalar'), ('PKG_UPGRADE','actualizar'),
                ('PKG_ERASE','eliminar'), ('PKG_UPGRADED','reemplazado'),
                ('PKG_OBSOLETED','eliminar')) if hasattr(tr, clave)}
            for item in base.transaction:
                if item.action not in etiquetas:
                    return 72
                p = item.pkg
                acciones.append(dict(accion=etiquetas[item.action], nombre=p.name,
                    arquitectura=p.arch, version=str(p.evr)))
            print(json.dumps({'version': 1, 'resolvedor': 'dnf4', 'acciones': acciones}, sort_keys=True))
        return 0
    except Exception:
        return 72


def main():
    modos = comandos()
    if len(sys.argv) != 2 or sys.argv[1] not in (*modos, 'dnf-simular', 'dnf5-preparar', 'apt-diagnostico') or os.geteuid() == 0:
        return 78
    try:
        import stat
        temporal = os.environ.get('ASISTENTE_TEMPORAL', '')
        ruta = Path(temporal)
        if ruta.parent != Path('/tmp') or not ruta.name.startswith('asistentelocal-plan-'):
            return 78
        temporal_fd = os.open(temporal, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            st = os.fstat(temporal_fd)
            if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o700:
                return 78
            from auditoria_aislamiento import restringir
            restringir(temporal_fd=temporal_fd)
        finally:
            os.close(temporal_fd)
    except Exception:
        return 78
    if sys.argv[1] == 'dnf5-preparar':
        from dnf5_preparacion import recoger
        print(json.dumps(recoger(temporal),sort_keys=True))
        return 0
    if sys.argv[1] == 'apt-diagnostico':
        try:
            from diagnostico_apt_nativo import recoger
            print(json.dumps(recoger(),sort_keys=True))
            return 0
        except (OSError,ValueError,KeyError,TypeError,ImportError,SystemError,AttributeError):
            return 72
    if sys.argv[1] == 'dnf-simular':
        return resolver_dnf()
    try:
        os.execve(modos[sys.argv[1]][0], list(modos[sys.argv[1]]),
                  dict(os.environ, LC_ALL='C', LANG='C'))
    except OSError:
        return 69


if __name__ == '__main__':
    sys.exit(main())
