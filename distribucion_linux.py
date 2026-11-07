"""Detección independiente: no selecciona herramientas ni ejecuta comandos.

Solo reconoce Fedora con versión numérica y Debian 13. Los derivados no se
habilitan mediante ID_LIKE. Una fuente existente inválida o ilegible no permite
recurrir a la siguiente. contenido y rutas son entradas alternativas para tests.
"""
from pathlib import Path
import re
import shlex

RUTAS_OS_RELEASE = ('/etc/os-release', '/usr/lib/os-release')
MAX_CONTENIDO = 65536
_ASIGNACION = re.compile(r'([A-Z_][A-Z_0-9]*)=(.*)')
_VALOR = re.compile(r'''(?:'[^']*'|"(?:\\.|[^"\\])*"|(?:\\.|[^\s'"\\])*)''')


def detectar_distribucion(*, contenido=None, rutas=None):
    """Devuelve estado, ID, VERSION_ID, VERSION_CODENAME, origen y motivo.

    No hay fallback por contenido inválido, permisos o distribución desconocida.
    Los campos ausentes se representan con None. No se evalúan expansiones shell.
    """
    resultado = dict(estado='no_soportado', id=None, version_id=None,
                     version_codename=None, origen=None, motivo=None)
    if contenido is not None and rutas is not None:
        raise ValueError('Usar contenido o rutas, no ambos')
    if contenido is None:
        for ruta in RUTAS_OS_RELEASE if rutas is None else rutas:
            resultado['origen'] = str(ruta)
            try:
                with Path(ruta).open('r', encoding='utf-8') as fuente:
                    contenido = fuente.read(MAX_CONTENIDO + 1)
                break
            except FileNotFoundError:
                continue
            except (OSError, UnicodeError):
                resultado['motivo'] = 'lectura_no_disponible'
                return resultado
        else:
            resultado.update(origen=None, motivo='archivos_ausentes')
            return resultado
    else:
        resultado['origen'] = 'contenido'
    try:
        if not isinstance(contenido, str) or len(contenido) > MAX_CONTENIDO:
            raise ValueError()
        if any(ord(c) < 32 and c not in '\n\r\t' or ord(c) == 127 for c in contenido):
            raise ValueError()
        campos = {}
        for linea in contenido.splitlines():
            linea = linea.strip()
            if not linea or linea.startswith('#'):
                continue
            match = _ASIGNACION.fullmatch(linea)
            if not match or not _VALOR.fullmatch(match[2]) or match[1] in campos:
                raise ValueError()
            valores = shlex.split(match[2], comments=False, posix=True)
            campos[match[1]] = valores[0] if valores else ''
        ident = campos.get('ID')
        version = campos.get('VERSION_ID')
        codename = campos.get('VERSION_CODENAME')
        if not ident or not re.fullmatch(r'[a-z0-9._-]+', ident):
            raise ValueError()
        if version is not None and not re.fullmatch(r'[0-9]+(?:\.[0-9]+)*', version):
            raise ValueError()
        if codename is not None and not re.fullmatch(r'[a-z0-9._-]+', codename):
            raise ValueError()
        resultado.update(id=ident, version_id=version, version_codename=codename)
        soportado = (ident == 'fedora' and version is not None or
                     ident == 'debian' and version == '13')
        resultado.update(estado='soportado' if soportado else 'no_soportado',
                         motivo=None if soportado else 'distribucion_o_version_no_soportada')
    except (ValueError, TypeError):
        resultado['motivo'] = 'datos_invalidos'
    return resultado
