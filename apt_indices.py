"""Objetivos binarios locales. Solo se llama desde el hijo ya aislado de APT.

Dos invocaciones fijas de indextargets: universo y selección según Release.
No ejecuta update ni adquiere índices. Los nombres/rutas nunca se publican.
"""
import ctypes
import hashlib
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import time

from auditoria_debian import _finalizar_proceso

MAX_BYTES = 4 * 1024 * 1024
MAX_LINEA = 16384
MAX_INDICES = 10000
MAX_STDERR = 8192
MAX_SEGUNDOS = 15
COMANDO = ('/usr/bin/apt-get', '-o', 'Dir::State::status=/var/lib/dpkg/status',
           '-o', 'Dir::Cache::pkgcache=', '-o', 'Debug::NoLocking=true', 'indextargets')


class ComprobacionFallida(Exception):
    pass


def _ejecutar(sin_release, deadline, limite_bytes=None):
    # El descendiente hereda todas las restricciones. PDEATHSIG evita dejarlo
    # vivo si el supervisor agota el plazo y termina el lector Python.
    padre = os.getpid()
    limite_bytes = MAX_BYTES if limite_bytes is None else min(limite_bytes, MAX_BYTES)
    def al_nacer():
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != padre:
            os._exit(78)
    entorno = dict(os.environ, LC_ALL='C', PYTHONDONTWRITEBYTECODE='1')
    for variable in ('APT_CONFIG', 'DPKG_ROOT', 'DPKG_ADMINDIR'):
        entorno.pop(variable, None)
    comando = list(COMANDO) + (['--no-release-info'] if sin_release else [])
    proceso = None
    codigo = None
    recogido = False
    salida = bytearray()
    errores = 0
    entrada = open(os.devnull, 'rb')
    try:
        # DEVNULL de subprocess abre O_RDWR, que Landlock deniega. Aquí solo
        # se abre lectura; no se amplían permisos para /dev/null.
        proceso = subprocess.Popen(comando, stdin=entrada,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=entorno,
            preexec_fn=al_nacer)
        with selectors.DefaultSelector() as selector:
            selector.register(proceso.stdout, selectors.EVENT_READ, 'stdout')
            selector.register(proceso.stderr, selectors.EVENT_READ, 'stderr')
            while selector.get_map():
                espera = deadline - 1 - time.monotonic()
                if espera <= 0:
                    raise ComprobacionFallida()
                eventos = selector.select(espera)
                if not eventos:
                    raise ComprobacionFallida()
                for clave, _ in eventos:
                    bloque = os.read(clave.fd, 4096)
                    if not bloque:
                        selector.unregister(clave.fileobj)
                    elif clave.data == 'stderr':
                        errores += len(bloque)
                    else:
                        salida.extend(bloque)
                    if len(salida) + errores > limite_bytes or errores > MAX_STDERR:
                        raise ComprobacionFallida()
        codigo = proceso.wait(timeout=max(0, deadline - 1 - time.monotonic()))
        recogido = True
        if codigo or errores:
            raise ComprobacionFallida()
        return bytes(salida)
    finally:
        entrada.close()
        if proceso is not None:
            _, fallo = _finalizar_proceso(proceso, deadline, recogido, codigo)
            if fallo:
                raise ComprobacionFallida()


def _registros(texto):
    """Deb822 acotado; admite continuaciones Release, rechaza duplicados."""
    if len(texto) > MAX_BYTES:
        raise ValueError('limite_bytes')
    campos = {}
    ultimo = None
    for linea in texto.splitlines() + ['']:
        if len(linea) > MAX_LINEA or any(ord(c) < 32 and c != '\t' for c in linea):
            raise ValueError('linea_invalida')
        if not linea:
            if campos:
                yield campos
                campos = {}
                ultimo = None
        elif linea[0].isspace():
            if ultimo is None:
                raise ValueError('continuacion_invalida')
            campos[ultimo] += '\n' + linea.strip()
        else:
            clave, sep, valor = linea.partition(':')
            if not sep or not re.fullmatch(r'[A-Za-z][A-Za-z0-9-]*', clave):
                raise ValueError('campo_invalido')
            clave = clave.lower()
            if clave in campos:
                raise ValueError('campo_duplicado')
            campos[clave] = valor.strip()
            ultimo = clave


def parsear_objetivos(contenido, directorio):
    objetivos = {}
    for numero, dato in enumerate(_registros(contenido.decode('utf-8'))):
        if numero >= MAX_INDICES:
            raise ValueError('limite_indices')
        if 'identifier' not in dato:
            raise ValueError('objetivo_sin_tipo')
        if dato['identifier'] != 'Packages':
            continue
        for clave in ('metakey', 'base-uri', 'uri', 'filename', 'optional', 'target-of'):
            if not dato.get(clave) or '\n' in dato[clave]:
                raise ValueError('objetivo_incompleto')
        key = dato['metakey']
        if (key != 'Packages' and not re.fullmatch(r'[a-z0-9][a-z0-9+./-]*/binary-[a-z0-9-]+/Packages', key)):
            raise ValueError('metakey_invalida')
        if '..' in key.split('/') or dato['optional'] not in ('yes', 'no') or dato['target-of'] != 'deb':
            raise ValueError('objetivo_invalido')
        if key != 'Packages' and dato.get('architecture') != key.rsplit('/', 2)[1][7:]:
            raise ValueError('arquitectura_incoherente')
        base = dato['base-uri']
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*:', base) or not base.endswith('/') or dato['uri'] != base + key:
            raise ValueError('uri_incoherente')
        ruta = Path(dato['filename'])
        if not ruta.is_absolute() or ruta.parent != directorio or ruta.name in ('.', '..'):
            raise ValueError('ruta_invalida')
        identidad = (base, key)
        if identidad in objetivos:
            raise ValueError('objetivo_duplicado')
        objetivos[identidad] = dato
    return objetivos


def _leer_release(base, directorio):
    import apt_pkg
    # Una única ubicación de metadatos, derivada por APT, sin ejecutar URIs.
    nombre = apt_pkg.uri_to_filename(base + 'InRelease')
    ruta = directorio / nombre
    if not ruta.is_file():
        ruta = directorio / apt_pkg.uri_to_filename(base + 'Release')
    with ruta.open('rb') as fuente:
        contenido = fuente.read(MAX_BYTES + 1)
    if len(contenido) > MAX_BYTES:
        raise ValueError('release_excesivo')
    texto = contenido.decode('utf-8')
    if texto.startswith('-----BEGIN PGP SIGNED MESSAGE-----\n'):
        texto = texto.split('\n\n', 1)[1].split('\n-----BEGIN PGP SIGNATURE-----', 1)[0]
        texto = '\n'.join(l[2:] if l.startswith('- ') else l for l in texto.splitlines())
    registros = list(_registros(texto))
    if len(registros) != 1 or not registros[0].get('sha256'):
        raise ValueError('release_incompleto')
    dato = registros[0]
    hashes = {}
    for linea in dato['sha256'].splitlines():
        if not linea.strip():
            continue
        partes = linea.split()
        if len(partes) != 3:
            raise ValueError('hash_invalido')
        sha, tamano, key = partes
        if (not re.fullmatch('[0-9a-fA-F]{64}', sha) or not tamano.isdecimal()
                or len(tamano) > 20 or key in hashes):
            raise ValueError('hash_invalido')
        hashes[key] = (int(tamano), sha.lower())
    return dato, hashes, ruta, hashlib.sha256(contenido).digest()


def _disponible(ruta):
    try:
        with open(ruta, 'rb') as fuente:
            return stat.S_ISREG(os.fstat(fuente.fileno()).st_mode)
    except (FileNotFoundError, PermissionError, IsADirectoryError):
        return False


def clasificar(potenciales, efectivos, leer_release, disponible):
    if not set(efectivos) <= set(potenciales):
        raise ValueError('seleccion_incoherente')
    resultado = dict(configurados=len(efectivos), presentes=0, ausentes=0,
        necesarios=0, opcionales=0, no_aplicables=0, declarados_vacios=0,
        indeterminados=0, seleccion_verificada=True)
    releases = {}
    for base, key in potenciales:
        if base not in releases:
            try:
                releases[base] = leer_release(base)
            except (OSError, ValueError, UnicodeError, IndexError):
                releases[base] = None
        release = releases[base]
        seleccionado = efectivos.get((base, key))
        if seleccionado:
            resultado['opcionales' if seleccionado['optional'] == 'yes' else 'necesarios'] += 1
            presente = disponible(seleccionado['filename'])
            resultado['presentes' if presente else 'ausentes'] += 1
        if release is None:
            resultado['indeterminados'] += 1
            continue
        dato, hashes = release[:2]
        arch = potenciales[(base, key)].get('architecture')
        excluido = (arch and dato.get('architectures') and arch not in dato['architectures'].split()) or (
            arch == 'all' and 'Packages' in dato.get('no-support-for-architecture-all', '').split())
        entrada = hashes.get(key)
        # Si el tamaño sin comprimir no figura no inferimos vacío por el tamaño
        # de un archivo comprimido. Las exclusiones requieren evidencia positiva.
        if seleccionado:
            if excluido or entrada is None or entrada[0] == 0:
                resultado['indeterminados'] += 1
        elif excluido:
            resultado['no_aplicables'] += 1
        elif entrada == (0, hashlib.sha256(b'').hexdigest()):
            resultado['declarados_vacios'] += 1
        else:
            resultado['indeterminados'] += 1
    resultado['seleccion_verificada'] = not resultado['indeterminados']
    return resultado


def seleccionar_indices():
    """Ante cualquier fallo se desconoce la integridad; jamás implica cero updates."""
    desconocido = dict(configurados=0, presentes=0, ausentes=0, necesarios=0,
        opcionales=0, no_aplicables=0, declarados_vacios=0, indeterminados=0,
        seleccion_verificada=False)
    try:
        import apt_pkg
        config = apt_pkg.config
        directorio = Path(config.find_dir('Dir::State::lists'))
        if not directorio.is_absolute():
            raise ValueError('directorio_invalido')
        deadline = time.monotonic() + MAX_SEGUNDOS
        contenido = _ejecutar(True, deadline)
        potenciales = parsear_objetivos(contenido, directorio)
        restantes = MAX_BYTES - len(contenido)
        efectivos = parsear_objetivos(_ejecutar(False, deadline, restantes), directorio)
        leidos = {}
        def leer(base):
            leidos[base] = _leer_release(base, directorio)
            return leidos[base]
        resultado = clasificar(potenciales, efectivos, leer, _disponible)
        # Una selección vacía sin universo no demuestra cobertura.
        if not potenciales:
            resultado['seleccion_verificada'] = False
        # No mezclar una selección con Release que cambió durante la lectura.
        for _, _, ruta, huella in leidos.values():
            with ruta.open('rb') as fuente:
                contenido = fuente.read(MAX_BYTES + 1)
            if hashlib.sha256(contenido).digest() != huella:
                raise ValueError('release_cambio')
        return resultado, {d['filename'] for d in efectivos.values()}
    except (ComprobacionFallida, OSError, ValueError, UnicodeError,
            subprocess.SubprocessError, MemoryError):
        return desconocido, set()
