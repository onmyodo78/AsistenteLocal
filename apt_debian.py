"""Candidatos APT locales mediante python3-apt, únicamente en modo aislado.

No usa Acquire, DepCache, PackageManager, update ni resolución de dependencias.
La candidata procede de Policy; una versión superior no garantiza instalación.
"""
import json
import errno
import re
import os
from pathlib import Path
import selectors
import subprocess
import sys
import time

from auditoria_debian import NOMBRE, ARQUITECTURA, VERSION, _finalizar_proceso
from apt_indices import seleccionar_indices

MAX_BYTES = 4 * 1024 * 1024
MAX_LINEA = 16384
MAX_REGISTROS = 25000
MAX_STDERR = 8192
MAX_SEGUNDOS = 15
MAX_INDICES = 10000
MAX_ORIGENES = 16
EDAD_AVISO = 7 * 86400


# Protocolo interno: solo etiquetas cerradas; el mensaje nunca se emite.
ETAPAS = frozenset((
    'entorno', 'init_config', 'configuracion', 'init_system', 'abrir_cache',
    'crear_policy', 'preparar_preferencias', 'ruta_preferencias', 'existe_preferencias',
    'leer_preferencias', 'ruta_preferencias_d', 'existe_preferencias_d',
    'leer_preferencias_d', 'crear_sources', 'leer_sources', 'leer_indices',
    'enumerar_indices', 'propiedades_indice', 'enumerar_archivos', 'buscar_indice',
    'stat_indice', 'resumir_indices', 'iterar_paquetes', 'leer_paquete',
    'seleccionar_candidata', 'procedencia_candidata', 'comparar_versiones',
    'prioridad_candidata', 'validar_registro', 'serializar_indices', 'emitir_indices',
    'serializar_paquete', 'emitir_paquete', 'serializar_fin', 'emitir_fin'))
EXCEPCIONES = (MemoryError, AttributeError, TypeError, KeyError, ValueError, OSError, SystemError)
RELACIONES = frozenset(('permisos', 'datos_ausentes', 'api_posible', 'recursos', 'datos_o_limites',
                       'biblioteca_apt_indeterminada', 'sistema_indeterminado'))
PREFIJO_DIAGNOSTICO = 'APT_DIAGNOSTICO '
CATEGORIAS_MENSAJE = frozenset(('permisos', 'apertura_archivo', 'temporal', 'memoria',
                               'configuracion', 'datos_invalidos', 'indeterminado'))
PATRONES_MENSAJE = (
    ('permisos', r'\((?:1: Operation not permitted|13: Permission denied)\)(?=$|[,\n])'),
    ('apertura_archivo', r'(?:^|[,\n])\s*(?:E:)?(?:Could not open file|Unable to open file)\b'),
    ('temporal', r'(?:^|[,\n])\s*(?:E:)?(?:Could not create temporary file|Unable to mkstemp)\b'),
    ('memoria', r'(?:^|[,\n])\s*(?:E:)?(?:Dynamic MMap ran out of room|Couldn.t make mmap of [0-9]+ bytes|Cannot allocate memory)\b'),
    ('configuracion', r'(?:^|[,\n])\s*(?:E:)?(?:Syntax error|Malformed entry|Malformed line)\b'),
    ('datos_invalidos', r'(?:^|[,\n])\s*(?:E:)?(?:Encountered a section with no Package: header|Encountered a section with no Package header)\b'),
)


def _clasificar_mensaje(exc):
    # Uso exclusivo en SystemError. No conservar ni devolver el texto original.
    try:
        mensaje = str(exc)
        if len(mensaje) > MAX_STDERR:
            return 'indeterminado'
        coincidencias = {categoria for categoria, patron in PATRONES_MENSAJE
                        if re.search(patron, mensaje)}
        if coincidencias == {'temporal', 'permisos'}:
            return 'permisos'
        return coincidencias.pop() if len(coincidencias) == 1 else 'indeterminado'
    except Exception:
        return 'indeterminado'


def _etapa(contexto, etapa):
    if contexto is not None:
        contexto['etapa'] = etapa


def _diagnostico(etapa, exc):
    categoria = next(clase.__name__ for clase in EXCEPCIONES if isinstance(exc, clase))
    codigo = exc.errno if isinstance(exc, OSError) and type(exc.errno) is int else None
    codigo = codigo if codigo in errno.errorcode else None
    relacion = ('permisos' if codigo in (errno.EPERM, errno.EACCES) else
        'datos_ausentes' if codigo in (errno.ENOENT, errno.ENOTDIR) else
        'api_posible' if isinstance(exc, (AttributeError, TypeError)) else
        'recursos' if isinstance(exc, MemoryError) or codigo == errno.ENOMEM else
        'datos_o_limites' if isinstance(exc, (ValueError, KeyError)) else
        'biblioteca_apt_indeterminada' if isinstance(exc, SystemError) else 'sistema_indeterminado')
    dato = dict(etapa=etapa, excepcion=categoria, errno=codigo,
                error_seguro=errno.errorcode.get(codigo), relacion=relacion)
    if isinstance(exc, SystemError):
        dato['categoria_mensaje'] = _clasificar_mensaje(exc)
    return dato


def _registrar_diagnostico(dato):
    print(PREFIJO_DIAGNOSTICO + json.dumps(dato, ensure_ascii=True, separators=(',', ':')),
          file=sys.stderr, flush=True)


def _reenviar_diagnostico(contenido, codigo):
    # Solo reemitir una línea validada y acotada. Nunca reenviar stderr original.
    if codigo != 72:
        return
    validos = []
    for linea in contenido.splitlines():
        try:
            if not linea.startswith(PREFIJO_DIAGNOSTICO.encode()) or len(linea) > 512:
                continue
            from auditoria_seguridad import sin_duplicados
            dato = json.loads(linea[len(PREFIJO_DIAGNOSTICO):], object_pairs_hook=sin_duplicados)
            claves = {'etapa', 'excepcion', 'errno', 'error_seguro', 'relacion'}
            if set(dato) not in (claves, claves | {'categoria_mensaje'}):
                continue
            if 'categoria_mensaje' in dato and (dato['excepcion'] != 'SystemError' or
                    dato['categoria_mensaje'] not in CATEGORIAS_MENSAJE):
                continue
            if (dato['etapa'] not in ETAPAS or
                dato['excepcion'] not in {c.__name__ for c in EXCEPCIONES} or
                dato['relacion'] not in RELACIONES):
                continue
            numero = dato['errno']
            if numero is not None and (type(numero) is not int or numero not in errno.errorcode):
                continue
            if dato['error_seguro'] != errno.errorcode.get(numero):
                continue
            validos.append(dato)
        except (ValueError, TypeError, KeyError, UnicodeError):
            continue
    if len(validos) == 1:
        _registrar_diagnostico(validos[0])


def _texto(valor):
    if not isinstance(valor, str) or len(valor) > 512 or any(ord(c) < 32 or ord(c) == 127 for c in valor):
        raise ValueError('metadato_invalido')
    return valor


def validar_registro(r):
    if not isinstance(r, dict):
        raise ValueError('registro_invalido')
    for campo, patron in (('nombre_binario', NOMBRE), ('arquitectura', ARQUITECTURA),
                          ('instalada', VERSION)):
        if not patron.fullmatch(_texto(r[campo])):
            raise ValueError('identidad_invalida')
    if r['candidata'] is not None and not VERSION.fullmatch(_texto(r['candidata'])):
        raise ValueError('version_invalida')
    if r['prioridad'] is not None and type(r['prioridad']) is not int:
        raise ValueError('prioridad_invalida')
    for campo in ('retenido', 'superior', 'posible_actualizacion'):
        if type(r[campo]) is not bool:
            raise ValueError('indicador_invalido')
    if r['instalable_garantizada'] is not False or r['posible_actualizacion'] != (r['superior'] and not r['retenido']):
        raise ValueError('instalabilidad_invalida')
    if r['candidata'] is None and (r['superior'] or r['prioridad'] is not None or r['origenes']):
        raise ValueError('candidata_ausente')
    if not isinstance(r['origenes'], list) or len(r['origenes']) > MAX_ORIGENES:
        raise ValueError('origenes_invalidos')
    for origen in r['origenes']:
        for campo in ('origen', 'archivo', 'componente', 'sitio'):
            _texto(origen[campo])
        if type(origen['confiable_segun_apt']) is not bool:
            raise ValueError('confianza_invalida')
    return r


def validar_seleccion(meta):
    if set(meta) != {'configurados', 'presentes', 'ausentes', 'edad_max_s',
            'potencialmente_desactualizados', 'frescura', 'umbral_aviso_s',
            'necesarios', 'opcionales', 'no_aplicables', 'declarados_vacios',
            'indeterminados', 'seleccion_verificada', 'integridad_local'}:
        raise ValueError('campos_indices_invalidos')
    for campo in ('necesarios', 'opcionales', 'no_aplicables', 'declarados_vacios', 'indeterminados'):
        if type(meta[campo]) is not int or not 0 <= meta[campo] <= MAX_INDICES:
            raise ValueError('seleccion_invalida')
    if (type(meta['seleccion_verificada']) is not bool or
            meta['necesarios'] + meta['opcionales'] != meta['configurados'] or
            (meta['seleccion_verificada'] and meta['indeterminados'])):
        raise ValueError('seleccion_incoherente')
    esperado = ('desconocida' if not meta['seleccion_verificada'] else
                'parcial' if meta['ausentes'] else 'completa')
    if meta['integridad_local'] != esperado:
        raise ValueError('integridad_incoherente')


def _indices(cache, sources, ahora, contexto=None):
    _etapa(contexto, 'enumerar_indices')
    seleccion, archivos = seleccionar_indices()
    edades = []
    cargados = set()
    _etapa(contexto, 'enumerar_archivos')
    for numero, archivo in enumerate(cache.file_list):
        if numero >= MAX_INDICES:
            raise ValueError('limite_indices')
        if archivo.index_type != 'Debian Package Index':
            continue
        cargados.add(archivo.filename)
        _etapa(contexto, 'buscar_indice')
        indice = sources.find_index(archivo)
        if indice is not None and indice.exists and archivo.filename in archivos:
            _etapa(contexto, 'stat_indice')
            edades.append(ahora - os.stat(archivo.filename).st_mtime)
    _etapa(contexto, 'resumir_indices')
    if cargados - archivos or len(cargados & archivos) < seleccion['presentes']:
        seleccion['seleccion_verificada'] = False
    integridad = ('desconocida' if not seleccion['seleccion_verificada'] else
                  'parcial' if seleccion['ausentes'] else 'completa')
    return dict(seleccion, integridad_local=integridad,
        edad_max_s=int(max(edades)) if edades else None,
        potencialmente_desactualizados=not edades or min(edades) < 0 or max(edades) > EDAD_AVISO,
        frescura='no_verificada', umbral_aviso_s=EDAD_AVISO)


def _registros(cache, policy, sources, apt, contexto=None):
    _etapa(contexto, 'iterar_paquetes')
    for paquete in cache.packages:
        _etapa(contexto, 'leer_paquete')
        instalada = paquete.current_ver
        if (instalada is None or paquete.current_state != apt.CURSTATE_INSTALLED or
                paquete.inst_state not in (apt.INSTSTATE_OK, apt.INSTSTATE_HOLD)):
            continue
        _etapa(contexto, 'seleccionar_candidata')
        candidata = policy.get_candidate_ver(paquete)
        origenes = []
        if candidata is not None:
            _etapa(contexto, 'procedencia_candidata')
            for archivo, _ in candidata.file_list:
                indice = sources.find_index(archivo)
                if indice is None:
                    continue  # El archivo de estado dpkg no es un repositorio.
                origen = dict(origen=archivo.origin, archivo=archivo.archive,
                    componente=archivo.component, sitio=archivo.site,
                    confiable_segun_apt=bool(indice.is_trusted))
                if origen not in origenes:
                    origenes.append(origen)
                if len(origenes) > MAX_ORIGENES:
                    raise ValueError('limite_origenes')
        retenido = paquete.selected_state == apt.SELSTATE_HOLD
        _etapa(contexto, 'comparar_versiones')
        superior = candidata is not None and apt.version_compare(candidata.ver_str, instalada.ver_str) > 0
        _etapa(contexto, 'prioridad_candidata')
        prioridad = policy.get_priority(candidata) if candidata else None
        _etapa(contexto, 'validar_registro')
        yield validar_registro(dict(nombre_binario=paquete.name, arquitectura=instalada.arch,
            instalada=instalada.ver_str, candidata=candidata.ver_str if candidata else None,
            prioridad=prioridad,
            retenido=retenido, superior=superior, posible_actualizacion=superior and not retenido,
            instalable_garantizada=False, origenes=origenes))


def emitir_local():
    """Solo lo invoca el modo fijo apt-local DESPUÉS de restringir()."""
    try:
        import apt_pkg
    except ImportError:
        return 70
    contexto = {'etapa': 'entorno'}
    try:
        # No heredar selección arbitraria de configuración o raíz del proceso padre.
        for variable in ('APT_CONFIG', 'DPKG_ROOT', 'DPKG_ADMINDIR'):
            os.environ.pop(variable, None)
        _etapa(contexto, 'init_config')
        apt_pkg.init_config()
        _etapa(contexto, 'configuracion')
        config = apt_pkg.config
        if config.find('RootDir') not in ('', '/'):
            return 71
        config.set('Dir::State::status', '/var/lib/dpkg/status')
        config.set('Dir::Cache::pkgcache', '')
        config.set('Debug::NoLocking', 'true')
        _etapa(contexto, 'init_system')
        apt_pkg.init_system()
        _etapa(contexto, 'abrir_cache')
        cache = apt_pkg.Cache(None)
        _etapa(contexto, 'crear_policy')
        policy = apt_pkg.Policy(cache)
        _etapa(contexto, 'preparar_preferencias')
        for clave, lector in (('Dir::Etc::preferences', policy.read_pinfile),
                               ('Dir::Etc::preferencesparts', policy.read_pindir)):
            sufijo = '' if clave.endswith('preferences') else '_d'
            _etapa(contexto, 'ruta_preferencias' + sufijo)
            ruta = config.find_file(clave) if not sufijo else config.find_dir(clave)
            _etapa(contexto, 'existe_preferencias' + sufijo)
            existe = Path(ruta).exists()
            _etapa(contexto, 'leer_preferencias' + sufijo)
            if existe and not lector(ruta):
                return 71
        _etapa(contexto, 'crear_sources')
        sources = apt_pkg.SourceList()
        _etapa(contexto, 'leer_sources')
        if not sources.read_main_list():
            return 71
        _etapa(contexto, 'leer_indices')
        metadata = _indices(cache, sources, time.time(), contexto)
        total_bytes = 0
        def emitir(dato):
            nonlocal total_bytes
            tipo = dato['tipo']
            _etapa(contexto, 'serializar_' + tipo)
            texto = json.dumps(dato, ensure_ascii=True, separators=(',', ':'))
            total_bytes += len(texto)+1
            if len(texto) > MAX_LINEA or total_bytes > MAX_BYTES:
                raise ValueError('limite_salida')
            _etapa(contexto, 'emitir_' + tipo)
            print(texto, flush=True)
        emitir(dict(tipo='indices', datos=metadata))
        if metadata['seleccion_verificada'] and not metadata['presentes']:
            return 67
        cantidad = 0
        _etapa(contexto, 'iterar_paquetes')
        for registro in _registros(cache, policy, sources, apt_pkg, contexto):
            if cantidad >= MAX_REGISTROS:
                return 73
            emitir(dict(tipo='paquete', datos=registro))
            cantidad += 1
        emitir(dict(tipo='fin', registros=cantidad))
        return 0
    except (OSError, ValueError, TypeError, KeyError, AttributeError, SystemError, MemoryError) as exc:
        try:
            _registrar_diagnostico(_diagnostico(contexto['etapa'], exc))
        except (OSError, ValueError, MemoryError):
            pass  # El diagnóstico no cambia el código original ni provoca reintentos.
        return 72  # Sin errores originales: pueden contener rutas o configuración sensible.


class Acumulador:
    def __init__(self):
        self.indices = None
        self.registros = []
        self.identidades = set()
        self.fin = False
        self.bytes = self.stderr_bytes = 0
        self.error_acotado = bytearray()
        self.pendiente = bytearray()
        self.motivo = None

    def recibir(self, canal, bloque):
        self.bytes += len(bloque)
        if self.bytes > MAX_BYTES:
            self.motivo = 'limite_bytes'
            return
        if canal == 'stderr':
            self.stderr_bytes += len(bloque)
            if self.stderr_bytes > MAX_STDERR:
                self.motivo = 'limite_stderr'
            else:
                self.error_acotado.extend(bloque)
            return
        self.pendiente.extend(bloque)
        while b'\n' in self.pendiente:
            linea, _, resto = self.pendiente.partition(b'\n')
            self.pendiente = bytearray(resto)
            if len(linea) > MAX_LINEA:
                self.motivo = 'limite_linea'
                return
            try:
                from auditoria_seguridad import sin_duplicados
                dato = json.loads(linea, object_pairs_hook=sin_duplicados)
                if self.fin:
                    raise ValueError()
                if self.indices is None:
                    if dato['tipo'] != 'indices':
                        raise ValueError()
                    meta = dato['datos']
                    for campo in ('configurados', 'presentes', 'ausentes', 'umbral_aviso_s'):
                        if type(meta[campo]) is not int or not 0 <= meta[campo] <= 2**31:
                            raise ValueError()
                    edad = meta['edad_max_s']
                    if edad is not None and (type(edad) is not int or abs(edad) > 2**63):
                        raise ValueError()
                    if (meta['presentes']+meta['ausentes'] != meta['configurados'] or
                        type(meta['potencialmente_desactualizados']) is not bool or
                        meta['frescura'] != 'no_verificada'):
                        raise ValueError()
                    validar_seleccion(meta)
                    self.indices = meta
                elif dato['tipo'] == 'fin':
                    if type(dato['registros']) is not int or dato['registros'] != len(self.registros):
                        raise ValueError()
                    self.fin = True
                else:
                    if dato['tipo'] != 'paquete' or len(self.registros) >= MAX_REGISTROS:
                        raise ValueError()
                    r = validar_registro(dato['datos'])
                    identidad = (r['nombre_binario'], r['arquitectura'])
                    if identidad in self.identidades:
                        raise ValueError()
                    self.identidades.add(identidad)
                    self.registros.append(r)
            except (ValueError, UnicodeError, KeyError, TypeError, RecursionError):
                self.motivo = 'formato_invalido'
                return
        if len(self.pendiente) > MAX_LINEA:
            self.motivo = 'limite_linea'


def comando_aislado():
    return [sys.executable, '-B', str(Path(__file__).with_name('auditoria_aislamiento.py').resolve()), 'apt-local']


def consultar_actualizaciones(timeout):
    inicio = time.monotonic()
    presupuesto = min(MAX_SEGUNDOS, timeout)
    deadline = inicio + presupuesto
    # Reservar hasta un segundo PARA limpieza, nunca añadirlo al plazo total.
    fin_captura = deadline - min(1.0, max(0, presupuesto) / 4)
    a = Acumulador()
    codigo = None
    proceso = None
    recogido = False
    try:
        if timeout <= 0:
            raise TimeoutError()
        proceso = subprocess.Popen(comando_aislado(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   stdin=subprocess.DEVNULL)
        with selectors.DefaultSelector() as selector:
            selector.register(proceso.stdout, selectors.EVENT_READ, 'stdout')
            selector.register(proceso.stderr, selectors.EVENT_READ, 'stderr')
            while selector.get_map() and not a.motivo:
                espera = fin_captura-time.monotonic()
                if espera <= 0:
                    raise TimeoutError()
                eventos = selector.select(espera)
                if not eventos:
                    raise TimeoutError()
                for clave, _ in eventos:
                    bloque = os.read(clave.fd, min(4096, MAX_BYTES-a.bytes+1))
                    if bloque:
                        a.recibir(clave.data, bloque)
                    else:
                        selector.unregister(clave.fileobj)
                    if a.motivo:
                        break
        if not a.motivo:
            codigo = proceso.wait(timeout=max(0, fin_captura-time.monotonic()))
            recogido = True
    except (TimeoutError, subprocess.TimeoutExpired):
        a.motivo = 'tiempo_agotado'
    except FileNotFoundError:
        a.motivo = 'ejecutable_ausente'
    except PermissionError:
        a.motivo = 'permiso_denegado'
    except OSError:
        a.motivo = 'error_sistema'
    finally:
        if proceso is not None:
            codigo, fallo_limpieza = _finalizar_proceso(proceso, deadline, recogido, codigo)
            if fallo_limpieza is not None:
                a.motivo = fallo_limpieza
    if not a.motivo:
        a.motivo = {78:'aislamiento_no_disponible', 70:'python3_apt_no_disponible',
                    71:'configuracion_apt_no_disponible', 72:'consulta_apt_fallida',
                    73:'limite_registros', 67:'indices_ausentes'}.get(codigo)
        if not a.motivo:
            a.motivo = ('error_comando' if codigo else 'avisos_no_interpretados' if a.stderr_bytes else
                'salida_incompleta' if a.pendiente or not a.fin else
                'seleccion_indices_no_verificada' if a.indices and not a.indices['seleccion_verificada'] else
                'indices_ausentes' if not a.indices or not a.indices['presentes'] else
                'indices_parciales' if a.indices['ausentes'] else None)
    _reenviar_diagnostico(a.error_acotado, codigo)
    completo = a.motivo is None
    cantidades = dict(registros=len(a.registros), superiores=sum(r['superior'] for r in a.registros),
        retenidos=sum(r['retenido'] for r in a.registros),
        posibles=sum(r['posible_actualizacion'] for r in a.registros))
    return dict(version=1, fuente='apt_pkg.Policy', estado_adquisicion='completo' if completo else
        'parcial' if a.registros else 'error', motivo=a.motivo, codigo=codigo,
        duracion_s=round(time.monotonic()-inicio,6), bytes=a.bytes, stderr_bytes=a.stderr_bytes,
        indices=a.indices, candidatos=a.registros, recuentos_recogidos=cantidades,
        total_posibles=cantidades['posibles'] if completo else None,
        instalabilidad='no_comprobada', seguridad='no_evaluada',
        cobertura_aplicaciones='no_verificada',
        limitaciones=['Solo índices locales: frescura y cobertura no garantizadas.',
            'Integridad local completa no acredita actualidad ni cobertura de aplicaciones ajenas a los repositorios.',
            'Candidata superior no garantiza instalación; no se resuelven dependencias ni fases de despliegue.',
            'Retenciones excluidas de posibles actualizaciones; no se modifica su selección.',
            'La procedencia candidata no acredita el repositorio de instalación original.',
            'Procedencia según metadatos locales; no se revalida autenticidad ni caducidad Release.',
            'mtime es un indicio de antigüedad, no una fecha de publicación ni de sincronización completa.'])
