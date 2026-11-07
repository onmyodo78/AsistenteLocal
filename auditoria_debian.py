"""Inventario dpkg acotado y composición con candidatos locales de apt_debian.

consultar_inventario conserva su contrato versión 1 y solo consulta dpkg.
consultar_auditoria devuelve versión 2 con estados independientes de dpkg y APT.
"""
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import sys
import time

FORMATO = '${Package}\t${Architecture}\t${Version}\t${Status}\t${source:Package}\t${source:Version}\n'
COMANDO = ('dpkg-query', '--admindir=/var/lib/dpkg', '--show', '--showformat=' + FORMATO)
MAX_BYTES = 4 * 1024 * 1024
MAX_REGISTROS = 25000
MAX_LINEA = 2048
MAX_STDERR = 8192
MAX_SEGUNDOS = 15
MAX_RESUMEN = 5000
NOMBRE = re.compile(r'[a-z0-9][a-z0-9+.-]*\Z')
ARQUITECTURA = re.compile(r'[a-z0-9][a-z0-9-]*\Z')
VERSION = re.compile(r'(?:[0-9]+:)?[0-9][A-Za-z0-9.+:~\-]*\Z')
ESTADOS = frozenset(('not-installed', 'config-files', 'half-installed', 'unpacked',
                    'half-configured', 'triggers-awaited', 'triggers-pending', 'installed'))


def parsear_fila(linea):
    campos = linea.split('\t')
    if len(campos) != 6:
        raise ValueError('fila_dpkg_invalida')
    nombre, arch, version, estado, fuente, version_fuente = campos
    palabras = estado.split(' ')
    if (not NOMBRE.fullmatch(nombre) or len(palabras) != 3 or
        palabras[0] not in ('unknown', 'install', 'hold', 'deinstall', 'purge') or
        palabras[1] not in ('ok', 'reinstreq') or palabras[2] not in ESTADOS):
        raise ValueError('estado_dpkg_invalido')
    for valor, patron in ((arch, ARQUITECTURA), (version, VERSION),
                           (fuente, NOMBRE), (version_fuente, VERSION)):
        if valor and not patron.fullmatch(valor):
            raise ValueError('campo_dpkg_invalido')
    if palabras[2] != 'not-installed' and (not arch or not version):
        raise ValueError('identidad_dpkg_incompleta')
    categoria = ('instalado' if palabras[2] == 'installed' and palabras[1] == 'ok' else
                 'residual' if palabras[2] == 'config-files' else
                 'no_instalado' if palabras[2] == 'not-installed' else 'incompleto')
    return dict(nombre_binario=nombre, arquitectura=arch or None, version=version or None,
                estado_instalacion=estado, categoria=categoria,
                nombre_fuente=fuente or None, version_fuente=version_fuente or None)


class Acumulador:
    def __init__(self):
        self.registros = []
        self.identidades = set()
        self.pendiente = bytearray()
        self.bytes = self.stderr_bytes = 0
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
            return
        self.pendiente.extend(bloque)
        while b'\n' in self.pendiente:
            linea, _, resto = self.pendiente.partition(b'\n')
            self.pendiente = bytearray(resto)
            if len(linea) > MAX_LINEA:
                self.motivo = 'limite_linea'
                return
            if len(self.registros) >= MAX_REGISTROS:
                self.motivo = 'limite_registros'
                return
            try:
                registro = parsear_fila(linea.decode('utf-8'))
            except (ValueError, UnicodeError):
                self.motivo = 'formato_invalido'
                return
            identidad = (registro['nombre_binario'], registro['arquitectura'])
            if identidad in self.identidades:
                self.motivo = 'registro_duplicado'
                return
            self.identidades.add(identidad)
            self.registros.append(registro)
        if len(self.pendiente) > MAX_LINEA:
            self.motivo = 'limite_linea'


def comando_aislado():
    return [sys.executable, '-B', str(Path(__file__).with_name('auditoria_aislamiento.py').resolve()), 'dpkg']


def _finalizar_proceso(proceso, deadline, recogido, codigo):
    """Recoger y cerrar sin rebasar el presupuesto reservado de la adquisición.

    No usar el contexto Popen: su __exit__ puede esperar sin límite. Un proceso
    que no se recoge sigue siendo un fallo explícito; no se presume su limpieza.
    La recogida ulterior de ese proceso no queda garantizada por esta función.
    """
    fallo = None
    try:
        if not recogido:
            observado = proceso.poll()
            if observado is not None:
                codigo = observado
            else:
                try:
                    proceso.kill()
                except ProcessLookupError:
                    pass  # Puede haber terminado entre poll y kill: aún recoger.
                except OSError:
                    fallo = 'error_recogida'
                codigo = proceso.wait(timeout=max(0, deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        codigo, fallo = None, 'terminacion_no_confirmada'
    except OSError:
        codigo, fallo = None, 'error_recogida'
    finally:
        # Intentar ambos cierres aunque falle el primero; sin mensajes originales.
        for archivo in (proceso.stdout, proceso.stderr):
            try:
                archivo.close()
            except OSError:
                fallo = fallo or 'error_recogida'
    return codigo, fallo


def consultar_inventario(timeout):
    inicio = time.monotonic()
    presupuesto = min(MAX_SEGUNDOS, timeout)
    deadline = inicio + presupuesto
    # Reservar hasta un segundo PARA limpieza, nunca añadirlo al plazo total.
    fin_captura = deadline - min(1.0, max(0, presupuesto) / 4)
    acumulador = Acumulador()
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
            while selector.get_map() and acumulador.motivo is None:
                espera = fin_captura - time.monotonic()
                if espera <= 0:
                    raise TimeoutError()
                eventos = selector.select(espera)
                if not eventos:
                    raise TimeoutError()
                for clave, _ in eventos:
                    bloque = os.read(clave.fd, min(4096, MAX_BYTES-acumulador.bytes+1))
                    if not bloque:
                        selector.unregister(clave.fileobj)
                    else:
                        acumulador.recibir(clave.data, bloque)
                    if acumulador.motivo:
                        break
        if acumulador.motivo is None:
            codigo = proceso.wait(timeout=max(0, fin_captura-time.monotonic()))
            recogido = True
    except (TimeoutError, subprocess.TimeoutExpired):
        acumulador.motivo = 'tiempo_agotado'
    except FileNotFoundError:
        acumulador.motivo = 'ejecutable_ausente'
    except PermissionError:
        acumulador.motivo = 'permiso_denegado'
    except OSError:
        acumulador.motivo = 'error_sistema'
    finally:
        if proceso is not None:
            codigo, fallo_limpieza = _finalizar_proceso(proceso, deadline, recogido, codigo)
            if fallo_limpieza is not None:
                acumulador.motivo = fallo_limpieza
    if acumulador.motivo is None:
        acumulador.motivo = ('aislamiento_no_disponible' if codigo == 78 else
            'ejecutable_ausente' if codigo == 69 else 'error_comando' if codigo else
            'avisos_no_interpretados' if acumulador.stderr_bytes else
            'fila_incompleta' if acumulador.pendiente else None)
    completo = acumulador.motivo is None
    recuentos = {categoria: sum(r['categoria'] == categoria for r in acumulador.registros)
                 for categoria in ('instalado', 'incompleto', 'residual', 'no_instalado')}
    return dict(version=1, backend='debian', herramienta='auditoria_seguridad',
        alcance='inventario_local_dpkg', estado_seguridad='no_evaluada',
        estado_adquisicion='completo' if completo else 'parcial' if acumulador.registros else 'error',
        inventario_completo=completo, inventario_dpkg=acumulador.registros,
        fuente=dict(nombre='dpkg-query', codigo=codigo, motivo=acumulador.motivo,
                    bytes=acumulador.bytes, stderr_bytes=acumulador.stderr_bytes,
                    duracion_s=round(time.monotonic()-inicio, 6)),
        recuentos_recogidos=recuentos,
        total_instalados=recuentos['instalado'] if completo else None,
        actualizaciones='no_implementado', cve='no_disponible', avisos_seguridad='no_disponible',
        limitaciones=['Solo inventario local; no es una auditoría de vulnerabilidades.',
                      'Lectura no transaccional; no verifica integridad ni actualización de paquetes.'])


def resumen(datos, limite):
    vista = {k: v for k, v in datos.items() if k != 'inventario_dpkg'}
    if isinstance(vista.get('actualizaciones'), dict):
        vista['actualizaciones'] = {k: v for k, v in vista['actualizaciones'].items()
                                   if k != 'candidatos'}
    vista['inventario_excluido'] = True
    texto = json.dumps(vista, ensure_ascii=True, separators=(',', ':'))
    if len(texto) <= min(limite, MAX_RESUMEN):
        return texto
    minimo = json.dumps(dict(version=1, backend='debian', herramienta='auditoria_seguridad',
        estado_presentacion='omitido_por_limite', estado_seguridad='no_evaluada'), separators=(',', ':'))
    return minimo if len(minimo) <= min(limite, MAX_RESUMEN) else ''


def consultar_auditoria(timeout):
    """Inventario y candidatos independientes bajo un plazo compartido."""
    from apt_debian import consultar_actualizaciones
    inicio = time.monotonic()
    datos = consultar_inventario(timeout)
    actualizaciones = consultar_actualizaciones(max(0, timeout-(time.monotonic()-inicio)))
    datos['version'] = 2
    datos['alcance'] = 'inventario_y_candidatos_locales'
    datos['estado_inventario'] = datos['estado_adquisicion']
    # Las fuentes son secuenciales: detectar discrepancias sin inventar una instantánea.
    if datos['inventario_completo'] and actualizaciones['estado_adquisicion'] == 'completo':
        instalados = {(r['nombre_binario'], r['arquitectura']): r['version']
                      for r in datos['inventario_dpkg'] if r['categoria'] == 'instalado'}
        observados = {(r['nombre_binario'], r['arquitectura']): r['instalada']
                      for r in actualizaciones['candidatos']}
        if instalados != observados:
            actualizaciones.update(estado_adquisicion='parcial', motivo='inventarios_no_coincidentes',
                                   total_posibles=None)
    if not datos['inventario_completo']:
        actualizaciones['total_posibles'] = None
    datos['actualizaciones'] = actualizaciones
    if datos['estado_inventario'] == actualizaciones['estado_adquisicion'] == 'completo':
        datos['estado_adquisicion'] = 'completo'
    else:
        datos['estado_adquisicion'] = ('error' if datos['estado_inventario'] ==
            actualizaciones['estado_adquisicion'] == 'error' else 'parcial')
    return datos


class ResultadoDebian(str):
    def __new__(cls, datos, limite):
        instancia = super().__new__(cls, resumen(datos, limite))
        instancia._instantanea = json.dumps(datos, ensure_ascii=True, separators=(',', ':'))
        return instancia

    @property
    def datos(self):
        return json.loads(self._instantanea)

    def ajustar(self, limite):
        return resumen(self.datos, limite)
