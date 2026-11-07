"""Auditoría local: parsers puros, sin red ni escrituras."""
import json
import re
import os
from pathlib import Path
import selectors
import subprocess
import sys
import time

FORMATO_RPM = '%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n'
DNF = ('dnf', '--cacheonly', '--no-plugins', '--setopt=logdir=/proc/self/fd',
       'updateinfo', 'list', '--security', '--json')
CONSULTAS = (
    ('uname', ('uname', '-r')),
    ('rpm', ('rpm', '-qa', '--qf', FORMATO_RPM)),
    ('kernels', ('rpm', '-q', 'kernel-core', '--qf', FORMATO_RPM)),
    ('pendientes', DNF + ('--available',)),
    ('instalados', DNF + ('--installed',)),
)
TOKEN = re.compile(r'[A-Za-z0-9_+.:~^%-]+\Z')


def token(valor):
    if not isinstance(valor, str) or not TOKEN.fullmatch(valor):
        raise ValueError('campo inválido')
    return valor


def inventario(texto):
    filas = []
    for linea in texto.splitlines():
        campos = linea.split('\t')
        if len(campos) != 5:
            raise ValueError('RPM inválido')
        nombre, epoch, version, release = map(token, campos[:4])
        # RPM también enumera pseudoentradas gpg-pubkey sin arquitectura.
        arch = None if nombre == 'gpg-pubkey' and campos[4] == '(none)' else token(campos[4])
        if not epoch.isascii() or not epoch.isdigit():
            raise ValueError('epoch inválido')
        filas.append(dict(nombre=nombre, epoch=int(epoch), version=version,
                          release=release, arquitectura=arch))
    if not filas:
        raise ValueError('inventario vacío')
    return sorted(filas, key=lambda p: (p['nombre'], p['arquitectura'] or '', p['version'], p['release']))


def sin_duplicados(pares):
    salida = {}
    for clave, valor in pares:
        if clave in salida:
            raise ValueError('clave duplicada')
        salida[clave] = valor
    return salida


def avisos(texto):
    filas = json.loads(texto, object_pairs_hook=sin_duplicados)
    if not isinstance(filas, list):
        raise ValueError('DNF inválido')
    grupos = {}
    for fila in filas:
        if not isinstance(fila, dict) or fila.get('type') != 'security':
            raise ValueError('aviso inválido')
        ident = token(fila.get('name'))
        paquete = token(fila.get('nevra'))
        grupos.setdefault(ident, set()).add(paquete)
    return [{'id': ident, 'paquetes': sorted(paquetes)}
            for ident, paquetes in sorted(grupos.items())]


def clave_kernel(version):
    # Subconjunto estable Fedora. No comparar lexicográficamente ni inventar
    # orden RPM para kernels personalizados, rc, epoch o sufijos desconocidos.
    match = re.fullmatch(r'(\d+)\.(\d+)\.(\d+)-(\d+)\.fc44\.([A-Za-z0-9_]+)', version)
    if not match:
        return None
    return tuple(map(int, match.groups()[:4])), match[5]


def normalizar(fuentes):
    datos = {}
    estados = {}
    parsers = {'uname': lambda s: token(s.strip()), 'rpm': inventario, 'kernels': inventario,
               'pendientes': avisos, 'instalados': avisos}
    for nombre, _ in CONSULTAS:
        fuente = fuentes[nombre]
        estados[nombre] = {k: fuente[k] for k in ('estado', 'codigo', 'motivo', 'duracion_s', 'stdout_bytes', 'stderr_bytes', 'registros_recogidos') if k in fuente}
        datos[nombre] = None
        if nombre == 'rpm' and 'registros' in fuente:
            datos[nombre] = fuente['registros'] if fuente['registros'] else None
            continue
        if fuente['estado'] == 'correcta':
            try:
                datos[nombre] = parsers[nombre](fuente['stdout'])
            except (ValueError, TypeError, KeyError, RecursionError):
                estados[nombre]['estado'] = 'formato_invalido'
    for nombre, valor in datos.items():
        if valor is not None:
            estados[nombre].setdefault('registros_recogidos', len(valor) if isinstance(valor, list) else 1)
    kernels = None
    nuevos = None
    if datos['kernels'] is not None:
        kernels = [p for p in datos['kernels'] if p['nombre'] == 'kernel-core']
        activo = clave_kernel(datos['uname'] or '')
        if activo and kernels:
            candidatos = [(p, clave_kernel(f"{p['version']}-{p['release']}.{p['arquitectura']}"))
                          for p in kernels]
            if all(clave and p['epoch'] == 0 for p, clave in candidatos):
                # Solo la arquitectura del kernel activo; otras no son arrancables aquí.
                nuevos = [f"{p['version']}-{p['release']}.{p['arquitectura']}"
                          for p, clave in candidatos if clave[1] == activo[1] and clave[0] > activo[0]]
    validas = sum(v['estado'] == 'correcta' for v in estados.values())
    return {
        'version': 1, 'herramienta': 'auditoria_seguridad',
        'estado_adquisicion': 'completo' if validas == len(CONSULTAS) else 'parcial' if any(v is not None for v in datos.values()) else 'error',
        'fuentes': estados, 'kernel_activo': datos['uname'],
        'kernels_instalados': kernels, 'kernels_mas_recientes_no_activos': nuevos,
        'reinicio_pendiente_kernel': None if nuevos is None else bool(nuevos),
        'inventario_rpm': datos['rpm'],
        'inventario_completo': estados['rpm']['estado'] == 'correcta',
        'avisos_pendientes': datos['pendientes'], 'avisos_instalados': datos['instalados'],
        'recuentos': {n: None if datos[k] is None or (k == 'rpm' and estados['rpm']['estado'] != 'correcta') else len(datos[k]) for n, k in
                     [('paquetes_rpm', 'rpm'), ('avisos_pendientes', 'pendientes'), ('avisos_instalados', 'instalados')]} | {'paquetes_rpm_recogidos': len(datos['rpm'] or [])},
        'limitaciones': [
            'Solo caché disponible; antigüedad y cobertura de repositorios no verificadas. Cero avisos no demuestra ausencia de vulnerabilidades.',
            'Avisos instalados: DNF observa versiones iguales o anteriores a las instaladas; no prueba historial ni que todos los paquetes del aviso estén instalados.',
            'Reinicio pendiente indica únicamente un kernel-core estable Fedora 44 más reciente instalado; no comprueba arranque, módulos, servicios ni necesidad global de reinicio.',
            'Orden de kernels desconocido fuera del formato estable numérico Fedora 44 o con epoch distinto de cero.',
            'Consultas secuenciales, no transaccionales. Sin correlación CVE ni inferencias de vulnerabilidad por versión.',
            'Inventario solo en memoria local, excluido de LM Studio; sin exportación ni persistencia automática.'],
    }


def serializar(datos, limite):
    copia = dict(datos)
    copia.setdefault('estado_presentacion', 'completo')
    texto = json.dumps(copia, ensure_ascii=True, separators=(',', ':'))
    if len(texto) <= limite:
        return texto
    # Conservar estados/recuentos; omitir colecciones completas, nunca cortar JSON.
    copia['estado_presentacion'] = 'parcial'
    copia['colecciones_omitidas'] = list(copia.get('colecciones_omitidas', []))
    for campo in ('inventario_rpm', 'avisos_instalados', 'avisos_pendientes',
                  'kernels_instalados', 'kernels_mas_recientes_no_activos'):
        copia[campo] = None
        if campo not in copia['colecciones_omitidas']:
            copia['colecciones_omitidas'].append(campo)
        texto = json.dumps(copia, ensure_ascii=True, separators=(',', ':'))
        if len(texto) <= limite:
            return texto
    texto = '{"herramienta":"auditoria_seguridad","estado_presentacion":"omitido_por_limite"}'
    return texto if len(texto) <= limite else ''


MAX_INVENTARIO_BYTES = 4 * 1024 * 1024
MAX_PAQUETES = 25000
MAX_LINEA = 1024
MAX_STDERR = 8192
MAX_RESUMEN = 5000
AVISO_LOG_DNF = ('Cannot open log file: (2) - No such file or directory '
                 '[/proc/self/fd/dnf5.log]. Dropping all logs. To redirect the log '
                 'file location use the "logdir" configuration option.\n')


def comando_aislado(modo):
    if modo not in ('rpm', 'pendientes', 'instalados'):
        raise ValueError('modo no autorizado')
    return [sys.executable, '-B', str(Path(__file__).with_name('auditoria_aislamiento.py').resolve()), modo]


def consultar_inventario(timeout):
    return _leer_inventario(comando_aislado('rpm'), timeout)


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


def _leer_inventario(comando, timeout):
    """Streaming limitado, conserva solo filas completas y validadas.

    El argumento comando es interno, solo se sustituye en pruebas sintéticas.
    No se acumula stdout crudo ni se alteran límites del ejecutor compartido.
    """
    inicio = time.monotonic()
    presupuesto = max(0, min(15, timeout))
    deadline = inicio + presupuesto
    fin_captura = deadline - min(1.0, presupuesto / 4)
    registros = []
    pendiente = bytearray()
    total = stderr_bytes = stdout_bytes = invalidas = 0
    motivo = None
    codigo = None
    proceso = None
    recogido = False
    fallo = None
    try:
        proceso = subprocess.Popen(comando, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   stdin=subprocess.DEVNULL)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(proceso.stdout, selectors.EVENT_READ, 'stdout')
                selector.register(proceso.stderr, selectors.EVENT_READ, 'stderr')
                while selector.get_map() and motivo is None:
                    espera = fin_captura - time.monotonic()
                    if espera <= 0:
                        motivo = 'tiempo_agotado'
                        break
                    eventos = selector.select(espera)
                    if not eventos:
                        motivo = 'tiempo_agotado'
                        break
                    for key, _ in eventos:
                        bloque = os.read(key.fd, min(4096, MAX_INVENTARIO_BYTES - total + 1))
                        if not bloque:
                            selector.unregister(key.fileobj)
                            continue
                        excede = total + len(bloque) > MAX_INVENTARIO_BYTES
                        disponible = MAX_INVENTARIO_BYTES - total
                        total += len(bloque)
                        if key.data == 'stderr':
                            stderr_bytes += len(bloque)
                            if stderr_bytes > MAX_STDERR or excede:
                                motivo = 'limite_bytes' if excede else 'limite_stderr'
                                break
                            continue
                        stdout_bytes += len(bloque)
                        pendiente.extend(bloque[:disponible])
                        while b'\n' in pendiente:
                            linea, _, resto = pendiente.partition(b'\n')
                            pendiente = bytearray(resto)
                            if len(linea) > MAX_LINEA:
                                motivo = 'limite_linea'
                                break
                            try:
                                registro = inventario(linea.decode('utf-8') + '\n')[0]
                            except (ValueError, UnicodeError):
                                invalidas += 1
                                continue
                            if len(registros) >= MAX_PAQUETES:
                                motivo = 'limite_registros'
                                break
                            registros.append(registro)
                        if motivo:
                            break
                        if len(pendiente) > MAX_LINEA:
                            motivo = 'limite_linea'
                            break
                        if excede:
                            motivo = 'limite_bytes'
                            break
            if motivo is None:
                try:
                    codigo = proceso.wait(timeout=max(0, fin_captura-time.monotonic()))
                    recogido = True
                except subprocess.TimeoutExpired:
                    motivo = 'tiempo_agotado'
        finally:
            codigo, fallo = _finalizar_proceso(proceso, deadline, recogido, codigo)
            if fallo:
                motivo = fallo
        if motivo is None:
            motivo = ('aislamiento_no_disponible' if codigo == 78 else
                      'ejecutable_ausente' if codigo == 69 else
                      'error_comando' if codigo else 'avisos_no_interpretados' if stderr_bytes else
                      'formato_invalido' if pendiente or invalidas or not registros else None)
    except FileNotFoundError:
        motivo = 'ejecutable_ausente'
    except PermissionError:
        motivo = 'permiso_denegado'
    except OSError:
        motivo = 'error_sistema'
    if fallo:
        motivo = fallo  # No ocultar recogida no confirmada por un error de lectura.
    return {'estado': 'correcta' if motivo is None else 'parcial' if registros else 'error',
            'codigo': codigo, 'registros': registros, 'motivo': motivo,
            'duracion_s': round(time.monotonic()-inicio, 6), 'stdout_bytes': stdout_bytes,
            'stderr_bytes': stderr_bytes, 'registros_recogidos': len(registros)}


def resumen_modelo(datos):
    """Vista compacta sin inventario ni nombres de paquetes de avisos."""
    return {
        'version': 2, 'herramienta': 'auditoria_seguridad',
        'estado_adquisicion': datos['estado_adquisicion'], 'fuentes': datos['fuentes'],
        'kernel_activo': datos['kernel_activo'],
        'reinicio_pendiente_kernel': datos['reinicio_pendiente_kernel'],
        'kernels_mas_recientes_no_activos': datos['kernels_mas_recientes_no_activos'],
        'recuentos': datos['recuentos'],
        'inventario_completo': datos.get('inventario_completo', False),
        'avisos_pendientes': None if datos['avisos_pendientes'] is None else
            [{'id': a['id'], 'paquetes': len(a['paquetes'])} for a in datos['avisos_pendientes'][:10]],
        'avisos_instalados': None if datos['avisos_instalados'] is None else
            [{'id': a['id'], 'paquetes': len(a['paquetes'])} for a in datos['avisos_instalados'][:5]],
        'vista_avisos_limitada': any(datos[k] is not None and len(datos[k]) > n
                                   for k,n in [('avisos_pendientes',10), ('avisos_instalados',5)]),
        'limitaciones': [
            'Solo caché; cobertura y antigüedad desconocidas. Cero avisos no garantiza seguridad.',
            'Instalados: versiones iguales o anteriores según DNF, sin prueba de historial ni cobertura total del aviso.',
            'Reinicio solo para kernel estable Fedora 44; no verifica arranque ni servicios.',
            'Inventario local excluido del modelo. Sin correlación CVE ni vulnerabilidad deducida por versión.'],
    }


def serializar_compacto(datos, limite):
    copia = dict(datos)
    copia.setdefault('estado_presentacion', 'completo')
    if copia.get('vista_avisos_limitada'):
        copia['estado_presentacion'] = 'parcial'
    limite = min(MAX_RESUMEN, limite)
    copia['colecciones_omitidas'] = list(copia.get('colecciones_omitidas', []))
    for campo in (None, 'avisos_instalados', 'avisos_pendientes', 'kernels_mas_recientes_no_activos'):
        if campo is not None:
            copia[campo] = None
            if campo not in copia['colecciones_omitidas']:
                copia['colecciones_omitidas'].append(campo)
            copia['estado_presentacion'] = 'parcial'
        texto = json.dumps(copia, ensure_ascii=True, separators=(',', ':'))
        if len(texto) <= limite:
            return texto
    texto = '{"herramienta":"auditoria_seguridad","estado_presentacion":"omitido_por_limite"}'
    return texto if len(texto) <= limite else ''


def informe(datos):
    def valor(v):
        return 'desconocido' if v is None else 'sí' if v is True else 'no' if v is False else str(v)
    lineas = ['Hechos de auditoria_seguridad (calculados por Python)',
              'Adquisición: ' + datos['estado_adquisicion'],
              'Kernel activo: ' + valor(datos['kernel_activo']),
              'Kernel más reciente instalado, pendiente de activar: ' + valor(datos['reinicio_pendiente_kernel']),
              'Inventario RPM completo: ' + valor(datos.get('inventario_completo')),
              'Registros RPM válidos recogidos: ' + valor(datos['recuentos'].get('paquetes_rpm_recogidos')),
              'Total RPM confirmado: ' + valor(datos['recuentos']['paquetes_rpm']),
              'Avisos de seguridad pendientes: ' + valor(datos['recuentos']['avisos_pendientes']),
              'Avisos de seguridad instalados según DNF: ' + valor(datos['recuentos']['avisos_instalados'])]
    if datos['kernels_mas_recientes_no_activos']:
        lineas.append('Kernels más recientes confirmados (hasta 3): ' + ', '.join(datos['kernels_mas_recientes_no_activos'][:3]))
    for nombre, fuente in datos['fuentes'].items():
        lineas.append('Fuente ' + nombre + ': ' + fuente['estado'] +
                      ('; causa: ' + fuente['motivo'] if fuente.get('motivo') else ''))
    for campo, titulo in [('avisos_pendientes','Avisos pendientes'), ('avisos_instalados','Avisos instalados')]:
        if datos[campo]:
            lineas.append(titulo + ' (hasta 10): ' + ', '.join(a['id'] for a in datos[campo][:10]))
    lineas.extend(['Desconocido no equivale a cero. Las fuentes con errores no confirman ausencia de actualizaciones.',
                   'Solo caché: antigüedad y cobertura desconocidas; cero avisos no garantiza seguridad.',
                   'No se deducen vulnerabilidades por versión ni se correlacionan CVE. Reinicio limitado al kernel estable Fedora 44.'])
    return '\n'.join(lineas)


class ResultadoAuditoria(str):
    """Texto compacto para el modelo, inventario local inmutable separado."""
    def __new__(cls, datos, limite):
        instancia = super().__new__(cls, serializar_compacto(resumen_modelo(datos), limite))
        instancia._instantanea = json.dumps(datos, ensure_ascii=True, separators=(',', ':'))
        return instancia

    @property
    def datos(self):
        return json.loads(self._instantanea)

    def ajustar(self, limite):
        return serializar_compacto(json.loads(self), limite)


def registrar_metricas(nombre, fuente):
    """Solo metadatos de lista blanca; nunca stdout, stderr ni filas RPM."""
    import math
    if nombre not in {n for n,_ in CONSULTAS}:
        return
    estados = {'correcta', 'parcial', 'error', 'truncada', 'error_comando',
               'tiempo_agotado', 'ejecutable_ausente', 'permiso_denegado',
               'error_sistema', 'aislamiento_no_disponible',
               'avisos_no_interpretados', 'formato_invalido', 'no_consultada'}
    datos = {'fuente': nombre, 'estado': fuente.get('estado') if fuente.get('estado') in estados else 'error'}
    for campo in ('duracion_s', 'stdout_bytes', 'stderr_bytes', 'registros_recogidos', 'codigo'):
        valor = fuente.get(campo)
        if campo == 'duracion_s':
            datos[campo] = valor if type(valor) in (int,float) and math.isfinite(valor) and valor >= 0 else None
        else:
            datos[campo] = valor if type(valor) is int and (-255 if campo == 'codigo' else 0) <= valor <= 2**63-1 else None
    try:
        print('AUDITORIA_METRICAS ' + json.dumps(datos, allow_nan=False), file=sys.stderr)
    except Exception:
        pass
