"""Correlación de evidencia local Fedora con CVE y CISA KEV; solo lectura."""
import json
import re
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from auditoria_seguridad import AVISO_LOG_DNF, sin_duplicados

KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
DNF_DOC = 'https://dnf5.readthedocs.io/en/stable/commands/advisory.8.html'
COMANDO = ('dnf5', '--cacheonly', '--no-plugins', '--setopt=logdir=/proc/self/fd',
           'advisory', 'info', '--security', '--available', '--json')
CVE = re.compile(r'CVE-\d{4}-\d{4,}\Z')
NEVRA = re.compile(r'(.+)-(\d+:)?([^-]+)-([^-]+)\.([^.]+)\Z')


class SinRedireccion(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def consultar_kev(autorizado, timeout):
    if not autorizado:
        return {'estado': 'no_autorizada'}, None
    try:
        # URL fija, sin enviar inventario, CVE, ni otros datos del equipo.
        with urllib.request.build_opener(SinRedireccion).open(KEV_URL, timeout=timeout) as respuesta:
            contenido = respuesta.read(8 * 1024 * 1024 + 1)
        if len(contenido) > 8 * 1024 * 1024:
            raise ValueError('limite_bytes')
        datos = json.loads(contenido, object_pairs_hook=sin_duplicados)
        entradas = datos['vulnerabilities']
        if not isinstance(entradas, list) or datos['count'] != len(entradas):
            raise ValueError('catalogo_invalido')
        ids = set()
        for entrada in entradas:
            ident = entrada['cveID']
            if not isinstance(ident, str) or not CVE.fullmatch(ident):
                raise ValueError('CVE inválido')
            ids.add(ident)
        return {'estado': 'correcta', 'version': datos['catalogVersion'],
                'publicado': datos['dateReleased'],
                'consultado_utc': datetime.now(timezone.utc).isoformat()}, ids
    except (OSError, ValueError, KeyError, TypeError):
        return {'estado': 'error_o_formato_invalido'}, None


def correlacionar(local, detalles, kev_ids, comparar=None):
    """KEV nunca interviene en la valoración de la versión instalada."""
    if comparar is None:
        try:
            from rpm import labelCompare
            comparar = labelCompare
        except ImportError:
            pass
    filas = json.loads(detalles, object_pairs_hook=sin_duplicados)
    if not isinstance(filas, list):
        raise ValueError('DNF5 inválido')
    pendientes = {a['id']: set(a['paquetes']) for a in local['avisos_pendientes'] or []}
    inventario = local['inventario_rpm'] or []
    salida = []
    for aviso in filas:
        if aviso['Type'] != 'security' or not isinstance(aviso['Name'], str):
            raise ValueError('aviso inválido')
        cves = []
        for ref in aviso['references']:
            if ref['Type'].lower() == 'cve':
                if not CVE.fullmatch(ref['Id']):
                    raise ValueError('CVE inválido')
                cves.append(ref['Id'])
        for nevra in aviso['collections'].get('packages', []):
            match = NEVRA.fullmatch(nevra)
            if not match:
                raise ValueError('NEVRA inválido')
            nombre, epoch, version, release, arch = match.groups()
            correctiva = (epoch[:-1] if epoch else '0', version, release)
            for paquete in inventario:
                if (paquete['nombre'], paquete['arquitectura']) != (nombre, arch):
                    continue
                instalada = (str(paquete['epoch']), paquete['version'], paquete['release'])
                orden = comparar(instalada, correctiva) if comparar else None
                estado = ('version_correctiva_alcanzada' if orden is not None and orden >= 0 else
                          'correccion_pendiente_confirmada' if orden is not None and orden < 0
                          and nevra in pendientes.get(aviso['Name'], set()) else 'no_determinado')
                salida.append({'aviso': aviso['Name'], 'paquete': nombre, 'arquitectura': arch,
                               'instalada_evr': ':'.join((instalada[0], '-'.join(instalada[1:]))),
                               'correctiva_nevra': nevra, 'estado_local': estado,
                               'cves': [{'id': c, 'en_kev': None if kev_ids is None else c in kev_ids}
                                        for c in sorted(set(cves))]})
    return salida


def consultar(consultar_local, ejecutar, autorizado, deadline):
    local = consultar_local(deadline)
    informe = {'herramienta': 'correlacion_seguridad', 'fuentes_locales': local['fuentes'],
               'inventario_completo': local['inventario_completo'], 'resultados': [],
               'referencias': [DNF_DOC, 'RPM local: inventario y rpm.labelCompare', KEV_URL],
               'alcance': 'Avisos de seguridad disponibles según DNF5 y sus paquetes instalados.',
               'limitaciones': ['Solo caché DNF5; cobertura y antigüedad desconocidas.',
                                'KEV indica explotación conocida del CVE, no vulnerabilidad del paquete.',
                                'Versión correctiva alcanzada no demuestra activación del kernel ni reinicio de servicios.',
                                'No determinado y ausencia en KEV no equivalen a ausencia de vulnerabilidades.']}
    try:
        restante = deadline - time.monotonic()
        if restante <= 0:
            raise TimeoutError()
        comando = [sys.executable, '-B', str(Path(__file__).resolve()), '--detalle-local']
        codigo, texto, errores, truncado = ejecutar(comando, min(15, restante))
        if codigo or truncado or errores not in ('', AVISO_LOG_DNF):
            raise ValueError('detalle_no_disponible')
        # Validar evidencia local antes de consultar la fuente externa.
        informe['resultados'] = correlacionar(local, texto, None)
        informe['detalle_dnf5'] = 'correcto'
    except (OSError, TimeoutError, ValueError, KeyError, TypeError, AttributeError, RecursionError):
        informe['detalle_dnf5'] = 'no_disponible_o_formato_invalido'
    restante = deadline - time.monotonic()
    if restante > 0:
        estado, ids = consultar_kev(autorizado, min(10, restante))
    else:
        estado, ids = {'estado': 'no_consultada_por_tiempo'}, None
    informe['cisa_kev'] = estado
    for fila in informe['resultados']:
        for cve in fila['cves']:
            cve['en_kev'] = None if ids is None else cve['id'] in ids
    informe['total_resultados'] = len(informe['resultados'])
    return informe


def presentar(datos, limite):
    copia = dict(datos)
    copia['resultados'] = list(datos['resultados'])
    copia['resultados_omitidos'] = 0
    while True:
        texto = json.dumps(copia, ensure_ascii=True, separators=(',', ':'))
        if len(texto) <= limite:
            return texto
        if not copia['resultados']:
            return 'Informe de correlación omitido por límite de salida.'[:limite]
        copia['resultados'].pop()
        copia['resultados_omitidos'] += 1


if __name__ == '__main__':
    if sys.argv[1:] != ['--detalle-local']:
        sys.exit(78)
    from auditoria_aislamiento import restringir
    import os
    try:
        restringir()
    except Exception:
        sys.exit(78)
    try:
        os.execvpe(COMANDO[0], COMANDO, dict(os.environ, LC_ALL='C', PYTHONDONTWRITEBYTECODE='1'))
    except OSError:
        sys.exit(69)
