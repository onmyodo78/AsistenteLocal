"""Parser APT puro compartido por planificación y revalidación privilegiada."""
import re
from contratos_mantenimiento import paquete

INST = re.compile(r'^Inst ([a-z0-9][a-z0-9+.-]*(?::[a-z0-9-]+)?)(?: \[([^\]]+)\])? \(([^\s()]+) ([^()]*)\)$')
REMV = re.compile(r'^Remv ([a-z0-9][a-z0-9+.-]*(?::[a-z0-9-]+)?) \[([^\]]+)\]$')
CONF = re.compile(r'^Conf ([a-z0-9][a-z0-9+.-]*(?::[a-z0-9-]+)?) \(([^\s()]+) ([^()]*)\)$')
RESUMEN = re.compile(r'^(\d+) upgraded, (\d+) newly installed, (\d+) to remove and (\d+) not upgraded\.$')


def identidad(nombre, detalle, instalados, anterior=None):
    nombre, _, explicita = nombre.partition(':')
    archs = re.findall(r'\[([a-z0-9-]+)\]', detalle)
    arch = explicita or (archs[-1] if archs else None)
    candidatos = [r for r in instalados if r['nombre_binario'] == nombre and
                  (arch is None or r['arquitectura'] == arch) and
                  (anterior is None or r['version'] == anterior)]
    if arch is None and len(candidatos) == 1:
        arch = candidatos[0]['arquitectura']
    if arch is None:
        raise ValueError('arquitectura_no_verificada')
    if anterior is not None and not any(r['version'] == anterior and r['arquitectura'] == arch for r in candidatos):
        raise ValueError('inventario_no_coincidente')
    return nombre, arch


def parsear_simulacion(texto, inventario):
    """Acepta solo operaciones reconocidas y totales reconciliados.

    El resultado es una previsión local sin bloqueo, nunca una transacción lista
    para ejecutar. No se aceptan avisos ni formatos desconocidos como éxito.
    """
    instalados = [r for r in inventario if r['categoria'] == 'instalado']
    grupos = dict(actualizaciones=[], instalaciones=[], eliminaciones=[], retenciones=[])
    totales = []
    configuraciones = []
    roturas_observadas = set()
    roturas_finales = set()
    for linea in texto.splitlines():
        # Las anotaciones [] describen roturas intermedias, no acciones.
        # Solo se aceptan si todos los paquetes afectados figuran en el plan
        # y la última operación ya no muestra dependencias rotas.
        if linea.startswith(('Inst ', 'Conf ', 'Remv ')):
            anotacion = re.fullmatch(r'(.*[)\]]) \[([^\]]*)\]', linea)
            roturas_finales = set()
            if anotacion:
                linea, roturas = anotacion.groups()
                for nombre_roto in roturas.split():
                    if not re.fullmatch(r'[a-z0-9][a-z0-9+.-]*(?::[a-z0-9-]+)?', nombre_roto):
                        raise ValueError('dependencia_apt_no_interpretada')
                    roturas_finales.add(nombre_roto.split(':')[0])
                roturas_observadas.update(roturas_finales)
        if linea.startswith(('W:', 'E:', 'N:')):
            raise ValueError('avisos_apt_no_verificados')
        resumen = RESUMEN.fullmatch(linea)
        if resumen:
            totales.append(tuple(map(int, resumen.groups())))
        elif linea.startswith('Inst '):
            m = INST.fullmatch(linea)
            if not m:
                raise ValueError('operacion_apt_no_interpretada')
            nombre, anterior, nueva, detalle = m.groups()
            n, arch = identidad(nombre, detalle, instalados, anterior)
            if anterior is None and any(r['nombre_binario'] == n and r['arquitectura'] == arch for r in instalados):
                raise ValueError('instalacion_ambigua')
            grupos['actualizaciones' if anterior is not None else 'instalaciones'].append(paquete(n, arch, anterior, nueva))
        elif linea.startswith('Remv '):
            m = REMV.fullmatch(linea)
            if not m:
                raise ValueError('operacion_apt_no_interpretada')
            nombre, anterior = m.groups()
            n, arch = identidad(nombre, '', instalados, anterior)
            grupos['eliminaciones'].append(paquete(n, arch, anterior, None))
        elif linea.startswith('Conf '):
            m = CONF.fullmatch(linea)
            if not m:
                raise ValueError('configuracion_apt_no_interpretada')
            configuraciones.append(m.groups())
        elif re.match(r'^(Inst|Remv|Conf|Purg)\b', linea):
            raise ValueError('operacion_apt_no_interpretada')
    if len(totales) != 1 or totales[0][:3] != tuple(len(grupos[g]) for g in ('actualizaciones', 'instalaciones', 'eliminaciones')):
        raise ValueError('resumen_apt_no_coincidente')
    acciones = grupos['actualizaciones'] + grupos['instalaciones']
    for nombre, nueva, detalle in configuraciones:
        n, arch = identidad(nombre, detalle, instalados)
        if not any(r['nombre'] == n and r['arquitectura'] == arch and r['propuesta'] == nueva for r in acciones):
            raise ValueError('configuracion_sin_instalacion')
    confirmadas = {(n.split(':')[0], identidad(n, detalle, instalados)[1], v)
                   for n, v, detalle in configuraciones}
    if confirmadas != {(r['nombre'], r['arquitectura'], r['propuesta']) for r in acciones}:
        raise ValueError('configuracion_incompleta')
    afectadas = {r['nombre'] for r in acciones + grupos['eliminaciones']}
    if roturas_finales or not roturas_observadas <= afectadas:
        raise ValueError('dependencias_no_reconciliadas')
    for grupo in ('actualizaciones','instalaciones','eliminaciones'):

        claves = [(r['nombre'], r['arquitectura']) for r in grupos[grupo]]
        if len(claves) != len(set(claves)):
            raise ValueError('operacion_duplicada')
    # Retención explícita dpkg; no confundirla con paquetes no seleccionados.
    grupos['retenciones'] = [paquete(r['nombre_binario'], r['arquitectura'], r['version'], None)
        for r in instalados if r['estado_instalacion'].startswith('hold ')]
    grupos['no_actualizados_total'] = totales[0][3]
    return grupos



COMANDO_SIMULACION = ('/usr/bin/apt-get', '-o', 'RootDir=', '-o', 'Dir::State::status=/var/lib/dpkg/status',
       '-o', 'Dir::Cache::pkgcache=', '-o', 'Dir::Cache::srcpkgcache=',
       '-o', 'Debug::NoLocking=true', '-o', 'APT::Get::Show-User-Simulation-Note=false',
       '--simulate', 'dist-upgrade')
