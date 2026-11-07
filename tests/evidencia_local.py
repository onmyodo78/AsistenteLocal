"""Validaciones del contenido observado, independientes del código de salida."""
import os
from pathlib import Path
import re
import json
import AsistenteLocal as app


MOTIVOS_DPKG = frozenset(('limite_bytes','limite_linea','limite_stderr','limite_registros',
    'formato_invalido','registro_duplicado','tiempo_agotado','ejecutable_ausente',
    'permiso_denegado','error_sistema','aislamiento_no_disponible','error_comando',
    'avisos_no_interpretados','fila_incompleta','terminacion_no_confirmada','error_recogida'))
MOTIVOS_APT = MOTIVOS_DPKG | frozenset(('python3_apt_no_disponible','configuracion_apt_no_disponible',
    'consulta_apt_fallida','indices_ausentes','indices_parciales','seleccion_indices_no_verificada','salida_incompleta',
    'inventarios_no_coincidentes'))


def _comprobar_debian(resultado, *, apt_completo=False):
    """Contrato coherente no equivale a cobertura APT completa.

    Valida hechos y prefijos conservados; no certifica que las versiones procedan
    del anfitrión ni reproduce la selección de Policy mediante reglas propias.
    """
    from auditoria_debian import parsear_fila
    from apt_debian import validar_registro
    assert isinstance(resultado, app.ResultadoDebian)
    local, vista = resultado.datos, json.loads(resultado)
    assert (local['version'],local['alcance']) in ((1,'inventario_local_dpkg'),
                                                  (2,'inventario_y_candidatos_locales'))
    assert local['backend'] == 'debian' and local['herramienta'] == 'auditoria_seguridad'
    assert local['estado_seguridad'] == 'no_evaluada'
    assert local['cve'] == local['avisos_seguridad'] == 'no_disponible'
    assert 'inventario_dpkg' not in vista and vista['inventario_excluido'] is True
    for campo in ('estado_adquisicion','estado_seguridad','fuente','limitaciones',
                  'total_instalados','recuentos_recogidos'):
        assert vista[campo] == local[campo], 'Resumen pierde estados, errores o advertencias'
    for fuente in (local['fuente'],) + ((local['actualizaciones'],) if local['version'] == 2 else ()):
        assert fuente['codigo'] is None or type(fuente['codigo']) is int
        assert type(fuente['stderr_bytes']) is int and fuente['stderr_bytes'] >= 0
    filas = local['inventario_dpkg']
    assert type(filas) is list
    identidades = set()
    for fila in filas:
        reconstruida = parsear_fila('\t'.join(fila[k] or '' for k in (
            'nombre_binario','arquitectura','version','estado_instalacion','nombre_fuente','version_fuente')))
        assert reconstruida == fila, 'Fila dpkg incoherente'
        identidad = (fila['nombre_binario'],fila['arquitectura'])
        assert identidad not in identidades, 'Inventario duplicado'
        identidades.add(identidad)
    recuentos = local['recuentos_recogidos']
    assert set(recuentos) == {'instalado','incompleto','residual','no_instalado'}
    for categoria, cantidad in recuentos.items():
        assert type(cantidad) is int and cantidad >= 0
        assert cantidad == sum(p['categoria'] == categoria for p in filas)
    estado_dpkg = local.get('estado_inventario',local['estado_adquisicion'])
    assert estado_dpkg in ('completo','parcial'), 'Inventario dpkg fallido: no valida integración'
    assert type(local['inventario_completo']) is bool
    assert local['inventario_completo'] == (estado_dpkg == 'completo')
    if estado_dpkg == 'completo':
        assert local['fuente']['codigo'] == 0 and local['fuente']['motivo'] is None
        assert not local['fuente']['stderr_bytes']
        assert type(local['total_instalados']) is int and local['total_instalados'] == recuentos['instalado']
    else:
        assert filas and local['total_instalados'] is None
        assert local['fuente']['motivo'] in MOTIVOS_DPKG
        if local['fuente']['motivo'] == 'avisos_no_interpretados':
            assert local['fuente']['stderr_bytes'] > 0
    if local['version'] == 1:
        assert local['actualizaciones'] == vista['actualizaciones'] == 'no_implementado'
        assert local['estado_adquisicion'] == estado_dpkg
        assert not apt_completo, 'Cobertura APT completa no implementada en contrato dpkg v1'
        return 'Contrato dpkg verificado; APT no implementado; seguridad no evaluada'
    apt = local['actualizaciones']
    assert vista['estado_inventario'] == estado_dpkg
    assert vista['actualizaciones'] == {k:v for k,v in apt.items() if k != 'candidatos'}
    estado_apt = apt['estado_adquisicion']
    assert estado_apt in ('completo','parcial','error')
    assert apt['instalabilidad'] == 'no_comprobada' and apt['seguridad'] == 'no_evaluada'
    candidatos = apt['candidatos']
    assert type(candidatos) is list
    identificados = set()
    for fila in candidatos:
        validar_registro(fila)
        identidad = (fila['nombre_binario'],fila['arquitectura'])
        assert identidad not in identificados, 'Candidato duplicado'
        identificados.add(identidad)
        if fila['candidata'] is None:
            assert not fila['superior'] and not fila['posible_actualizacion']
    recogidos = dict(registros=len(candidatos), superiores=sum(r['superior'] for r in candidatos),
        retenidos=sum(r['retenido'] for r in candidatos), posibles=sum(r['posible_actualizacion'] for r in candidatos))
    assert apt['recuentos_recogidos'] == recogidos
    assert all(type(v) is int for v in apt['recuentos_recogidos'].values())
    indices = apt['indices']
    if candidatos or estado_apt == 'completo':
        assert type(indices) is dict
        assert indices['presentes'] > 0 or apt['motivo'] == 'seleccion_indices_no_verificada'
    if indices is not None:
        assert indices['frescura'] == 'no_verificada'
        for k in ('configurados','presentes','ausentes','umbral_aviso_s'):
            assert type(indices[k]) is int and indices[k] >= 0
        assert indices['presentes'] + indices['ausentes'] == indices['configurados']
        assert type(indices['potencialmente_desactualizados']) is bool
        assert indices['edad_max_s'] is None or type(indices['edad_max_s']) is int
        if 'integridad_local' in indices:
            from apt_debian import validar_seleccion
            validar_seleccion(indices)
    if estado_apt == 'completo':
        assert apt['codigo'] == 0 and apt['motivo'] is None and not apt['stderr_bytes']
        assert indices['ausentes'] == 0
        if 'integridad_local' in indices:
            assert indices['integridad_local'] == 'completa'
    else:
        assert apt['motivo'] in MOTIVOS_APT, 'Degradación sin causa explícita reconocida'
        codigo_esperado = {'python3_apt_no_disponible':70,'configuracion_apt_no_disponible':71,
                           'consulta_apt_fallida':72,'aislamiento_no_disponible':78}.get(apt['motivo'])
        if codigo_esperado is not None:
            assert apt['codigo'] == codigo_esperado, 'Código incompatible con causa APT'
        if apt['motivo'] == 'avisos_no_interpretados':
            assert apt['stderr_bytes'] > 0
        assert bool(candidatos) == (estado_apt == 'parcial'), 'Prefijo APT incompatible con su estado'
    if estado_dpkg == 'completo' and apt['motivo'] != 'inventarios_no_coincidentes':
        instalados = {(r['nombre_binario'],r['arquitectura']):r['version']
                      for r in filas if r['categoria'] == 'instalado'}
        assert all(instalados.get((r['nombre_binario'],r['arquitectura'])) == r['instalada']
                   for r in candidatos), 'Candidatos ajenos al inventario sin discrepancia explícita'
    completo = estado_dpkg == estado_apt == 'completo'
    assert local['estado_adquisicion'] == ('completo' if completo else 'parcial')
    if completo:
        assert { (r['nombre_binario'],r['arquitectura']):r['instalada'] for r in candidatos } == {
            (r['nombre_binario'],r['arquitectura']):r['version'] for r in filas if r['categoria'] == 'instalado'}
        assert type(apt['total_posibles']) is int and apt['total_posibles'] == recogidos['posibles']
    else:
        assert apt['total_posibles'] is None, 'Total global inventado con adquisición parcial'
    if apt_completo:
        assert completo, 'Cobertura APT completa no confirmada: adquisición parcial o fallida'
        return 'Cobertura APT completa e inventario dpkg contrastados; seguridad no evaluada'
    return ('Contrato Debian verificado; dpkg ' + estado_dpkg + '; APT ' + estado_apt +
            ('; cobertura APT completa' if completo else '; cobertura APT no confirmada (degradación representada)') +
            '; seguridad no evaluada')


def comprobar_debian(resultado, *, apt_completo=False):
    try:
        return _comprobar_debian(resultado,apt_completo=apt_completo)
    except (KeyError,TypeError,ValueError,OverflowError):
        raise AssertionError('Contrato Debian inválido o incompleto') from None


def comprobar(nombre, resultado, *, nivel_debian='apt_completo'):
    assert nivel_debian in ('contrato', 'apt_completo')
    if nombre in app.HERRAMIENTAS_SEGURIDAD:
        estado = json.loads(resultado).get('estado')
        assert estado not in ('no_implementado', 'no_soportado'), 'Auditoría o correlación no realizada'
    if nombre == 'auditoria_seguridad' and json.loads(resultado).get('backend') == 'debian':
        return comprobar_debian(resultado, apt_completo=nivel_debian == 'apt_completo')
    assert 'RESULTADO TRUNCADO' not in resultado, 'Resultado incompleto'
    assert 'ESTADO: ERROR' not in resultado, 'Un comando devolvió error'
    assert 'TIEMPO AGOTADO' not in resultado, 'Tiempo agotado'
    assert 'NO SE PUDO EJECUTAR' not in resultado, 'No se pudo ejecutar'
    if nombre == 'correlacion_seguridad':
        datos = json.loads(resultado)
        assert datos['herramienta'] == nombre
        assert datos['detalle_dnf5'] == 'correcto', 'Detalle DNF5 no disponible o inválido'
        assert datos['inventario_completo'] is True, 'Inventario local incompleto'
        fuentes = datos['fuentes_locales']
        assert set(fuentes) == {'uname', 'rpm', 'kernels', 'pendientes', 'instalados'}
        assert all(f['estado'] == 'correcta' for f in fuentes.values()), 'Fuentes locales incompletas'
        assert datos['cisa_kev']['estado'] == 'no_autorizada', 'Consulta externa inesperada'
        assert isinstance(datos['referencias'], list) and datos['referencias']
        assert isinstance(datos['alcance'], str) and datos['alcance']
        assert isinstance(datos['limitaciones'], list) and datos['limitaciones']
        filas = datos['resultados']
        assert isinstance(filas, list)
        assert type(datos['total_resultados']) is int and datos['total_resultados'] >= 0
        assert type(datos['resultados_omitidos']) is int and datos['resultados_omitidos'] == 0, 'Resultados omitidos'
        assert datos['total_resultados'] == len(filas), 'Recuento de correlación inconsistente'
        for fila in filas:
            for campo in ('aviso', 'paquete', 'arquitectura', 'instalada_evr', 'correctiva_nevra'):
                assert isinstance(fila[campo], str) and fila[campo]
            assert fila['estado_local'] in ('version_correctiva_alcanzada',
                                            'correccion_pendiente_confirmada', 'no_determinado')
            assert isinstance(fila['cves'], list)
            ids = []
            for cve in fila['cves']:
                assert re.fullmatch(r'CVE-\d{4}-\d{4,}', cve['id'])
                assert cve['en_kev'] is None, 'KEV no consultado debe ser desconocido'
                ids.append(cve['id'])
            assert len(ids) == len(set(ids)), 'CVE duplicados'
        return f'{len(filas)} resultados de correlación; fuentes locales completas; KEV no autorizado'
    if nombre == 'auditoria_seguridad':
        datos = json.loads(resultado)
        assert datos['herramienta'] == nombre and datos['version'] == 2
        assert datos['estado_adquisicion'] in ('completo', 'parcial', 'error')
        assert 'inventario_rpm' not in datos, 'Inventario completo enviado al modelo'
        assert len(resultado) <= 5000
        assert isinstance(resultado, app.ResultadoAuditoria)
        local = resultado.datos
        recogidos = len(local['inventario_rpm'] or [])
        assert local['recuentos']['paquetes_rpm_recogidos'] == recogidos
        if local['inventario_completo']:
            assert local['recuentos']['paquetes_rpm'] == recogidos
        else:
            assert local['recuentos']['paquetes_rpm'] is None
        for campo in ('avisos_pendientes', 'avisos_instalados'):
            if local[campo] is not None:
                assert len({a['id'] for a in local[campo]}) == datos['recuentos'][campo]
        return ('Auditoría ' + datos['estado_adquisicion'] +
                '; inventario local excluido; solo caché, cobertura y antigüedad no verificadas')
    if nombre == 'interfaces_red':
        datos = json.loads(resultado)
        assert datos['herramienta'] == nombre and datos['version'] == 1
        assert datos['estado'] == 'completo', 'Resultado parcial, fallido u omitido'
        assert all(f['estado'] == 'correcta' for f in datos['fuentes'].values())
        interfaces = datos['interfaces']
        assert len({i['nombre'] for i in interfaces}) == len(interfaces)
        assert datos['alcance']['interfaces_enumeradas_ip'] == len(interfaces)
        for interfaz in interfaces:
            assert interfaz['administrativo'] in ('UP', 'DOWN')
            assert interfaz['radio'] == 'desconocida'
            assert interfaz['conectividad'] == 'no_comprobada'
            assert interfaz['networkmanager'] is not None
            for sentido in ('rx', 'tx'):
                assert all(type(v) is int and v >= 0 for v in interfaz['contadores'][sentido].values())
        return f'{len(interfaces)} interfaces normalizadas; radio y conectividad no medidas'
    salidas = re.findall(r'SALIDA ESTÁNDAR:\n(.*?)\nERRORES O AVISOS:', resultado, re.S)
    if app.TOOLS[nombre]['commands']:
        assert len(salidas) == len(app.TOOLS[nombre]['commands']), 'Faltan resultados'
    if nombre == 'disco':
        filas = [l.split() for l in salidas[0].splitlines()[1:] if l.strip()]
        assert filas and all(len(f) >= 6 and re.fullmatch(r'\d+%', f[4]) for f in filas)
        return f'{len(filas)} sistemas de archivos; porcentajes y puntos de montaje presentes'
    if nombre == 'memoria':
        assert re.search(r'^Mem:\s+\S+\s+\S+\s+\S+', salidas[0], re.M)
        assert re.search(r'^Swap:\s+\S+\s+\S+\s+\S+', salidas[0], re.M)
        return '; '.join(l for l in salidas[0].splitlines() if l.startswith(('Mem:', 'Swap:')))
    if nombre == 'sistema':
        assert salidas[0].startswith('Linux ') and len(salidas[0].split()) >= 5
        return 'kernel ' + salidas[0].split()[2]
    if nombre == 'servicios_fallidos':
        cantidad = re.search(r'(\d+) loaded units listed', salidas[0])
        assert cantidad, 'Falta resumen de unidades'
        filas = re.findall(r'^.*\sfailed\s+failed\s.*$', salidas[0], re.M)
        assert len(filas) == int(cantidad[1]), 'Resumen y unidades no coinciden'
        return cantidad[1] + ' unidades fallidas; resumen contrastado con filas'
    if nombre in ('puertos', 'conexiones'):
        for salida in salidas:
            assert all(c in salida.splitlines()[0] for c in ('Recv-Q', 'Send-Q', 'Address:Port'))
            assert all(len(l.split()) >= (5 if nombre == 'puertos' else 4)
                       for l in salida.splitlines()[1:] if l.strip())
        conteos = [len([l for l in salida.splitlines()[1:] if l.strip()]) for salida in salidas]
        return f'TCP: {conteos[0]} filas; UDP: {conteos[1]} filas; cabeceras verificadas, procesos solo cuando aparecen'
    if nombre == 'cortafuegos':
        assert salidas[0].strip() == 'running'
        assert salidas[1].strip()
        assert all(c in salidas[2] for c in ('target:', 'services:', 'ports:', 'interfaces:'))
        return 'running; zonas activas y campos de la zona predeterminada; no todas las reglas de otras zonas'
    if nombre == 'vpn':
        for salida, minimo in zip(salidas, (3, 4)):
            assert salida.strip()
            assert all(len(re.split(r'(?<!\\):', l)) >= minimo for l in salida.splitlines())
        return 'tipos de conexión y estados de dispositivos; no confirma ruta ni ausencia de fugas'
    if nombre == 'trafico_red':
        intervalo = re.search(r'Intervalo real: ([\d.]+)', resultado)
        assert intervalo and float(intervalo[1]) > 0
        valores = re.findall(r'  (?:RX|TX): (\d+) bytes \| ([\d.]+) B/s \| ([\d.]+) Mbit/s', resultado)
        assert valores and len(valores) % 2 == 0
        for total, velocidad, mbits in valores:
            assert abs(float(velocidad) - int(total) / float(intervalo[1])) <= max(1, float(velocidad) * .005)
            assert abs(float(mbits) - float(velocidad) * 8 / 1e6) <= .001
        return f'{len(valores)//2} interfaces; intervalo y conversiones de velocidad contrastados'
    if nombre == 'listar_documentos':
        with os.scandir(Path(app.__file__).resolve().parent / 'documentos') as entradas:
            cantidad = sum(1 for _ in entradas)
        assert cantidad <= app.MAX_DOCUMENTS, 'Directorio excede el alcance de esta prueba'
        assert resultado.count('Nombre: ') == cantidad
        if cantidad == 0:
            assert 'La carpeta está vacía.' in resultado
        return f'{cantidad} entradas contrastadas con la carpeta autorizada; no se leen contenidos'
    raise AssertionError('Herramienta sin validador de contenido')


def comprobar_respuesta(nombre, texto, resultado):
    """Detecta errores observados; no sustituye una revisión semántica completa."""
    minusculas = texto.casefold()
    if nombre == 'auditoria_seguridad' and isinstance(resultado, app.ResultadoDebian):
        datos = resultado.datos
        apt = datos.get('actualizaciones')
        if not isinstance(apt,dict) or apt['total_posibles'] is None:
            assert not re.search(r'no (?:hay|existen) actualizaciones|sin actualizaciones|\b0 actualizaciones',
                                 minusculas), 'APT desconocido no acredita ausencia de actualizaciones'
        assert not re.search(r'no (?:hay|existen) vulnerabilidades|sin vulnerabilidades',minusculas), \
            'Seguridad Debian no evaluada'
    if nombre == 'memoria':
        assert not re.search(r'no hay actividad de swap|no se recurre al swap|swap.{0,30}inactivo',
                             minusculas), 'Una lectura puntual no prueba ausencia de actividad de swap'
    if nombre == 'puertos' and 'cups' not in resultado.casefold():
        assert 'cups' not in minusculas, 'Servicio CUPS atribuido sin identificación en la salida'
    if nombre == 'interfaces_red':
        assert 'apagada' not in minusculas, 'DOWN/unavailable no prueba que la radio esté apagada'
    if nombre == 'listar_documentos':
        assert 'contenido oculto' not in minusculas, 'El listado también incluye entradas ocultas del primer nivel'
