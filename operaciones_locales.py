"""Lecturas operativas cerradas. Sin cliente HTTP, persistencia ni administración.

La clasificación no concede autoridad: el coordinador vuelve a validar cada ID.
Los resultados de dominio y los contratos de auditoría existentes no cambian.
"""
import shutil
import subprocess
import sys

from autonomia_herramientas import consultar_disco
from interfaces_red import normalizar, informe_verificado
from memoria import informe_memoria
from servicios import informe_servicios

REQUISITOS = {
    'memoria': (sys.executable,), 'disco': ('df',),
    'interfaces_red': ('ip', 'nmcli'), 'vpn': ('nmcli',),
    'servicios_fallidos': ('systemctl',),
    'sistema': ('uname',), 'puertos': ('ss',), 'conexiones': ('ss',),
    'cortafuegos': ('firewall-cmd',), 'trafico_red': (sys.executable,),
    'listar_documentos': (sys.executable,),
}
BLOQUEADAS = ('ip_publica', 'diagnostico_vpn')


def capacidad(nombre, catalogo):
    if nombre == 'ip_publica':
        return 'no_implementada_independientemente'
    if nombre not in catalogo:
        return 'no_disponible'
    requisitos = REQUISITOS.get(nombre, ('curl',))
    presentes = [bool(shutil.which(n)) for n in requisitos]
    apta = any(presentes) if nombre == 'interfaces_red' else all(presentes)
    return 'disponible' if apta else 'no_disponible'


def fuente(comando, deadline, ejecutar, comprobar):
    comprobar(deadline)
    try:
        codigo, salida, errores, truncado = ejecutar(list(comando), min(15, comprobar(deadline)))
        comprobar(deadline)
        estado = ('truncada' if truncado else 'error_comando' if codigo else
                  'avisos_no_interpretados' if errores else 'correcta')
        return dict(estado=estado, codigo=codigo, stdout=salida, stderr='')
    except FileNotFoundError:
        estado = 'ejecutable_ausente'
    except PermissionError:
        estado = 'permiso_denegado'
    except (TimeoutError, subprocess.TimeoutExpired):
        estado = 'tiempo_agotado'
    except OSError:
        estado = 'error_sistema'
    return dict(estado=estado, codigo=None, stdout='', stderr='')


def adquirir(nombre, deadline, *, ejecutar, comprobar, catalogo, memoria, interfaces, servicios, limite, consulta):
    """Informe normalizado o salida etiquetada del catálogo previo, sin modelo."""
    if nombre == 'memoria':
        return informe_memoria(memoria(deadline), limite=limite)
    if nombre == 'servicios_fallidos':
        texto, resultado = informe_servicios(servicios(deadline), limite=limite)
        return texto, resultado.estado_presentacion
    if nombre == 'interfaces_red':
        return informe_verificado(interfaces(catalogo[nombre], deadline).datos, limite=limite)
    if nombre == 'disco':
        datos, estado = consultar_disco(
            lambda cmd, fin: fuente(cmd, fin, ejecutar, comprobar), deadline)
        lineas = ['Espacio de sistemas de archivos locales; integridad no comprobada.',
                  'Fuente df: ' + datos['fuente'] + '.']
        for m in datos['montajes']:
            lineas.append(f"{m['ruta']}: disponibles={m['disponible_bytes']} B; total={m['total_bytes']} B.")
        if not datos['montajes']:
            estado = 'error'
            lineas.append('Espacio desconocido; no equivale a cero.')
        return '\n'.join(lineas), estado
    if nombre == 'vpn':
        # Reutilizar el comando fijo escapado y el parser NM de interfaces.
        nm = fuente(catalogo['interfaces_red']['commands'][1], deadline, ejecutar, comprobar)
        datos = normalizar({'ip': dict(estado='no_consultada', stdout='', stderr='', codigo=None), 'nmcli': nm})
        valida = datos['fuentes']['nmcli']['estado'] == 'correcta'
        lineas = ['VPN local: observación de tipos y estados de NetworkManager.',
                  'Fuente nmcli: ' + datos['fuentes']['nmcli']['estado'] + '.',
                  'No comprueba conectividad, IP pública, rutas ni ausencia de fugas.',
                  'No se publican nombres de conexiones ni dispositivos.']
        estados = []
        for interfaz in datos['interfaces']:
            registro = interfaz['networkmanager']
            if registro and registro['tipo_observado'] in ('vpn', 'wireguard', 'tun', 'ip-tunnel'):
                # Estados cerrados: no reflejar texto libre del comando.
                estado = registro['estado_observado']
                estados.append(estado if estado in ('connected', 'disconnected', 'connecting', 'unavailable', 'unmanaged') else 'desconocido')
        if valida:
            lineas.append(f'Dispositivos de tipo túnel/VPN observados: {len(estados)}; estados: ' + ', '.join(estados) + '.')
            lineas.append('La ausencia de estos tipos no descarta una VPN ni inspecciona perfiles VPN sin dispositivo propio.')
        else:
            lineas.append('Estado VPN desconocido; fuente no utilizable.')
        return '\n'.join(lineas), 'parcial' if valida else 'error'
    if nombre in ('sistema', 'puertos', 'conexiones', 'cortafuegos', 'trafico_red', 'listar_documentos'):
        texto = consulta(nombre, deadline)
        # Mantener comandos y límites del catálogo previo. Sin atribuir éxito a
        # una salida libre; cada línea conserva su carácter de dato de herramienta.
        texto = 'Salida del catálogo existente; verificación de dominio no disponible.\n' + '\n'.join(
            'Herramienta | ' + linea for linea in texto.split('\n'))
        if len(texto) > limite:
            return 'Salida omitida por límite; comprobación no verificable.', 'omitido_por_limite'
        return texto, 'no_verificable'
    raise ValueError('operacion_no_permitida')


def ejecutar_plan(plan, deadline, *, catalogo, adquirir, comprobar, limite=18000,
                  total=60000, llamadas=8, sondear=capacidad):
    """Capacidad, autorización, ejecución y verificación independientes en memoria.

    No reintenta ni retorna texto del usuario o del modelo.
    Los errores propios se reducen a códigos; el catálogo previo conserva su salida.
    Cada elemento contiene un informe acotado listo para presentar.
    """
    resultados = []
    usados = set()
    volumen = 0
    for nombre in plan.nombres:
        if nombre in usados:
            continue
        usados.add(nombre)
        r = dict(operacion=nombre, capacidad='no_disponible', autorizacion='denegada',
                 ejecucion='no_iniciada', verificacion='no_verificable',
                 motivo='operacion_no_permitida', informe='Comprobación no realizada.')
        if nombre not in REQUISITOS and nombre not in BLOQUEADAS:
            resultados.append(r)
            continue
        try:
            comprobar(deadline)
            r['capacidad'] = sondear(nombre, catalogo)
            if nombre in BLOQUEADAS:
                r['motivo'] = 'consulta_externa_fuera_de_esta_ruta_local'
                r['informe'] = ('Consulta externa no realizada. Esta ruta solo admite lecturas locales; '
                                'no requiere privilegios administrativos.')
            elif r['capacidad'] != 'disponible':
                r['motivo'] = 'dependencia_o_herramienta_no_disponible'
            elif len(resultados) >= llamadas or min(limite, total - volumen) < 1000:
                r['motivo'] = 'presupuesto_agotado'
            else:
                r['autorizacion'] = 'permitida_lectura_local'
                r['ejecucion'] = 'iniciada'
                texto, estado = adquirir(nombre, deadline, min(limite, total - volumen))
                comprobar(deadline)
                if estado not in ('completo', 'parcial', 'error', 'omitido_por_limite', 'no_verificable') or not isinstance(texto, str):
                    raise ValueError('resultado_invalido')
                if len(texto) > min(limite, total - volumen):
                    raise ValueError('resultado_excesivo')
                r.update(ejecucion='finalizada', verificacion=estado,
                         motivo='resultado_de_adquisicion', informe=texto)
                volumen += len(texto)
        except KeyboardInterrupt:
            r.update(ejecucion='cancelada', motivo='cancelacion_usuario')
            resultados.append(r)
            break
        except (TimeoutError, subprocess.TimeoutExpired):
            r.update(ejecucion='tiempo_agotado' if r['ejecucion'] == 'iniciada' else 'no_iniciada', motivo='plazo_agotado')
        except (OSError, ValueError, TypeError, KeyError):
            r.update(ejecucion='fallida' if r['ejecucion'] == 'iniciada' else 'no_iniciada', motivo='adquisicion_o_capacidad_no_verificable')
        resultados.append(r)
    return resultados
