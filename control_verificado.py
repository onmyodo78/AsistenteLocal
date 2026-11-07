"""Política común de plazos y salidas para modalidades verificadas.

No adquiere datos ni interpreta resultados de dominio; no importa un cliente HTTP.
"""
import sys
import time

from resultado_verificado import ResultadoVerificado

EXITO = 0
FALLO = 1
USO_INVALIDO = 2  # Conservado por argparse, sin sustituir su gestión de errores.
PARCIAL = 3
INTERRUMPIDO = 130

_CODIGOS_POR_ESTADO = {
    'completo': EXITO,
    'parcial': PARCIAL,
    'omitido_por_limite': PARCIAL,
    'error': FALLO,
}


def codigo_salida(estado):
    # Un estado no reconocido es un error de contrato; nunca significa éxito.
    return _CODIGOS_POR_ESTADO[estado]


def ejecutar_verificada(adquirir, presentar, *, segundos, comprobar_plazo, mensajes):
    """Aplica el mismo deadline antes/después de adquirir y antes de publicar.

    Los adaptadores conservan los contratos propios de cada herramienta.
    No hay reintentos y nunca se vuelve a adquirir tras una excepción.
    """
    deadline = time.monotonic() + segundos
    try:
        comprobar_plazo(deadline)
        resultado = adquirir(deadline)
        comprobar_plazo(deadline)
        texto, presentado = presentar(resultado)
        # La pareja textual anterior sigue admitida como adaptador de transición.
        estado = presentado.estado_presentacion if isinstance(presentado, ResultadoVerificado) else presentado
        codigo = codigo_salida(estado)
        comprobar_plazo(deadline)
        print(texto)
        return codigo
    except KeyboardInterrupt:
        print(mensajes['interrupcion'], file=sys.stderr)
        return INTERRUMPIDO
    except TimeoutError:
        print(mensajes['timeout'])
        return FALLO
    except (OSError, ValueError, TypeError, KeyError):
        print(mensajes['error'])
        return FALLO
