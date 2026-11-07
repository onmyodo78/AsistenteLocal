"""Interfaz local humana: prepara y autoriza md/csv; no consume ni publica.

Solo main() despacha COMANDO desde input humano. Ninguna respuesta del modelo
se procesa aquí. La autorización pendiente vive solo en esta instancia; iniciar
otra preparación revoca la anterior. No hay acceso al escritor ni a SQLite.
"""
from datetime import datetime, timezone
import json
import re
import sys

from exportacion_controlador import ControladorExportacion
from sesion_resultados import MAX_REGISTROS

COMANDO = ':exportar'


class _Cancelar(Exception):
    pass


class InterfazExportacion:
    def __init__(self, coleccion):
        self._coleccion = coleccion
        self._control = ControladorExportacion()
        self._pendiente = None

    def cerrar(self):
        self._pendiente = None
        self._control.desactivar()

    def _leer(self, mensaje):
        if sys.stdin.isatty() is not True:
            raise _Cancelar()
        texto = input(mensaje)
        if type(texto) is not str or len(texto) > 4096:
            raise _Cancelar()
        texto = texto.strip()
        if not texto or texto.casefold() == 'cancelar':
            raise _Cancelar()
        return texto

    def preparar_interactiva(self):
        """Devuelve 'autorizada', 'cancelada' o 'no_disponible'; nunca crea archivos."""
        # No trasladar una confirmación a una nueva selección/formato/destino.
        self.cerrar()
        try:
            if sys.stdin.isatty() is not True:
                print('Exportación no disponible: se requiere entrada interactiva directa.')
                return 'no_disponible'
            entradas = self._coleccion.consultar()
            if not entradas:
                print('No hay resultados saneados disponibles; no se ejecutarán diagnósticos.')
                return 'no_disponible'
            print('Preparación local de exportación. Escribe cancelar en cualquier paso.')
            for e in entradas:
                r = e['registro']
                print(f"{e['id']}: {r['herramienta']} | ejecución={r['ejecucion']} | calidad={r['calidad']} | cobertura={r['cobertura']}")
            seleccion = self._leer('Identificadores separados por comas: ')
            partes = [v.strip() for v in seleccion.split(',')]
            if not 1 <= len(partes) <= MAX_REGISTROS or any(not re.fullmatch(r'[1-9][0-9]{0,8}', p) for p in partes):
                raise _Cancelar()
            registros = self._coleccion.seleccionar([int(v) for v in partes])
            formato = self._leer('Formato: md (Markdown) o csv: ')
            if formato not in ('md', 'csv'):
                print('Formato no admitido. Opciones disponibles: md y csv.')
                raise _Cancelar()
            destino = self._leer('Ruta absoluta de destino, con extensión correspondiente: ')
            self._control.activar()
            ident = self._control.preparar_desde_registros(
                [r['registro'] for r in registros], formato=formato, destino=destino,
                fecha_preparacion_utc=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                observaciones=[r['observacion'] for r in registros])
            vista = self._control.vista_previa(ident)
            print('Vista previa saneada:')
            print(json.dumps(vista, ensure_ascii=True, sort_keys=True, indent=2))
            # Solo se muestra al humano el destino que acaba de introducir. No se
            # incluye en informe, vista estructurada, mensajes del modelo o errores.
            print('Destino introducido (representación escapada): ' + ascii(destino))
            print('Esta fase solo autoriza en memoria. No se creará ningún archivo.')
            confirmacion = self._leer('Para autorizar exactamente esta preparación escribe AUTORIZAR: ')
            if confirmacion != 'AUTORIZAR':
                raise _Cancelar()
            # Comprobar que sigue siendo interactiva antes de emitir el permiso.
            if sys.stdin.isatty() is not True:
                raise _Cancelar()
            token = self._control.confirmar(ident, vista, confirmacion=True)
            self._pendiente = (ident, token)
            print('Exportación autorizada temporalmente en memoria. Archivo no publicado; no se ha creado ningún archivo.')
            return 'autorizada'
        except (_Cancelar, EOFError, KeyboardInterrupt):
            self.cerrar()
            print('Preparación cancelada. No se ha creado ningún archivo.')
            return 'cancelada'
        except Exception:
            # No propagar errores con rutas a los manejadores genéricos de main.
            self.cerrar()
            print('Preparación no disponible: selección, sesión o datos no válidos. No se ha creado ningún archivo.')
            return 'no_disponible'
