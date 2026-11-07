"""Colección efímera de copias saneadas; sin persistencia ni adquisiciones.

No se conecta a los modos verificados todavía. Su futuro punto de captura es
control_verificado.ejecutar_verificada: tras adquirir/comprobar_plazo y antes de
presentar. El original solo es argumento transitorio del adaptador, no se retiene.
"""
import json
import math
import threading
import time

from historial_contratos import validar, adaptar_verificado
from informe_exportacion import preparar_informe

MAX_REGISTROS = 100
MAX_BYTES = 1024 * 1024
VIDA_SEGUNDOS = 1800


class ErrorSesion(ValueError):
    pass


def _fallo(codigo):
    raise ErrorSesion(codigo) from None


def _ahora(reloj):
    v = reloj()
    if type(v) not in (int, float) or not math.isfinite(v) or v < 0:
        _fallo('reloj_no_valido')
    return v


class ColeccionSesion:
    """Vida máxima fija de 30 min desde creación; no se renueva con actividad.

    Límites sobre bytes UTF-8 de instantáneas serializadas, no sobre RSS de Python.
    Caducidad comprobada al acceder: elimina referencias y cierra la sesión.
    No garantiza borrado forense de memoria ni limpieza en segundo plano.
    """

    def __init__(self, *, reloj=time.monotonic):
        self._reloj = reloj
        self._inicio = self._ultimo = _ahora(reloj)
        self._cerrada = False
        self._registros = {}
        self._bytes = 0
        self._siguiente = 1
        self._lock = threading.RLock()

    def _borrar(self):
        self._registros.clear()
        self._bytes = 0

    def _comprobar(self):
        if self._cerrada:
            _fallo('sesion_no_disponible')
        try:
            ahora = _ahora(self._reloj)
        except ErrorSesion:
            self._borrar()
            self._cerrada = True
            raise
        if ahora < self._ultimo or ahora-self._inicio >= VIDA_SEGUNDOS:
            self._borrar()
            self._cerrada = True
            _fallo('sesion_caducada_o_reloj_incoherente')
        self._ultimo = ahora

    def insertar_saneado(self, registro, *, observacion=None):
        """Solo contrato histórico validable; no acepta texto ni un resultado bruto."""
        with self._lock:
            self._comprobar()
            try:
                saneado = validar(registro)
                fecha = None
                if observacion is not None:
                    # Reutilizar validación de fechas de exportación, sin reloj civil
                    # implícito ni generación de formatos. La fiabilidad la declara el llamador.
                    if type(observacion) is not dict or set(observacion) != {'fecha_utc', 'verificada'}:
                        _fallo('registro_no_valido')
                    preparar_informe([saneado], fecha_preparacion_utc=observacion['fecha_utc'],
                                     observaciones=[observacion])
                    fecha = dict(fecha_utc=observacion['fecha_utc'], verificada=True)
                ident = self._siguiente
                texto = json.dumps(dict(id=ident, registro=saneado, observacion=fecha),
                                   ensure_ascii=True, allow_nan=False, separators=(',', ':'))
            except (ValueError, TypeError, KeyError, RecursionError):
                _fallo('registro_no_valido')
            self._comprobar()
            tamano = len(texto.encode('utf-8'))
            if len(self._registros) >= MAX_REGISTROS or self._bytes+tamano > MAX_BYTES:
                _fallo('limite_sesion')
            self._registros[ident] = texto
            self._bytes += tamano
            self._siguiente += 1
            return ident

    def insertar_verificado(self, resultado, distribucion, *, observacion=None):
        """Adaptador para los cinco modos verificados; nunca vuelve a adquirir."""
        with self._lock:
            self._comprobar()
            try:
                saneado = adaptar_verificado(resultado, distribucion)
            except (ValueError, TypeError, KeyError, RecursionError):
                _fallo('registro_no_valido')
            return self.insertar_saneado(saneado, observacion=observacion)

    def consultar(self):
        with self._lock:
            self._comprobar()
            return [json.loads(t) for t in self._registros.values()]

    def seleccionar(self, identificadores):
        """Selección explícita no vacía, sin duplicados, en orden de inserción."""
        with self._lock:
            self._comprobar()
            if (type(identificadores) is not list or not 1 <= len(identificadores) <= MAX_REGISTROS or
                any(type(i) is not int or i not in self._registros for i in identificadores) or
                len(set(identificadores)) != len(identificadores)):
                _fallo('seleccion_no_valida')
            return [json.loads(self._registros[i]) for i in sorted(identificadores)]

    def estado(self):
        with self._lock:
            self._comprobar()
            return dict(version_sesion=1, registros=len(self._registros), bytes_serializados=self._bytes,
                        max_registros=MAX_REGISTROS, max_bytes=MAX_BYTES,
                        vida_maxima_segundos=VIDA_SEGUNDOS)

    def vaciar(self):
        """No reutiliza ids ni renueva la vida de la colección."""
        with self._lock:
            self._comprobar()
            self._borrar()

    def cerrar(self):
        with self._lock:
            self._borrar()
            self._cerrada = True
