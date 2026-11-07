"""Preparación y consentimiento explícito, sin adquisiciones ni integración automática.

La futura interfaz debe mostrar vista_previa y llamar a confirmar solo ante una
acción explícita del usuario. Este módulo no autentica personas ni impide usar
por separado la API de bajo nivel HistorialMemoria. No se integra con la aplicación.
"""
import json
import math
import secrets
import threading
import time

from historial_contratos import validar, _limitar
from historial_sqlite import HistorialMemoria, ErrorHistorial, _lote
from historial_persistente import HistorialPersistente

MAX_PREPARADAS = 16
VIGENCIA_SEGUNDOS = 300
OMISIONES = ('sin_salidas_originales', 'sin_identidades_sensibles',
             'sin_texto_libre', 'solo_metricas_lista_blanca',
             'sin_conclusiones_de_seguridad')


# Registro privado efímero: el destino no acepta datos ni 'manual' como permiso.
_PERMISOS = {}


def _consumir_permiso(permiso, destino):
    try:
        entrada = _PERMISOS.pop(permiso, None)
    except TypeError:
        entrada = None
    if entrada is None or entrada[0] is not destino:
        _fallo('permiso_persistente_no_disponible')
    _, contenido, vigente = entrada
    vigente()
    return json.loads(contenido), vigente


class ErrorControlador(ValueError):
    pass


def _fallo(codigo):
    raise ErrorControlador(codigo)


def _json(dato):
    return json.dumps(dato, ensure_ascii=True, allow_nan=False, sort_keys=True,
                      separators=(',', ':'))


def _preparar(auditoria, resultados, eventos):
    # Reutilizar límites y validación del motor sin abrir una conexión.
    try:
        a, registros, eventos_validados = _lote(auditoria, resultados, eventos)
        r = [validar(json.loads(texto)) for texto in registros]
        e = [dict(tipo=t, resultado_orden=o, cantidad=c) for t,o,c in eventos_validados]
        return _json(dict(auditoria=a, resultados=r, eventos=e))
    except (ValueError, TypeError, KeyError, RecursionError):
        _fallo('preparacion_invalida')


class ControladorHistorial:
    """Desactivado por defecto. Preparaciones inmutables; vistas son copias.

    Modificar entradas o vistas devueltas no modifica la instantánea. Para cambiar
    su contenido se usa reemplazar(), que revoca cualquier autorización anterior.
    Tokens de confirmación son objetos opacos, locales, de un solo intento.
    """

    def __init__(self, destino=None, *, reloj=time.monotonic):
        if destino is not None and type(destino) not in (HistorialMemoria, HistorialPersistente):
            _fallo('destino_no_admitido')
        self._destino = destino
        self._propio = False
        self._reloj = reloj
        self._activo = False
        self._preparadas = {}
        self._autorizaciones = {}
        self._guardados = set()
        self._lock = threading.RLock()

    def activar(self):
        """Habilita el controlador; no autoriza auditorías ni crea una base."""
        with self._lock:
            self._activo = True

    def desactivar(self):
        with self._lock:
            self._activo = False
            self._autorizaciones.clear()
            self._preparadas.clear()

    def _obtener(self, identificador):
        if not self._activo:
            _fallo('historial_desactivado')
        if type(identificador) is not str or identificador not in self._preparadas:
            _fallo('preparacion_no_disponible')
        return self._preparadas[identificador]

    def preparar(self, auditoria, resultados, eventos=None):
        with self._lock:
            if not self._activo:
                _fallo('historial_desactivado')
            if len(self._preparadas) >= MAX_PREPARADAS:
                _fallo('limite_preparaciones')
            contenido = _preparar(auditoria, resultados, [] if eventos is None else eventos)
            if contenido in self._guardados:
                _fallo('auditoria_ya_guardada')
            identificador = secrets.token_hex(16)
            self._preparadas[identificador] = dict(contenido=contenido, estado='preparada')
            return identificador

    def _revocar(self, identificador):
        self._autorizaciones = {t: a for t,a in self._autorizaciones.items()
                                if a['identificador'] != identificador}

    def reemplazar(self, identificador, auditoria, resultados, eventos=None):
        with self._lock:
            p = self._obtener(identificador)
            if p['estado'] not in ('preparada', 'confirmada'):
                _fallo('preparacion_finalizada')
            # Incluso un intento de modificación inválida revoca el consentimiento.
            self._revocar(identificador)
            p['estado'] = 'preparada'
            p['contenido'] = _preparar(auditoria, resultados, [] if eventos is None else eventos)

    def vista_previa(self, identificador):
        with self._lock:
            p = self._obtener(identificador)
            if p['estado'] not in ('preparada', 'confirmada'):
                _fallo('preparacion_finalizada')
            d = json.loads(p['contenido'])
            return dict(version_vista=1, auditoria=d['auditoria'], resultados=d['resultados'],
                        eventos=d['eventos'], omisiones=list(OMISIONES),
                        destino='sqlite_local' if type(self._destino) is HistorialPersistente else 'sqlite_memoria',
                        persistencia_disco=type(self._destino) is HistorialPersistente)

    def _ahora(self):
        valor = self._reloj()
        if type(valor) not in (int, float) or not math.isfinite(valor) or valor < 0:
            _fallo('reloj_invalido')
        return valor

    def confirmar(self, identificador, vista, *, confirmacion=False):
        """Exige True literal y la vista exacta presentada. No guarda datos."""
        with self._lock:
            p = self._obtener(identificador)
            self._revocar(identificador)
            if p['estado'] not in ('preparada', 'confirmada'):
                _fallo('preparacion_finalizada')
            p['estado'] = 'preparada'
            if confirmacion is not True:
                _fallo('confirmacion_explicita_requerida')
            try:
                _limitar(vista)
                coincide = _json(vista) == _json(self.vista_previa(identificador))
            except (ValueError, TypeError, RecursionError):
                coincide = False
            if not coincide:
                _fallo('vista_no_coincidente')
            token = object()
            ahora = self._ahora()
            self._autorizaciones[token] = dict(identificador=identificador,
                contenido=p['contenido'], inicio=ahora, vence=ahora+VIGENCIA_SEGUNDOS,
                destino=self._destino, ruta=getattr(self._destino, '_ruta', None))
            p['estado'] = 'confirmada'
            return token

    def cancelar(self, identificador):
        with self._lock:
            p = self._obtener(identificador)
            if p['estado'] not in ('preparada', 'confirmada'):
                _fallo('preparacion_finalizada')
            self._revocar(identificador)
            del self._preparadas[identificador]

    def guardar(self, identificador, autorizacion=None):
        with self._lock:
            p = self._obtener(identificador)
            if p['estado'] != 'confirmada':
                _fallo('autorizacion_no_disponible')
            # Consumir antes de validar vigencia o intentar el guardado: no reintentos.
            try:
                a = self._autorizaciones.pop(autorizacion, None)
            except TypeError:
                a = None
            if a is None:
                _fallo('autorizacion_no_disponible')
            if a['identificador'] != identificador:
                _fallo('autorizacion_no_coincidente')
            p['estado'] = 'consumida'
            if p['contenido'] in self._guardados:
                _fallo('auditoria_ya_guardada')
            ahora = self._ahora()
            if (not a['inicio'] <= ahora < a['vence'] or a['contenido'] != p['contenido'] or
                    a['destino'] is not self._destino or a['ruta'] != getattr(self._destino, '_ruta', None)):
                _fallo('autorizacion_no_vigente')
            try:
                d = json.loads(p['contenido'])
                # Segunda validación del contenido exacto autorizado antes del motor.
                if _preparar(d['auditoria'], d['resultados'], d['eventos']) != a['contenido']:
                    _fallo('autorizacion_no_vigente')
                if self._destino is None:
                    self._destino = HistorialMemoria()
                    self._propio = True
                if type(self._destino) is HistorialPersistente:
                    def vigente():
                        if not a['inicio'] <= self._ahora() < a['vence']:
                            _fallo('autorizacion_no_vigente')
                    permiso = object()
                    _PERMISOS[permiso] = (self._destino, p['contenido'], vigente)
                    try:
                        ident = self._destino._guardar_autorizado(permiso)
                    finally:
                        _PERMISOS.pop(permiso, None)
                else:
                    ident = self._destino.guardar_auditoria(d['auditoria'], d['resultados'], d['eventos'])
            except ErrorHistorial as error:
                if str(error) == 'publicado_durabilidad_no_confirmada':
                    self._guardados.add(p['contenido'])
                    p['estado'] = 'guardada_incierta'
                    _fallo('publicado_durabilidad_no_confirmada')
                p['estado'] = 'fallida'
                _fallo('guardado_fallido')
            except Exception:
                p['estado'] = 'fallida'
                _fallo('guardado_fallido')
            self._guardados.add(p['contenido'])
            p['estado'] = 'guardada'
            return ident

    def cerrar(self):
        with self._lock:
            self.desactivar()
            if self._propio:
                self._destino.cerrar()
                self._destino = None
                self._propio = False
