"""Preparación y consentimiento para md/csv, sin escritura ni integración.

La interfaz futura debe recoger la selección de destino y confirmación humana.
No autentica personas ni convierte respuestas de LM Studio en consentimiento.
Las rutas elegidas se mantienen privadas: no aparecen en vista previa ni errores.
"""
from dataclasses import dataclass, field
import json
import math
from pathlib import PurePosixPath
import re
import secrets
import threading
import time

from informe_exportacion import preparar_informe, validar_informe
from exportacion_generadores import generar_markdown, generar_csv

FORMATOS = ('md', 'csv')
MAX_PREPARACIONES = 16
VIGENCIA_SEGUNDOS = 300


class ErrorExportacion(ValueError):
    pass


def _fallo(codigo):
    raise ErrorExportacion(codigo)


def _destino(destino, formato):
    if type(formato) is not str or formato not in FORMATOS:
        _fallo('formato_no_admitido')
    if type(destino) is not str or not 1 <= len(destino) <= 4096:
        _fallo('destino_no_admitido')
    ruta = PurePosixPath(destino)
    if (not ruta.is_absolute() or destino.startswith('//') or str(ruta) != destino or
        '..' in ruta.parts or any(ord(c) < 32 or ord(c) == 127 for c in destino) or
        not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,119}\.'+formato, ruta.name)):
        _fallo('destino_no_admitido')
    return destino


def _canonico(d):
    return json.dumps(d, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(',', ':'))


def _preparar(informe, formato, destino):
    _destino(destino, formato)
    try:
        d = validar_informe(informe)
        contenido = {'md': generar_markdown, 'csv': generar_csv}[formato](d)
        return dict(informe=_canonico(d), contenido=contenido, formato=formato,
                    destino=destino, estado='preparada', revision=1)
    except (ValueError, TypeError, KeyError, RecursionError):
        _fallo('preparacion_no_valida')


@dataclass(frozen=True)
class EntregaExportacion:
    """Entrega única en memoria para un futuro escritor; no escribe nada.

    destino y contenido no se incluyen en repr; no registrar ni exportar la ruta.
    """
    formato: str
    destino: str = field(repr=False)
    contenido: bytes = field(repr=False)


class ControladorExportacion:
    def __init__(self, *, reloj=time.monotonic):
        self._reloj = reloj
        self._activo = False
        self._preparadas = {}
        self._autorizaciones = {}
        self._lock = threading.RLock()

    def activar(self):
        """Habilitar no confirma ninguna exportación."""
        with self._lock:
            self._activo = True

    def desactivar(self):
        with self._lock:
            self._activo = False
            self._preparadas.clear()
            self._autorizaciones.clear()

    def _obtener(self, identificador):
        if not self._activo:
            _fallo('exportacion_desactivada')
        if type(identificador) is not str or identificador not in self._preparadas:
            _fallo('preparacion_no_disponible')
        return self._preparadas[identificador]

    def preparar(self, informe, *, formato, destino):
        with self._lock:
            if not self._activo:
                _fallo('exportacion_desactivada')
            if len(self._preparadas) >= MAX_PREPARACIONES:
                _fallo('limite_preparaciones')
            p = _preparar(informe, formato, destino)
            identificador = secrets.token_hex(16)
            self._preparadas[identificador] = p
            return identificador

    def preparar_desde_registros(self, registros, *, formato, destino,
                                 fecha_preparacion_utc, observaciones=None):
        if not self._activo:
            _fallo('exportacion_desactivada')
        _destino(destino, formato)
        try:
            informe = preparar_informe(registros, fecha_preparacion_utc=fecha_preparacion_utc,
                                       observaciones=observaciones)
        except (ValueError, TypeError, KeyError, RecursionError):
            _fallo('preparacion_no_valida')
        return self.preparar(informe, formato=formato, destino=destino)

    def _revocar(self, identificador):
        self._autorizaciones = {t:a for t,a in self._autorizaciones.items() if a['identificador'] != identificador}

    def reemplazar(self, identificador, informe, *, formato, destino):
        with self._lock:
            p = self._obtener(identificador)
            if p['estado'] not in ('preparada', 'confirmada'):
                _fallo('preparacion_finalizada')
            self._revocar(identificador)
            p['estado'] = 'preparada'
            nuevo = _preparar(informe, formato, destino)
            nuevo['revision'] = p['revision']+1
            self._preparadas[identificador] = nuevo

    def vista_previa(self, identificador):
        with self._lock:
            p = self._obtener(identificador)
            if p['estado'] not in ('preparada', 'confirmada'):
                _fallo('preparacion_finalizada')
            d = json.loads(p['informe'])
            return dict(version_vista=1, preparacion=identificador, revision=p['revision'],
                formato=p['formato'], extension='.'+p['formato'], tamano_bytes=len(p['contenido']),
                destino_seleccionado=True, escritura_implementada=False,
                fecha_preparacion_utc=d['fecha_preparacion_utc'],
                version_formato=d['version_formato'], version_privacidad=d['version_privacidad'],
                version_catalogo=d['version_catalogo'], resultados=[dict(orden=r['orden'],
                    herramienta=r['origen']['herramienta'], ejecucion=r['origen']['ejecucion'],
                    calidad=r['origen']['calidad'], cobertura=r['origen']['cobertura'],
                    componentes=r['componentes'], omisiones=r['omisiones'], limitaciones=r['limitaciones'])
                    for r in d['resultados']])

    def _ahora(self):
        ahora = self._reloj()
        if type(ahora) not in (int, float) or not math.isfinite(ahora) or ahora < 0:
            _fallo('reloj_no_valido')
        return ahora

    def confirmar(self, identificador, vista, *, confirmacion=False):
        with self._lock:
            p = self._obtener(identificador)
            if p['estado'] not in ('preparada', 'confirmada'):
                _fallo('preparacion_finalizada')
            self._revocar(identificador)
            p['estado'] = 'preparada'
            if confirmacion is not True:
                _fallo('confirmacion_explicita_requerida')
            # Igualdad canónica también distingue booleanos y enteros.
            try:
                if _canonico(vista) != _canonico(self.vista_previa(identificador)):
                    _fallo('vista_no_coincidente')
            except (ValueError, TypeError, RecursionError):
                _fallo('vista_no_coincidente')
            ahora = self._ahora()
            token = object()
            self._autorizaciones[token] = dict(identificador=identificador, revision=p['revision'],
                contenido=p['contenido'], informe=p['informe'], formato=p['formato'],
                destino=p['destino'], inicio=ahora, vence=ahora+VIGENCIA_SEGUNDOS)
            p['estado'] = 'confirmada'
            return token

    def cancelar(self, identificador):
        with self._lock:
            p = self._obtener(identificador)
            if p['estado'] not in ('preparada', 'confirmada'):
                _fallo('preparacion_finalizada')
            self._revocar(identificador)
            del self._preparadas[identificador]

    def consumir(self, identificador, autorizacion=None):
        """Devuelve EntregaExportacion una sola vez; no hay método de escritura."""
        with self._lock:
            p = self._obtener(identificador)
            if p['estado'] != 'confirmada':
                _fallo('autorizacion_no_disponible')
            try:
                a = self._autorizaciones.pop(autorizacion, None)
            except TypeError:
                a = None
            if a is None:
                _fallo('autorizacion_no_disponible')
            if a['identificador'] != identificador:
                _fallo('autorizacion_no_coincidente')
            p['estado'] = 'consumida'
            ahora = self._ahora()
            if (not a['inicio'] <= ahora < a['vence'] or any(a[k] != p[k] for k in
                    ('revision', 'contenido', 'informe', 'formato', 'destino'))):
                _fallo('autorizacion_no_vigente')
            return EntregaExportacion(p['formato'], p['destino'], p['contenido'])
