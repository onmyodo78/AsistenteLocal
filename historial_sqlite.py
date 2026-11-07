"""Motor experimental independiente, exclusivamente SQLite :memory:.

No abre rutas ni acepta conexiones externas. Sin integración, adquisición,
exportación, migración, retención o guardado automático. Cerrar destruye los datos.
"""
from datetime import datetime, timezone
import json
import sqlite3

from historial_contratos import validar

VERSION_ESQUEMA = 1
MAX_RESULTADOS = 100
MAX_EVENTOS = 100
MAX_LOTE_BYTES = 1024 * 1024
MAX_CONSULTA = 100
EVENTOS = frozenset(('fuente_ausente', 'limite_alcanzado', 'campos_omitidos_privacidad',
                     'finalizacion_parcial', 'observacion_no_verificada'))

ESQUEMA = (
    """CREATE TABLE auditorias (
        id INTEGER PRIMARY KEY,
        inicio_utc TEXT NOT NULL, fin_utc TEXT NOT NULL, guardado_utc TEXT NOT NULL,
        distribucion TEXT NOT NULL CHECK(distribucion IN ('fedora','debian13')),
        version_esquema INTEGER NOT NULL CHECK(version_esquema=1),
        version_privacidad INTEGER NOT NULL CHECK(version_privacidad=1),
        autorizacion TEXT NOT NULL CHECK(autorizacion='manual'),
        CHECK(inicio_utc <= fin_utc)
    ) STRICT""",
    """CREATE TABLE resultados (
        id INTEGER PRIMARY KEY,
        auditoria_id INTEGER NOT NULL REFERENCES auditorias(id),
        orden INTEGER NOT NULL CHECK(orden>=0 AND orden<100),
        registro_json TEXT NOT NULL CHECK(length(CAST(registro_json AS BLOB))<=8192),
        UNIQUE(auditoria_id,orden), UNIQUE(auditoria_id,id)
    ) STRICT""",
    """CREATE TABLE eventos (
        id INTEGER PRIMARY KEY,
        auditoria_id INTEGER NOT NULL REFERENCES auditorias(id),
        resultado_id INTEGER,
        orden INTEGER NOT NULL CHECK(orden>=0 AND orden<100),
        tipo TEXT NOT NULL CHECK(tipo IN ('fuente_ausente','limite_alcanzado',
          'campos_omitidos_privacidad','finalizacion_parcial','observacion_no_verificada')),
        cantidad INTEGER CHECK(cantidad>=0),
        UNIQUE(auditoria_id,orden),
        FOREIGN KEY(auditoria_id,resultado_id) REFERENCES resultados(auditoria_id,id)
    ) STRICT""",
)


class ErrorHistorial(ValueError):
    """Error cerrado sin texto SQLite, SQL, parámetros ni datos originales."""


def _fallo():
    raise ErrorHistorial('historial_invalido')


def _fecha(valor):
    if type(valor) is not str or len(valor) != 20:
        _fallo()
    try:
        fecha = datetime.strptime(valor, '%Y-%m-%dT%H:%M:%SZ')
    except ValueError:
        _fallo()
    if fecha.strftime('%Y-%m-%dT%H:%M:%SZ') != valor:
        _fallo()
    return valor


def _claves(d, claves):
    if type(d) is not dict or set(d) != set(claves):
        _fallo()


def _entero(v, minimo, maximo):
    if type(v) is not int or not minimo <= v <= maximo:
        _fallo()
    return v


def _lote(auditoria, resultados, eventos):
    _claves(auditoria, ('inicio_utc', 'fin_utc', 'distribucion', 'autorizacion'))
    inicio, fin = _fecha(auditoria['inicio_utc']), _fecha(auditoria['fin_utc'])
    if inicio > fin or auditoria['distribucion'] not in ('fedora', 'debian13') or auditoria['autorizacion'] != 'manual':
        _fallo()
    if type(resultados) is not list or not 1 <= len(resultados) <= MAX_RESULTADOS:
        _fallo()
    if type(eventos) is not list or len(eventos) > MAX_EVENTOS:
        _fallo()
    serializados = []
    try:
        for resultado in resultados:
            registro = validar(resultado)
            if registro['distribucion'] != auditoria['distribucion']:
                _fallo()
            serializados.append(json.dumps(registro, ensure_ascii=True, allow_nan=False,
                                           separators=(',', ':')))
    except (ValueError, TypeError, KeyError, RecursionError):
        _fallo()
    saneados = []
    for evento in eventos:
        _claves(evento, ('tipo', 'resultado_orden', 'cantidad'))
        if type(evento['tipo']) is not str or evento['tipo'] not in EVENTOS:
            _fallo()
        orden = evento['resultado_orden']
        if orden is not None:
            _entero(orden, 0, len(resultados)-1)
        cantidad = evento['cantidad']
        if cantidad is not None:
            _entero(cantidad, 0, 2**63-1)
        saneados.append((evento['tipo'], orden, cantidad))
    if sum(len(s.encode()) for s in serializados) + len(json.dumps(saneados).encode()) > MAX_LOTE_BYTES:
        _fallo()
    return dict(auditoria), serializados, saneados


class HistorialMemoria:
    """API sin parámetros de ruta. Una conexión privada por instancia; no compartir hilos."""

    def __init__(self):
        self._conexion = sqlite3.connect(':memory:', isolation_level=None)
        try:
            self._conexion.execute('PRAGMA foreign_keys=ON')
            self._conexion.execute('PRAGMA temp_store=MEMORY')
            self._conexion.execute('PRAGMA journal_mode=MEMORY')
            self._conexion.execute('BEGIN')
            for sentencia in ESQUEMA:
                self._conexion.execute(sentencia)
            self._conexion.execute('PRAGMA user_version=1')
            self._conexion.execute('COMMIT')
        except sqlite3.Error:
            self._conexion.close()
            raise ErrorHistorial('inicializacion_no_disponible') from None

    def _comprobar(self):
        if self._conexion.execute('PRAGMA user_version').fetchone()[0] != VERSION_ESQUEMA:
            raise ErrorHistorial('version_esquema_incompatible')
        if self._conexion.execute('PRAGMA foreign_keys').fetchone()[0] != 1:
            raise ErrorHistorial('integridad_no_disponible')
        if self._conexion.in_transaction:
            raise ErrorHistorial('transaccion_externa_no_admitida')

    def guardar_auditoria(self, auditoria, resultados, eventos=None):
        """Guarda un lote validado, atómicamente. Eventos usan índices de resultado del lote.

        Devuelve el id interno; 'manual' es metadato, no una comprobación de consentimiento.
        El futuro controlador deberá obtener la autorización antes de llamar a este método.
        """
        try:
            self._comprobar()
            a, registros, e = _lote(auditoria, resultados, [] if eventos is None else eventos)
            self._conexion.execute('BEGIN IMMEDIATE')
            try:
                cursor = self._conexion.execute(
                    'INSERT INTO auditorias(inicio_utc,fin_utc,guardado_utc,distribucion,version_esquema,version_privacidad,autorizacion) VALUES(?,?,?,?,1,1,?)',
                    (a['inicio_utc'], a['fin_utc'], datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                     a['distribucion'], a['autorizacion']))
                ident = cursor.lastrowid
                ids = []
                for orden, registro in enumerate(registros):
                    ids.append(self._conexion.execute(
                        'INSERT INTO resultados(auditoria_id,orden,registro_json) VALUES(?,?,?)',
                        (ident, orden, registro)).lastrowid)
                for orden, (tipo, indice, cantidad) in enumerate(e):
                    self._conexion.execute('INSERT INTO eventos(auditoria_id,resultado_id,orden,tipo,cantidad) VALUES(?,?,?,?,?)',
                        (ident, None if indice is None else ids[indice], orden, tipo, cantidad))
                self._conexion.execute('COMMIT')
                return ident
            except BaseException:
                self._conexion.execute('ROLLBACK')
                raise
        except sqlite3.Error:
            raise ErrorHistorial('persistencia_fallida') from None

    def listar_auditorias(self, limite=MAX_CONSULTA, despues_id=0):
        """Consulta paginada sin DDL ni escritura; ids ordenados ascendentemente."""
        try:
            self._comprobar()
            _entero(limite, 1, MAX_CONSULTA)
            _entero(despues_id, 0, 2**63-1)
            filas = self._conexion.execute('SELECT id,inicio_utc,fin_utc,guardado_utc,distribucion,version_esquema,version_privacidad,autorizacion FROM auditorias WHERE id>? ORDER BY id LIMIT ?',
                                           (despues_id, limite)).fetchall()
            claves = ('id', 'inicio_utc', 'fin_utc', 'guardado_utc', 'distribucion',
                      'version_esquema', 'version_privacidad', 'autorizacion')
            return [dict(zip(claves, f)) for f in filas]
        except sqlite3.Error:
            raise ErrorHistorial('consulta_fallida') from None

    def consultar_resultados(self, auditoria_id):
        try:
            self._comprobar()
            _entero(auditoria_id, 1, 2**63-1)
            filas = self._conexion.execute('SELECT id,orden,registro_json FROM resultados WHERE auditoria_id=? ORDER BY orden', (auditoria_id,)).fetchall()
            return [dict(id=i, orden=o, registro=validar(json.loads(r))) for i,o,r in filas]
        except (sqlite3.Error, ValueError, TypeError, KeyError, RecursionError):
            raise ErrorHistorial('consulta_fallida') from None

    def consultar_eventos(self, auditoria_id):
        try:
            self._comprobar()
            _entero(auditoria_id, 1, 2**63-1)
            filas = self._conexion.execute('SELECT id,resultado_id,orden,tipo,cantidad FROM eventos WHERE auditoria_id=? ORDER BY orden', (auditoria_id,)).fetchall()
            return [dict(zip(('id','resultado_id','orden','tipo','cantidad'), f)) for f in filas]
        except sqlite3.Error:
            raise ErrorHistorial('consulta_fallida') from None

    def cerrar(self):
        self._conexion.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.cerrar()
