"""Diario SQLite duradero. El ejecutor usa una ruta fija protegida por root."""
from contextlib import contextmanager,closing
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import stat

DIRECTORIO = Path('/var/lib/asistentelocal')
FINALES = ('completo','cancelado','fallido','incompleto','resultado_desconocido')


def utc():
    return datetime.now(timezone.utc).isoformat()


def seguro(p, uid, directorio=False):
    s=p.lstat()
    if (s.st_uid != uid or stat.S_ISLNK(s.st_mode)
            or (not stat.S_ISDIR(s.st_mode) if directorio else not stat.S_ISREG(s.st_mode))
            or stat.S_IMODE(s.st_mode) != (0o700 if directorio else 0o600)
            or (not directorio and s.st_nlink != 1)):
        raise PermissionError('registro_no_protegido')


def proteger_padres(directorio):
    if Path(directorio)==DIRECTORIO:
        for padre in DIRECTORIO.parents:
            st=padre.lstat()
            if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022:
                raise PermissionError('registro_no_protegido')


class Registro:
    def __init__(self, directorio=DIRECTORIO, *, uid=0):
        self.directorio=Path(directorio)
        self.uid=uid
        self.db=None
        self.lock=None

    def __enter__(self):
        proteger_padres(self.directorio)
        self.directorio.mkdir(mode=0o700, exist_ok=True)
        seguro(self.directorio,self.uid,True)
        p=self.directorio/'ejecucion.lock'
        fd=os.open(p,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        self.lock=fd
        try:
            seguro(p,self.uid)
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            base=self.directorio/'mantenimiento.sqlite3'
            if not base.exists():
                nuevo=os.open(base,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                os.close(nuevo)
            seguro(base,self.uid)
            self.db=sqlite3.connect(base,timeout=0,isolation_level=None)
            self.db.execute('PRAGMA trusted_schema=OFF')
            self.db.execute('PRAGMA foreign_keys=ON')
            self.db.execute('PRAGMA synchronous=FULL')
            self.db.execute('PRAGMA journal_mode=DELETE')
            version=self.db.execute('PRAGMA user_version').fetchone()[0]
            if version not in (0,1): raise ValueError('registro_version_no_admitida')
            if version==0:
                with self.transaccion():
                    self.db.execute('''CREATE TABLE operaciones (
                        id TEXT PRIMARY KEY, uid INTEGER NOT NULL, inicio TEXT NOT NULL,
                        fin TEXT, digest TEXT NOT NULL, plan_json TEXT NOT NULL,
                        politica_json TEXT NOT NULL, estado TEXT NOT NULL,
                        error TEXT, resultado_json TEXT) STRICT''')
                    self.db.execute('''CREATE TABLE eventos (
                        id INTEGER PRIMARY KEY, operacion TEXT NOT NULL REFERENCES operaciones(id),
                        fecha TEXT NOT NULL, estado TEXT NOT NULL, detalle_json TEXT NOT NULL) STRICT''')
                    self.db.execute('PRAGMA user_version=1')
            return self
        except BaseException:
            self.__exit__(None,None,None)
            raise

    @contextmanager
    def transaccion(self):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            yield
            self.db.execute('COMMIT')
        except BaseException:
            if self.db.in_transaction:self.db.execute('ROLLBACK')
            raise

    def iniciar(self,p):
        with self.transaccion():
            if self.db.execute('SELECT 1 FROM operaciones WHERE id=?',(p['id'],)).fetchone():
                raise ValueError('autorizacion_consumida')
            if self.db.execute("SELECT 1 FROM operaciones WHERE estado NOT IN ('completo','cancelado','fallido')").fetchone():
                raise ValueError('operacion_pendiente_revision')
            self.db.execute('INSERT INTO operaciones VALUES (?,?,?,?,?,?,?,?,?,?)',
                (p['id'],p['uid'],utc(),None,p['digest'],json.dumps(p['plan'],sort_keys=True),
                 json.dumps(p['politica'],sort_keys=True),'autorizada',None,None))
            self._evento(p['id'],'autorizada',{})

    def _evento(self,ident,estado,detalle):
        self.db.execute('INSERT INTO eventos (operacion,fecha,estado,detalle_json) VALUES (?,?,?,?)',
                        (ident,utc(),estado,json.dumps(detalle,ensure_ascii=True,sort_keys=True)))

    def fase(self,ident,estado,detalle=None):
        with self.transaccion():
            self.db.execute('UPDATE operaciones SET estado=? WHERE id=?',(estado,ident))
            self._evento(ident,estado,detalle or {})

    def finalizar(self,ident,estado,error=None,resultado=None):
        if estado not in FINALES: raise ValueError('estado_final_invalido')
        with self.transaccion():
            self.db.execute('UPDATE operaciones SET fin=?,estado=?,error=?,resultado_json=? WHERE id=?',
                (utc(),estado,error,json.dumps(resultado or {},ensure_ascii=True,sort_keys=True),ident))
            self._evento(ident,estado,dict(error=error,resultado=resultado or {}))

    def __exit__(self,*args):
        if self.db is not None:self.db.close();self.db=None
        if self.lock is not None:os.close(self.lock);self.lock=None


def historial(directorio=DIRECTORIO,uid=0):
    d=Path(directorio)
    proteger_padres(d)
    if not d.exists():return []
    seguro(d,uid,True)
    p=d/'mantenimiento.sqlite3'
    if not p.exists():return []
    seguro(p,uid)
    with closing(sqlite3.connect(p.as_uri()+'?mode=ro',uri=True,timeout=0)) as db:
        db.execute('PRAGMA trusted_schema=OFF')
        if db.execute('PRAGMA user_version').fetchone()[0]!=1:raise ValueError('registro_version_no_admitida')
        return [dict(id=r[0],uid=r[1],inicio=r[2],fin=r[3],estado=r[4],error=r[5])
                for r in db.execute('SELECT id,uid,inicio,fin,estado,error FROM operaciones ORDER BY inicio DESC LIMIT 20')]
