"""Persistencia exclusivamente :memory:, sin adquisición de herramientas."""
import sqlite3
import unittest
from unittest.mock import patch

import historial_contratos as contratos
import historial_sqlite as motor


def auditoria():
    return dict(inicio_utc='2026-11-05T12:00:00Z', fin_utc='2026-11-05T12:01:00Z',
                distribucion='debian13', autorizacion='manual')


def resultado():
    return contratos.estado_conocido('sistema', 'debian13', 'no_verificado')


def evento(indice=0):
    return dict(tipo='observacion_no_verificada', resultado_orden=indice, cantidad=None)


class SQLiteHistorial(unittest.TestCase):
    def setUp(self):
        self.h = motor.HistorialMemoria()
        self.addCleanup(self.h.cerrar)

    def conteos(self):
        return tuple(self.h._conexion.execute('SELECT count(*) FROM '+tabla).fetchone()[0]
                     for tabla in ('auditorias', 'resultados', 'eventos'))

    def test_solo_memoria_sin_rutas(self):
        self.assertEqual(self.h._conexion.execute('PRAGMA database_list').fetchall()[0][2], '')
        self.assertEqual(self.h._conexion.execute('PRAGMA temp_store').fetchone()[0], 2)
        self.assertEqual(self.h._conexion.execute('PRAGMA journal_mode').fetchone()[0], 'memory')
        with self.assertRaises(TypeError):
            motor.HistorialMemoria('/tmp/no-permitido.sqlite')

    def test_esquema_y_version(self):
        tablas = self.h._conexion.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()
        self.assertEqual(tablas, [('auditorias',), ('eventos',), ('resultados',)])
        self.assertEqual(self.h._conexion.execute('PRAGMA user_version').fetchone()[0], 1)
        self.assertEqual(self.h._conexion.execute('PRAGMA foreign_keys').fetchone()[0], 1)

    def test_insercion_y_roundtrip(self):
        r = resultado()
        ident = self.h.guardar_auditoria(auditoria(), [r], [evento(), evento(None)])
        self.assertEqual(self.conteos(), (1, 1, 2))
        self.assertEqual(self.h.consultar_resultados(ident)[0]['registro'], r)
        e = self.h.consultar_eventos(ident)
        self.assertEqual(e[0]['resultado_id'], self.h.consultar_resultados(ident)[0]['id'])
        self.assertIsNone(e[1]['resultado_id'])
        self.assertEqual(self.h.listar_auditorias()[0]['version_privacidad'], 1)
        self.assertEqual(self.h._conexion.execute('PRAGMA foreign_key_check').fetchall(), [])

    def test_registros_repetidos_permitidos_ordenes_unicos(self):
        ident = self.h.guardar_auditoria(auditoria(), [resultado(), resultado()])
        filas = self.h.consultar_resultados(ident)
        self.assertEqual([f['orden'] for f in filas], [0, 1])
        self.assertNotEqual(filas[0]['id'], filas[1]['id'])
        with self.assertRaises(sqlite3.IntegrityError):
            self.h._conexion.execute('INSERT INTO resultados(auditoria_id,orden,registro_json) VALUES(?,?,?)', (ident, 0, '{}'))
        self.assertEqual(self.conteos(), (1, 2, 0))

    def test_claves_foraneas_y_eventos_misma_auditoria(self):
        a = self.h.guardar_auditoria(auditoria(), [resultado()], [evento()])
        b = self.h.guardar_auditoria(auditoria(), [resultado()])
        rid = self.h.consultar_resultados(a)[0]['id']
        for aid, r in ((b, rid), (9999, None), (a, 9999)):
            with self.assertRaises(sqlite3.IntegrityError):
                self.h._conexion.execute('INSERT INTO eventos(auditoria_id,resultado_id,orden,tipo) VALUES(?,?,?,?)',
                    (aid, r, 1, 'fuente_ausente'))
        with self.assertRaises(sqlite3.IntegrityError):
            self.h._conexion.execute('INSERT INTO resultados(auditoria_id,orden,registro_json) VALUES(?,?,?)', (999, 0, '{}'))

    def test_duplicados_eventos_e_ids_rechazados(self):
        a = self.h.guardar_auditoria(auditoria(), [resultado()], [evento()])
        e = self.h.consultar_eventos(a)[0]
        with self.assertRaises(sqlite3.IntegrityError):
            self.h._conexion.execute('INSERT INTO eventos(id,auditoria_id,orden,tipo) VALUES(?,?,?,?)',
                (e['id'], a, 1, 'fuente_ausente'))
        with self.assertRaises(sqlite3.IntegrityError):
            self.h._conexion.execute('INSERT INTO eventos(auditoria_id,orden,tipo) VALUES(?,?,?)', (a, 0, 'fuente_ausente'))

    def test_validacion_antes_de_insertar(self):
        malo = resultado()
        malo['metricas']['usuario'] = '/privado'
        with self.assertRaises(motor.ErrorHistorial):
            self.h.guardar_auditoria(auditoria(), [resultado(), malo], [evento()])
        self.assertEqual(self.conteos(), (0, 0, 0))
        self.assertFalse(self.h._conexion.in_transaction)

    def test_fallo_durante_insercion_resultado_rollback(self):
        self.h._conexion.execute("CREATE TRIGGER fallo BEFORE INSERT ON resultados WHEN NEW.orden=1 BEGIN SELECT RAISE(ABORT,'dato privado'); END")
        with self.assertRaisesRegex(motor.ErrorHistorial, '^persistencia_fallida$'):
            self.h.guardar_auditoria(auditoria(), [resultado(), resultado()], [evento()])
        self.assertEqual(self.conteos(), (0, 0, 0))
        self.assertFalse(self.h._conexion.in_transaction)

    def test_fallo_evento_rollback_conserva_auditoria_anterior(self):
        anterior = self.h.guardar_auditoria(auditoria(), [resultado()])
        self.h._conexion.execute("CREATE TRIGGER fallo BEFORE INSERT ON eventos BEGIN SELECT RAISE(ABORT,'privado'); END")
        with self.assertRaises(motor.ErrorHistorial):
            self.h.guardar_auditoria(auditoria(), [resultado()], [evento()])
        self.assertEqual(self.conteos(), (1, 1, 0))
        self.assertEqual(self.h.listar_auditorias()[0]['id'], anterior)

    def test_versiones_incompatibles_sin_migraciones(self):
        for v in (0, 2, 999):
            self.h._conexion.execute('PRAGMA user_version='+str(v))
            antes = self.h._conexion.total_changes
            with self.assertRaises(motor.ErrorHistorial):
                self.h.guardar_auditoria(auditoria(), [resultado()])
            self.assertEqual(self.h._conexion.total_changes, antes)
            self.assertEqual(self.h._conexion.execute('PRAGMA user_version').fetchone()[0], v)
        self.h._conexion.execute('PRAGMA user_version=1')
        self.assertEqual(self.conteos(), (0, 0, 0))

    def test_consultas_no_escriben_y_copias_independientes(self):
        ident = self.h.guardar_auditoria(auditoria(), [resultado()])
        antes = (self.h._conexion.total_changes, self.h._conexion.serialize())
        self.h._conexion.execute('PRAGMA query_only=ON')
        self.h.listar_auditorias()
        r = self.h.consultar_resultados(ident)
        self.h.consultar_eventos(ident)
        self.assertEqual(antes, (self.h._conexion.total_changes, self.h._conexion.serialize()))
        r[0]['registro']['metricas']['privado'] = 1
        self.assertNotIn('privado', self.h.consultar_resultados(ident)[0]['registro']['metricas'])

    def test_paginacion_y_consulta_ausente(self):
        a = self.h.guardar_auditoria(auditoria(), [resultado()])
        b = self.h.guardar_auditoria(auditoria(), [resultado()])
        self.assertEqual(self.h.listar_auditorias(limite=1)[0]['id'], a)
        self.assertEqual(self.h.listar_auditorias(despues_id=a)[0]['id'], b)
        self.assertEqual(self.h.consultar_resultados(999), [])
        self.assertEqual(self.h.consultar_eventos(999), [])

    def test_metadatos_fechas_y_distro_invalidos(self):
        for k, v in (('inicio_utc', '/privado'), ('fin_utc', '2026-11-05T11:00:00Z'),
                     ('distribucion', 'ubuntu'), ('autorizacion', 'automatico')):
            d = auditoria()
            d[k] = v
            with self.assertRaises(motor.ErrorHistorial):
                self.h.guardar_auditoria(d, [resultado()])
        d = auditoria()
        d['hostname'] = 'privado'
        with self.assertRaises(motor.ErrorHistorial):
            self.h.guardar_auditoria(d, [resultado()])
        self.assertEqual(self.conteos(), (0, 0, 0))

    def test_eventos_no_admiten_texto_privado_o_referencia_externa(self):
        for k, v in (('tipo', 'usuario-privado'), ('cantidad', '/privado'),
                     ('cantidad', True), ('resultado_orden', 99), ('resultado_id', 123)):
            e = evento()
            e[k] = v
            with self.assertRaises(motor.ErrorHistorial):
                self.h.guardar_auditoria(auditoria(), [resultado()], [e])
        self.assertEqual(self.conteos(), (0, 0, 0))

    def test_privacidad_tipos_y_versiones_contrato(self):
        for mutar in (lambda r: r.update(hostname='privado'),
                      lambda r: r.update(version=2),
                      lambda r: r['metricas'].update(ruta='/privado'),
                      lambda r: r.update(procedencia='privado'),
                      lambda r: r.update(componentes={'usuario': {}})):
            r = resultado()
            mutar(r)
            with self.assertRaisesRegex(motor.ErrorHistorial, '^historial_invalido$'):
                self.h.guardar_auditoria(auditoria(), [r])
        self.assertEqual(self.conteos(), (0, 0, 0))

    def test_limites_lote_y_registros(self):
        for r, e in (([], []), ([resultado()]*(motor.MAX_RESULTADOS+1), []),
                     ([resultado()], [evento()]*(motor.MAX_EVENTOS+1))):
            with self.assertRaises(motor.ErrorHistorial):
                self.h.guardar_auditoria(auditoria(), r, e)
        with patch.object(motor, 'MAX_LOTE_BYTES', 10):
            with self.assertRaises(motor.ErrorHistorial):
                self.h.guardar_auditoria(auditoria(), [resultado()])
        registro = resultado()
        with patch.object(contratos, 'MAX_REGISTRO_BYTES', 10):
            with self.assertRaises(motor.ErrorHistorial):
                self.h.guardar_auditoria(auditoria(), [registro])
        self.assertEqual(self.conteos(), (0, 0, 0))

    def test_integridad_desactivada_y_transaccion_externa(self):
        self.h._conexion.execute('PRAGMA foreign_keys=OFF')
        with self.assertRaises(motor.ErrorHistorial):
            self.h.guardar_auditoria(auditoria(), [resultado()])
        self.h._conexion.execute('PRAGMA foreign_keys=ON')
        self.h._conexion.execute('BEGIN')
        with self.assertRaises(motor.ErrorHistorial):
            self.h.guardar_auditoria(auditoria(), [resultado()])
        self.assertTrue(self.h._conexion.in_transaction)
        self.h._conexion.execute('ROLLBACK')

    def test_fedora_y_debian_no_se_mezclan(self):
        d = auditoria()
        d['distribucion'] = 'fedora'
        with self.assertRaises(motor.ErrorHistorial):
            self.h.guardar_auditoria(d, [resultado()])
        r = contratos.estado_conocido('auditoria_seguridad', 'fedora', 'no_ejecutado')
        self.h.guardar_auditoria(d, [r])
        self.assertEqual(self.conteos(), (1, 1, 0))

    def test_sin_io_adquisiciones_y_cierre(self):
        with patch('builtins.open', side_effect=AssertionError('archivo')), \
             patch('subprocess.Popen', side_effect=AssertionError('adquisicion')):
            with motor.HistorialMemoria() as h:
                h.guardar_auditoria(auditoria(), [resultado()])
                h.listar_auditorias()
            with self.assertRaises(motor.ErrorHistorial):
                h.listar_auditorias()
