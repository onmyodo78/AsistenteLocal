"""Clasificación sintética: mensajes privados nunca abandonan la memoria."""
import contextlib
import io
import json
import unittest

import apt_debian as apt
import test_apt_debian as fixtures


class MensajeApt(unittest.TestCase):
    def test_patrones_cerrados(self):
        for mensaje, esperado in [
            ('E:fallo (13: Permission denied)', 'permisos'),
            ('E:fallo (1: Operation not permitted)', 'permisos'),
            ('E:Could not open file /privado/SECRETO', 'apertura_archivo'),
            ('E:Unable to mkstemp /privado/SECRETO', 'temporal'),
            ('E:Could not create temporary file for /privado/SECRETO', 'temporal'),
            ('E:Dynamic MMap ran out of room. SECRETO', 'memoria'),
            ("E:Couldn't make mmap of 12345 bytes", 'memoria'),
            ('E:Syntax error /privado/SECRETO', 'configuracion'),
            ('E:Encountered a section with no Package: header SECRETO', 'datos_invalidos')]:
            with self.subTest(esperado=esperado):
                dato=apt._diagnostico('abrir_cache',SystemError(mensaje))
                self.assertEqual(dato['categoria_mensaje'],esperado)
                self.assertIsNone(dato['errno'])
                self.assertNotIn('SECRETO',json.dumps(dato))
                self.assertNotIn('/privado',json.dumps(dato))

    def test_ambiguedad_desconocidos_y_limite(self):
        for mensaje in ('', 'SECRETO', 'Permission denied',
            '/privado/Unable to mkstemp',
            'E:Could not open file SECRETO (13: Permission denied)',
            'E:Unable to mkstemp SECRETO, E:Cannot allocate memory',
            'E:Syntax error '+('x'*apt.MAX_STDERR)):
            with self.subTest(mensaje=mensaje[:30]):
                self.assertEqual(apt._clasificar_mensaje(SystemError(mensaje)), 'indeterminado')
        class NoConvertible(SystemError):
            def __str__(self):
                raise RuntimeError('SECRETO')
        self.assertEqual(apt._clasificar_mensaje(NoConvertible()),'indeterminado')

    def test_transporte_y_contrato_publico_sin_mensaje(self):
        dato=apt._diagnostico('abrir_cache',SystemError('E:Unable to mkstemp /privado/SECRETO'))
        contenido=(apt.PREFIJO_DIAGNOSTICO+json.dumps(dato)+'\n').encode()
        with contextlib.redirect_stderr(io.StringIO()) as stderr:
            resultado=fixtures.AptLocal().adquirir('',codigo=72,stderr=contenido)
        publicado=json.loads(stderr.getvalue().removeprefix(apt.PREFIJO_DIAGNOSTICO))
        self.assertEqual(publicado['categoria_mensaje'],'temporal')
        self.assertEqual(resultado['codigo'],72)
        self.assertEqual(resultado['estado_adquisicion'],'error')
        self.assertNotIn('categoria_mensaje',resultado)
        self.assertNotIn('SECRETO',json.dumps(resultado)+stderr.getvalue())
        dato['categoria_mensaje']='SECRETO'
        with contextlib.redirect_stderr(io.StringIO()) as stderr:
            apt._reenviar_diagnostico((apt.PREFIJO_DIAGNOSTICO+json.dumps(dato)).encode(),72)
        self.assertEqual(stderr.getvalue(),'')
