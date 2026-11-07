"""Controlador sin escritor: datos sintéticos y destinos que nunca se abren."""
import builtins
import copy
import json
import unittest
from unittest.mock import patch

import exportacion_controlador as c
from exportacion_generadores import generar_csv, generar_markdown
from test_informe_exportacion import informe, memoria, FECHA


class ControladorExportacion(unittest.TestCase):
    def setUp(self):
        self.ahora = 100.
        self.control = c.ControladorExportacion(reloj=lambda: self.ahora)
        self.control.activar()
        self.addCleanup(self.control.desactivar)

    def preparar(self, formato='md', destino=None):
        return self.control.preparar(informe(), formato=formato,
            destino=destino or '/destino-privado/informe.'+formato)

    def confirmar(self, ident):
        return self.control.confirmar(ident, self.control.vista_previa(ident), confirmacion=True)

    def test_desactivado_por_defecto(self):
        control = c.ControladorExportacion()
        with self.assertRaises(c.ErrorExportacion):
            control.preparar(informe(), formato='md', destino='/informe.md')

    def test_mismos_datos_dos_formatos_en_memoria(self):
        d = informe()
        antes = copy.deepcopy(d)
        for formato, generador in (('md', generar_markdown), ('csv', generar_csv)):
            ident = self.control.preparar(d, formato=formato, destino='/informe.'+formato)
            vista = self.control.vista_previa(ident)
            self.assertEqual(vista['formato'], formato)
            self.assertEqual(vista['tamano_bytes'], len(generador(d)))
            self.assertFalse(vista['escritura_implementada'])
            entrega = self.control.consumir(ident, self.confirmar(ident))
            self.assertEqual(entrega.contenido, generador(d))
            self.assertEqual(entrega.destino, '/informe.'+formato)
        self.assertEqual(d, antes)

    def test_vista_privada_determinista_y_estados(self):
        ident = self.preparar()
        vista = self.control.vista_previa(ident)
        self.assertEqual(vista, self.control.vista_previa(ident))
        r = vista['resultados'][0]
        self.assertEqual(r['ejecucion'], 'correcto')
        self.assertIn('cobertura', r)
        self.assertIn('identidades_excluidas', r['omisiones'])
        self.assertNotIn('destino-privado', json.dumps(vista))
        entrega = self.control.consumir(ident, self.confirmar(ident))
        self.assertNotIn('destino-privado', repr(entrega))

    def test_sin_confirmacion_y_confirmaciones_implicitas(self):
        ident = self.preparar()
        for valor in (False, None, 1, 'manual', 'si', {'lmstudio': True}):
            with self.assertRaises(c.ErrorExportacion):
                self.control.confirmar(ident, self.control.vista_previa(ident), confirmacion=valor)
        with self.assertRaises(c.ErrorExportacion):
            self.control.consumir(ident)

    def test_rechaza_json_en_todas_las_entradas(self):
        for formato in ('json', 'markdown', 'xlsx', 'MD', None):
            with self.assertRaises(c.ErrorExportacion):
                self.control.preparar(informe(), formato=formato, destino='/informe.json')
            with self.assertRaises(c.ErrorExportacion):
                self.control.preparar_desde_registros([memoria()], formato=formato,
                    destino='/informe.json', fecha_preparacion_utc=FECHA)
        ident = self.preparar()
        token = self.confirmar(ident)
        with self.assertRaises(c.ErrorExportacion):
            self.control.reemplazar(ident, informe(), formato='json', destino='/informe.json')
        with self.assertRaises(c.ErrorExportacion):
            self.control.consumir(ident, token)

    def test_caducidad_y_retroceso_reloj(self):
        for ahora in (400., 99.):
            self.ahora = 100.
            ident = self.preparar()
            token = self.confirmar(ident)
            self.ahora = ahora
            with self.assertRaises(c.ErrorExportacion):
                self.control.consumir(ident, token)
            with self.assertRaises(c.ErrorExportacion):
                self.control.consumir(ident, token)

    def test_cancelacion_y_desactivacion(self):
        ident = self.preparar()
        token = self.confirmar(ident)
        self.control.cancelar(ident)
        with self.assertRaises(c.ErrorExportacion):
            self.control.consumir(ident, token)
        ident = self.preparar()
        token = self.confirmar(ident)
        self.control.desactivar()
        self.control.activar()
        with self.assertRaises(c.ErrorExportacion):
            self.control.consumir(ident, token)

    def test_uso_unico_y_autorizacion_especifica(self):
        a, b = self.preparar(), self.preparar()
        ta, tb = self.confirmar(a), self.confirmar(b)
        self.control.consumir(a, ta)
        with self.assertRaises(c.ErrorExportacion):
            self.control.consumir(a, ta)
        self.control.consumir(b, tb)
        a, b = self.preparar(), self.preparar()
        ta = self.confirmar(a)
        self.confirmar(b)
        with self.assertRaises(c.ErrorExportacion):
            self.control.consumir(b, ta)
        with self.assertRaises(c.ErrorExportacion):
            self.control.consumir(a, ta)

    def test_cambios_contenido_formato_destino_revocan(self):
        for cambio in ('contenido', 'formato', 'destino'):
            ident = self.preparar()
            token = self.confirmar(ident)
            d = informe()
            formato, destino = 'md', '/destino-privado/informe.md'
            if cambio == 'contenido':
                r = memoria()
                r['metricas']['ram_libre_bytes'] = None
                d = informe([r])
            elif cambio == 'formato':
                formato, destino = 'csv', '/destino-privado/informe.csv'
            else:
                destino = '/otro-destino/informe.md'
            vieja = self.control.vista_previa(ident)
            self.control.reemplazar(ident, d, formato=formato, destino=destino)
            with self.assertRaises(c.ErrorExportacion):
                self.control.consumir(ident, token)
            with self.assertRaises(c.ErrorExportacion):
                self.control.confirmar(ident, vieja, confirmacion=True)
            self.control.consumir(ident, self.confirmar(ident))

    def test_instantanea_aislada_y_vista_modificada(self):
        d = informe()
        ident = self.control.preparar(d, formato='md', destino='/informe.md')
        vista = self.control.vista_previa(ident)
        d['resultados'][0]['origen']['hostname'] = 'privado'
        self.assertEqual(vista, self.control.vista_previa(ident))
        vista['tamano_bytes'] = 0
        with self.assertRaises(c.ErrorExportacion):
            self.control.confirmar(ident, vista, confirmacion=True)

    def test_sin_filtracion_en_errores_y_rechazo_campos_privados(self):
        d = informe()
        d['hostname'] = '/privado'
        with self.assertRaisesRegex(c.ErrorExportacion, '^preparacion_no_valida$'):
            self.control.preparar(d, formato='md', destino='/informe.md')
        with self.assertRaisesRegex(c.ErrorExportacion, '^destino_no_admitido$'):
            self.control.preparar(informe(), formato='md', destino='/privado/../informe.md')

    def test_destinos_lexicos_sin_acceso_sistema_archivos(self):
        for ruta in ('informe.md', '//informe.md', '/a/../informe.md', '/a/./informe.md',
                     '/a//informe.md', '/informe.csv', '/.informe.md', '/informe.md\n', '/informe.md/'):
            with self.assertRaises(c.ErrorExportacion):
                self.preparar(destino=ruta)

    def test_preparacion_desde_registros(self):
        ident = self.control.preparar_desde_registros([memoria()], formato='csv',
            destino='/informe.csv', fecha_preparacion_utc=FECHA)
        entrega = self.control.consumir(ident, self.confirmar(ident))
        self.assertEqual(entrega.contenido, generar_csv(informe()))

    def test_reconfirmar_invalida_token_anterior(self):
        ident = self.preparar()
        viejo = self.confirmar(ident)
        nuevo = self.confirmar(ident)
        with self.assertRaises(c.ErrorExportacion):
            self.control.consumir(ident, viejo)
        self.control.consumir(ident, nuevo)

    def test_limites_y_fallo_generador(self):
        with patch.object(c, 'MAX_PREPARACIONES', 1):
            self.preparar()
            with self.assertRaises(c.ErrorExportacion):
                self.preparar()
        self.control.desactivar()
        self.control.activar()
        with patch.object(c, 'generar_markdown', side_effect=ValueError('/privado')):
            with self.assertRaisesRegex(c.ErrorExportacion, '^preparacion_no_valida$'):
                self.preparar()
        self.assertEqual(self.control._preparadas, {})

    def test_ausencia_io_adquisiciones_sqlite(self):
        d = informe()
        importar = builtins.__import__
        def prohibir(nombre, *args, **kw):
            if 'sqlite' in nombre or nombre in ('historial_controlador', 'historial_persistente'):
                raise AssertionError('sqlite')
            return importar(nombre, *args, **kw)
        with patch('builtins.__import__', side_effect=prohibir), \
             patch('builtins.open', side_effect=AssertionError('archivo')), \
             patch('os.open', side_effect=AssertionError('descriptor')), \
             patch('os.mkdir', side_effect=AssertionError('directorio')), \
             patch('subprocess.Popen', side_effect=AssertionError('adquisicion')):
            ident = self.control.preparar(d, formato='md', destino='/informe.md')
            self.control.consumir(ident, self.confirmar(ident))
