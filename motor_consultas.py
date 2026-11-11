"""Clasificación local conservadora y contexto efímero; sin adquisiciones."""
from dataclasses import dataclass
import re
import time
import unicodedata

NOMBRES = ('auditoria_seguridad', 'correlacion_seguridad')
MAX_HECHOS = 2
MAX_TEXTO = 6000
VIDA_SEGUNDOS = 1800


def normalizar(texto):
    return ''.join(c for c in unicodedata.normalize('NFD', texto.lower())
                   if unicodedata.category(c) != 'Mn')


@dataclass(frozen=True)
class Plan:
    nombres: tuple = ()
    reutilizar: bool = False
    conceptual: bool = False
    motivo: str = ''
    local: bool = False

    @property
    def tipo(self):
        if self.nombres or self.reutilizar:
            return 'operativa'
        return 'conceptual' if self.conceptual else 'ambigua'


def _planificar_seguridad(pregunta):
    """Gramática conservadora: conceptos y negaciones nunca fuerzan adquisición.

    Se conserva para el protocolo de auditoría y su contexto de sesión.
    Una comprobación explícita es nueva; solo las referencias al pasado reutilizan.
    """
    texto = normalizar(pregunta)
    conceptual = bool(re.search(r'\b(que es|que significa|como funciona|explica que|para que sirve|diferencia entre)\b', texto))
    negada = bool(re.search(r'\b(no|sin)\s+(?:\w+\s+){0,2}(ejecut|consult|audit|comprob|correlacion|repit|repet)', texto))
    nueva = bool(re.search(r'\b(nueva|nuevo|actualiza|repite|repetir|otra vez|de nuevo|ahora)\b', texto)) and not negada
    reutilizar = not nueva and bool(re.search(
        r'\b(anterior(?:es)?|obtenidos|ya obtenid[oa]s?|reutiliza\w*|sin repetir|sin ejecutar|esos resultados|esos datos)\b', texto))
    nombres = []
    solicitud_breve = bool(re.fullmatch(r'(?:una |la )?auditoria(?: de seguridad)?(?: (?:de|en) debian(?: 13)?)?[.!?]?', texto.strip()))
    accion = bool(re.search(r'\b(audita\w*|comprueba\w*|comprobar|verifica\w*|revisa\w*|realiza\w*|ejecuta\w*|analiza\w*|auditar|repetir|repite|consulta\w*|haz|dame|correlaciona\w*|solicito|quiero|necesito)\b', texto))
    for nombre in NOMBRES:
        literal = nombre in texto
        tema = (bool(re.search(r'\b(auditoria|seguridad|actualizaciones|paquetes)\b', texto))
                if nombre == 'auditoria_seguridad' else
                bool(re.search(r'\b(correlacion|cve|vulnerabilidades)\b', texto)))
        if literal or tema and (accion or reutilizar or solicitud_breve) or nombre == 'auditoria_seguridad' and re.search(r'\baudita\w*\b', texto):
            nombres.append(nombre)
    if conceptual:
        return Plan(tuple(nombres), True) if reutilizar else Plan(conceptual=True)
    if negada and not reutilizar:
        return Plan(conceptual=True)
    return Plan(tuple(nombres), reutilizar)


# IDs cerrados: nunca se derivan comandos ni argumentos del texto.
TEMAS_LOCALES = {
    'memoria': r'\b(memoria|ram|swap)\b',
    'disco': r'\b(disco|espacio|almacenamiento)\b',
    'interfaces_red': r'\b(interfaces?(?:_red)?|tarjetas? de red)\b',
    'vpn': r'\b(vpn|wireguard|tunel)\b',
    'servicios_fallidos': r'\b(servicios?(?:_fallidos)?|systemd)\b',
    'ip_publica': r'\bip publica\b',
    'diagnostico_vpn': r'\bdiagnostico_vpn\b',
    'sistema': r'\b(sistema|kernel|arquitectura)\b',
    'puertos': r'\bpuertos\b',
    'conexiones': r'\bconexiones\b',
    'cortafuegos': r'\b(cortafuegos|firewall)\b',
    'trafico_red': r'\b(trafico_red|trafico de red)\b',
    'listar_documentos': r'\b(listar_documentos|documentos)\b',
}
ACCION = r'\b(comprueba|comprobar|verifica|verificar|revisa|revisar|consulta|consultar|muestra|muestrame|mostrar|dame|dime|lista|listar|ejecuta|ejecutar)\b'
CONCEPTO = r'\b(que es|que son|que significa|como funciona|como funcionan|para que sirve|diferencia entre|explica(?:me)?|que (?:herramientas|comandos|permisos)|(?:es posible|se puede|puedo) (?:comprobar|verificar|consultar|revisar)|como (?:puedo |se puede |debo |podria )?(?:comprobar|verificar|consultar|revisar|ver|saber))\b'
NEGACION = r'\b(no|sin|nunca|tampoco|excepto|salvo)\b'


def planificar(pregunta):
    """No reconocido implica aclaración, nunca autorización delegada al modelo.

    Las cláusulas con negación se excluyen; negaciones de alcance dudoso,
    condicionales y referencias locales al pasado no fuerzan adquisición.
    La gramática de seguridad previa conserva su contrato de sesión.
    """
    texto = normalizar(pregunta).strip()
    locales = any(re.search(patron, texto) for patron in TEMAS_LOCALES.values())
    if re.search(r'\bauditoria\b', texto) and not any(re.search(TEMAS_LOCALES[n], texto) for n in ('memoria', 'disco', 'interfaces_red', 'vpn', 'servicios_fallidos')):
        return _planificar_seguridad(pregunta)
    seguridad = bool(re.search(r'\b(auditoria|audita\w*|seguridad|actualizaciones|paquetes|correlacion|cve|vulnerabilidades|auditoria_seguridad|correlacion_seguridad)\b', texto))
    if not locales and (seguridad or re.search(r'\b(anterior\w*|reutiliza\w*|sin repetir|esos resultados|esos datos)\b', texto)):
        return _planificar_seguridad(pregunta)
    if not locales:
        if re.search(CONCEPTO, texto) or re.fullmatch(r'(hola|buenos dias|buenas tardes)[!.]?', texto):
            return Plan(conceptual=True, motivo='consulta_conceptual')
        return Plan(motivo='solicitud_no_reconocida')
    if re.search(CONCEPTO, texto) and not re.search(r'\b(comprueba|verifica|revisa|consulta|muestra|muestrame|dame|lista|ejecuta)\b', texto):
        return Plan(conceptual=True, motivo='consulta_conceptual', local=True)
    if re.search(r'\b(si|quizas|tal vez|podria|podrias|antes de|despues de|cuando|a menos|o)\b', texto):
        return Plan(motivo='alcance_condicional_o_alternativo', local=True)
    if re.search(r'\b(anterior\w*|obtenidos|reutiliza\w*|sin repetir|sin ejecutar|esos datos)\b', texto):
        return Plan(motivo='referencia_local_sin_contexto_admitido', local=True)
    # Cambios del sistema nunca se convierten en lecturas sustitutivas.
    if re.search(r'\b(instala\w*|actualiza\w*|reinicia\w*|borra\w*|elimina\w*|desactiva\w*|activa\w*|sudo|apt|dnf|comando|terminal|shell|bash|curl)\b', texto):
        return Plan(motivo='cambio_fuera_del_alcance_de_lectura', local=True)
    literal = texto.rstrip('.!?')
    if literal in TEMAS_LOCALES:
        return Plan((literal,), motivo='identificador_explicito', local=True)
    nombres = []
    accion_previa = False
    conceptual = False
    negada_previa = False
    for clausula in re.split(r'\s+y\s+|[,;]|\s+(?=sin\b|pero\b|excepto\b|salvo\b)', texto):
        temas = [n for n, patron in TEMAS_LOCALES.items() if re.search(patron, clausula)]
        if len(temas) > 1:
            return Plan(motivo='varios_objetos_sin_separacion_clara', local=True)
        if re.search(NEGACION, clausula):
            negada_previa = True
            accion_previa = False
            continue
        if re.search(CONCEPTO, clausula):
            conceptual = True
            accion_previa = False
            continue
        accion = bool(re.search(ACCION, clausula))
        if temas and (accion or accion_previa and not negada_previa):
            # "servicios" sin selector no autoriza una inspección más amplia.
            if 'servicios_fallidos' in temas and not re.search(r'fallid|servicios_fallidos', clausula):
                return Plan(motivo='especificar_servicios_fallidos', local=True)
            nombres.extend(n for n in temas if n not in nombres)
            accion_previa = True
            negada_previa = False
        elif temas:
            return Plan(motivo='falta_accion_explicita', local=True)
        elif clausula.strip() and not re.fullmatch(r'(?:pero )?(?:explica|resume|presenta|muestra).*', clausula.strip()):
            return Plan(motivo='clausula_no_reconocida', local=True)
    if seguridad:
        return Plan(motivo='mezcla_de_alcances_no_admitida', local=True)
    if nombres:
        return Plan(tuple(nombres), motivo='lectura_explicita', local=True)
    return Plan(conceptual=conceptual, motivo='concepto_o_exclusion_sin_adquisicion', local=True)


class ContextoFactual:
    """Último resumen por herramienta; sin texto del usuario ni del modelo.

    Solo recibe proyecciones cerradas producidas por Python. No persiste a disco.
    La caducidad no se renueva al leer. Los errores sustituyen el éxito anterior.
    """
    def __init__(self, reloj=time.monotonic):
        self._reloj = reloj
        self._hechos = {}

    def guardar(self, nombre, texto):
        if nombre not in NOMBRES or not isinstance(texto, str) or len(texto) > MAX_TEXTO:
            raise ValueError('Hecho fuera del contrato de sesión')
        self._hechos[nombre] = (self._reloj(), texto)
        while len(self._hechos) > MAX_HECHOS:
            del self._hechos[next(iter(self._hechos))]

    def consultar(self, nombres=()):
        ahora = self._reloj()
        self._hechos = {n: (t, s) for n, (t, s) in self._hechos.items()
                        if 0 <= ahora - t < VIDA_SEGUNDOS}
        return {n: (int(ahora - t), s) for n, (t, s) in self._hechos.items()
                if not nombres or n in nombres}

    def cerrar(self):
        self._hechos.clear()
