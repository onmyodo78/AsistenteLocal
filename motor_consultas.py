"""Clasificación local conservadora y contexto efímero; sin adquisiciones."""
from dataclasses import dataclass
import re
import time
import unicodedata

NOMBRES = ('auditoria_seguridad', 'correlacion_seguridad')
NOMBRES_CONTEXTO = NOMBRES + ('memoria',)
MAX_HECHOS = 3
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
    explicar: bool = False
    pendientes: tuple = ()

    @property
    def tipo(self):
        if self.nombres or self.reutilizar:
            return 'mixta' if self.explicar else 'operativa'
        return 'conceptual' if self.conceptual else 'ambigua'


def _planificar_seguridad(pregunta):
    """Gramática conservadora: conceptos y negaciones nunca fuerzan adquisición.

    Se conserva para el protocolo de auditoría y su contexto de sesión.
    Una comprobación explícita es nueva; solo las referencias al pasado reutilizan.
    """
    texto = normalizar(pregunta)
    if re.match(r'\s*(?:no|sin|nunca|tampoco)\s+(?:me\s+)?(?:expli(?:ca|que)\w*|interpret\w*|resum\w*)\b', texto):
        # Excluir una explicación no solicita otra ni reutiliza hechos anteriores.
        return Plan()
    conceptual = es_conceptual(texto.strip(' ¿¡'))
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
ACCION = r'\b(analiza|analizar|diagnostica|diagnosticar|realiza|haz|comprueba|comprobar|verifica|verificar|revisa|revisar|consulta|consultar|muestra|muestrame|mostrar|dame|dime|lista|listar|ejecuta|ejecutar)\b'
CONCEPTO = r'\b(es normal|por que|que implica|que ocurre|que pasa|que ventajas|que riesgos|que relacion|que es|que son|que significa|como funciona|como funcionan|para que sirve|diferencia entre|que diferencias? (?:hay )?entre|cual es la diferencia entre|en que se diferencian|explica(?:me|rme|r|ndo)?|para (?:saber|entender|conocer)|que (?:herramientas|comandos|permisos)|(?:es posible|se puede|puedo) (?:comprobar|verificar|consultar|revisar)|como (?:puedo |se puede |debo |podria )?(?:comprobar|verificar|consultar|revisar|ver|saber))\b'
NEGACION = r'\b(no|sin|nunca|tampoco|excepto|salvo)\b'


def es_conceptual(clausula):
    """Intención explicativa inicial, no una relativa dentro de una orden.

    Solo admite introductores explícitos y cortesía acotada; lo desconocido no
    se envía por defecto al modelo. Recibe texto normalizado.
    """
    return bool(re.match(
        r'(?:por favor\s+)?(?:(?:me )?(?:puedes|podrias)\s+)?(?:' + CONCEPTO +
        r'|\b(?:como interpretar|resume|resumeme|dime si)\b)', clausula))


TEMAS_ADQUISICION = dict(TEMAS_LOCALES,
    auditoria_seguridad=r'\b(auditoria_seguridad|auditoria|audita\w*|actualizaciones|paquetes)\b',
    correlacion_seguridad=r'\b(correlacion_seguridad|correlacion|cve|vulnerabilidades)\b')


def planificar(pregunta):
    """Selecciona adquisiciones por cláusula; no recorta la pregunta a responder.

    La explicación usa siempre la pregunta original. Una cláusula bloqueada no
    invalida las lecturas independientes; no se hereda una acción tras negaciones,
    conceptos o fragmentos cuyo alcance no está resuelto.
    """
    texto = normalizar(pregunta).strip()
    # Reutilización local cerrada: no es una adquisición ni un permiso nuevo.
    if re.fullmatch(
            r'(?:interpreta|explica(?:me)?|reutiliza)\s+'
            r'(?:(?:los\s+)?(?:resultados|datos)\s+(?:anteriores|obtenidos)\s+de\s+(?:la\s+)?(?:memoria|ram|swap)'
            r'|(?:la\s+)?(?:memoria|ram|swap)\s+anterior)'
            r'(?:\s+sin\s+(?:repetir|ejecutar)(?:\s+la)?\s+consulta)?[.!?]?', texto):
        return Plan(('memoria',), reutilizar=True, local=True, motivo='instantanea_memoria_anterior')
    locales = any(re.search(patron, texto) for patron in TEMAS_LOCALES.values())
    seguridad = bool(re.search(r'\b(auditoria|audita\w*|seguridad|actualizaciones|paquetes|correlacion|cve|vulnerabilidades|auditoria_seguridad|correlacion_seguridad)\b', texto))
    separable = bool(re.search(r'\b(y|pero)\b|[,;]|\S\s+sin (?:consult|ejecut|comprob)', texto))
    mixta_seguridad = seguridad and separable and bool(re.search(CONCEPTO, texto) or re.search(NEGACION, texto))
    if not locales and not mixta_seguridad and (seguridad or re.search(r'\b(anterior\w*|reutiliza\w*|sin repetir|esos resultados|esos datos)\b', texto)):
        return _planificar_seguridad(pregunta)
    # Mantener la selección de auditoría básica/seguridad previa, sin confundir
    # "sistema" con una solicitud independiente de uname.
    if not mixta_seguridad and re.search(r'\bauditoria\b', texto) and not any(re.search(TEMAS_LOCALES[n], texto) for n in ('memoria', 'disco', 'interfaces_red', 'vpn', 'servicios_fallidos')):
        return _planificar_seguridad(pregunta)
    nombres, pendientes = [], []
    explicar = False
    modo = None
    literal = texto.rstrip('.!?')
    if literal in TEMAS_LOCALES:
        return Plan((literal,), motivo='identificador_explicito', local=True)
    # Son restricciones sobre el mecanismo, no negaciones de la lectura.
    texto = re.sub(r'\b(?:sin (?:usar |utilizar |solicitar )?(?:sudo|privilegios(?: administrativos)?|permisos administrativos|red|internet|conexiones externas)|no (?:uses|utilices|solicites) sudo(?: para)?)\b', '', texto)
    clausulas = re.split(r'\s+(?:y|pero)\s+|[,;:.!?\n]+|\s+(?=explicando\b|para (?:saber|entender|conocer)|sin\s+(?:consult|comprob|ejecut|verific|revis|mirar|listar|mostrar)|excepto\b|salvo\b)', texto)
    for clausula in clausulas:
        clausula = clausula.strip(' ¿¡')
        if not clausula:
            continue
        if clausula in ('hola', 'buenos dias', 'buenas tardes', 'por favor'):
            # Cortesía separada no es una operación pendiente ni cambia el modo.
            continue
        temas = [n for n, patron in TEMAS_ADQUISICION.items() if re.search(patron, clausula)]
        if 'auditoria_seguridad' in temas and 'sistema' in temas:
            temas.remove('sistema')
        negada = bool(re.match(r'(?:(?:por favor)\s+)?(?:no|nunca|tampoco|sin|excepto|salvo)\b', clausula))
        if negada:
            if re.search(r'\b(explic\w*|interpret\w*|resum\w*)\b', clausula):
                # Negar explicación no niega las lecturas de una enumeración.
                continue
            modo = 'excluida'
            continue
        if es_conceptual(clausula):
            explicar = True
            modo = 'conceptual'
            continue
        if re.search(r'\b(?:no|sin|nunca|tampoco)\s+(?:\w+\s+){0,3}(?:consult\w*|comprob\w*|verific\w*|revis\w*|ejecut\w*)', clausula):
            modo = 'excluida'
            continue
        acciones = re.findall(ACCION, clausula) + re.findall(r'\b(audita\w*|correlaciona\w*)\b', clausula)
        # Los infinitivos coordinados siguen bajo la explicación anterior:
        # «diferencia entre consultar memoria y revisar disco». Una orden
        # explícita («y comprueba disco») conserva la solicitud mixta existente.
        if modo == 'conceptual' and acciones and all(a.endswith('r') for a in acciones):
            continue
        accion = bool(acciones) or bool(re.search(r'\b(cuanta (?:memoria|ram) (?:tengo|queda|hay)|cuanto espacio (?:queda|tengo|hay)|cual es (?:mi |la )?ip publica)\b', clausula))
        if not accion and modo in ('excluida', 'conceptual') and temas:
            continue
        motivo = None
        interrogativa = bool(re.match(r'(?:comprueba|verifica|consulta|revisa)\s+si\b', clausula))
        if re.search(r'\b(quizas|tal vez|podria|podrias|antes de|despues de|cuando|a menos|o)\b', clausula) or (re.search(r'\bsi\b', clausula) and not interrogativa):
            motivo = 'alcance_condicional_o_alternativo'
        elif re.search(r'\b(anterior\w*|obtenidos|reutiliza\w*|sin repetir|sin ejecutar|esos datos)\b', clausula):
            motivo = 'referencia_local_sin_contexto_admitido'
        elif re.search(r'\b(instala\w*|actualiza(?:r|me)?|reinicia\w*|borra\w*|elimina\w*|desactiva\w*|activa\w*|sudo|apt|dnf|comando|terminal|shell|bash|curl)\b', clausula):
            motivo = 'cambio_fuera_del_alcance_de_lectura'
        elif len(temas) > 1:
            motivo = 'varios_objetos_sin_separacion_clara'
        elif 'servicios_fallidos' in temas and not re.search(r'fallid|servicios_fallidos', clausula):
            motivo = 'especificar_servicios_fallidos'
        elif temas and (accion or modo == 'operativa'):
            nombres.extend(n for n in temas if n not in nombres)
            modo = 'operativa'
            continue
        else:
            motivo = 'solicitud_no_reconocida'
        pendientes.append(motivo)
        modo = None
    if not locales and re.fullmatch(r'(hola|buenos dias|buenas tardes)[!.]?', texto):
        explicar = True
        pendientes = []
    return Plan(tuple(nombres), conceptual=explicar and not nombres,
                motivo='lectura_explicita' if nombres else 'consulta_conceptual' if explicar else 'solicitud_no_reconocida',
                local=True, explicar=explicar, pendientes=tuple(dict.fromkeys(pendientes)))


class ContextoFactual:
    """Último resumen por herramienta; sin texto del usuario ni del modelo.

    Solo recibe proyecciones cerradas producidas por Python. No persiste a disco.
    La caducidad no se renueva al leer. Los errores sustituyen el éxito anterior.
    """
    def __init__(self, reloj=time.monotonic):
        self._reloj = reloj
        self._hechos = {}

    def guardar(self, nombre, texto):
        if nombre not in NOMBRES_CONTEXTO or not isinstance(texto, str) or len(texto) > MAX_TEXTO:
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

    def invalidar(self, nombre):
        """Retira una entrada sin convertir un estado de control en evidencia."""
        if nombre not in NOMBRES_CONTEXTO:
            raise ValueError('Hecho fuera del contrato de sesión')
        self._hechos.pop(nombre, None)

    def cerrar(self):
        self._hechos.clear()
