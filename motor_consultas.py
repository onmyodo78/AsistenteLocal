"""Plan local de seguridad Debian y contexto efímero de hechos, sin adquisiciones."""
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


def planificar(pregunta):
    """Gramática conservadora: conceptos y negaciones nunca fuerzan adquisición.

    Las solicitudes no reconocidas siguen la selección habitual del modelo.
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
