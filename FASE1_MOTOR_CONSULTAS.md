> Documento histórico de implementación. Para las capacidades y límites actuales,
> consultar [README](README.md) y [estado de la versión](ESTADO_VERSION.md).

# Fase 1: consultas explícitas y contexto factual Debian

El plan local se aplica al backend Debian 13. Para las solicitudes reconocidas,
Python decide las llamadas antes de consultar al modelo y utiliza el despachador
existente, con los mismos permisos y presupuestos. Las dos herramientas de esta
fase son `auditoria_seguridad` y `correlacion_seguridad`. La segunda conserva su
respuesta `no_implementado`: no se ha implementado correlación CVE.

Ejemplos:

- `Audita Debian 13`: adquisición nueva de auditoría.
- `Ejecuta auditoria_seguridad y correlacion_seguridad`: ambas consultas se
  procesan antes de cerrar herramientas y solicitar una interpretación.
- `Interpreta la auditoria_seguridad anterior`: reutilización sin adquisición.
- `Interpreta lo anterior sin repetir`: reutilización de los hechos vigentes.
- `Ejecuta una nueva auditoria_seguridad`: sustituye la instantánea anterior.
- `Qué es auditoria_seguridad`: respuesta conceptual, con herramientas cerradas.

La selección usa una gramática conservadora, no comprensión general del lenguaje.
Reconoce los nombres de herramientas, acciones y temas de seguridad del módulo
`motor_consultas.py`. Las negaciones reconocidas evitan forzar adquisiciones.
Fuera de esa gramática se mantiene la selección habitual del modelo; las órdenes
ambiguas y las negaciones por cláusulas no tienen cobertura completa. Los nombres
literales con una orden positiva son la forma más precisa de solicitar el plan.
No se extiende esta fase a herramientas de red, memoria ni otros backends.

El contexto factual es independiente del historial de exportación. En el bucle
interactivo vive durante la sesión; los consumidores de `preguntar()` pueden
pasar un `ContextoFactual` explícito. Las llamadas sin contexto no comparten una
memoria global implícita. No se guardan preguntas ni interpretaciones del modelo.

Se conserva el último resumen por herramienta, con estados y recuentos cerrados
calculados por Python, sin inventarios, candidatas, nombres de paquetes, rutas ni
salidas originales. Una referencia al pasado no renueva la caducidad. Los datos
se identifican como instantáneas anteriores y se muestra su antigüedad. Si faltan
o han caducado, Python indica que la comprobación no se ha realizado y no adquiere
nada para suplirla. Un intento nuevo invalida el éxito anterior antes de empezar;
un error, timeout o interrupción no recupera silenciosamente ese éxito.

Los límites nuevos restringen exclusivamente esta memoria adicional: dos resúmenes,
un máximo de 6.000 caracteres por resumen y 30 minutos desde cada adquisición.
No amplían los límites de herramientas, salida, HTTP ni tiempo. Se conserva el
plazo HTTP de 45 segundos, el global de 120 segundos y la ausencia de reintentos.
La memoria se borra al cerrar la sesión. No hay persistencia a disco.

Los hechos de Python se muestran antes de la interpretación y se conservan si
esta falla. La interpretación continúa siendo texto no verificado: esta fase no
implementa un verificador semántico de afirmaciones, streaming ni interfaz
asíncrona. La consulta HTTP sigue bloqueando mientras espera.

No se implementa simulación APT, no se cambian índices, no se añaden dependencias,
comandos libres ni consultas externas. Las pruebas son simuladas y no acreditan
compatibilidad o latencia del servidor LM Studio instalado.

El respaldo previo de `AsistenteLocal.py` se conservó localmente, fuera del
conjunto publicable. Los otros tres archivos de
esta fase son nuevos; no tenían contenido previo que respaldar.


## Informes factuales y texto del modelo

`informes_factuales.py` contiene funciones puras para los informes Debian de
inventario/apt, correlación y fallo de adquisición. Los campos no admitidos no
se reproducen como texto libre; los recuentos inválidos o incompletos son
`desconocido`, nunca cero implícito. El informe declara también la simulación
APT no realizada, la correlación CVE no implementada y la seguridad no evaluada.
Los resúmenes de sesión reutilizan esas mismas funciones.

En la conversación, cada informe se delimita entre `INFORME FACTUAL DE PYTHON`
y `FIN DEL INFORME FACTUAL`. Los informes existentes de Fedora e interfaces
usan también esa presentación. Las demás herramientas muestran su salida o
estado con el prefijo `Herramienta |`, sin atribuirle una interpretación
semántica. Esto no convierte una salida textual arbitraria en un diagnóstico
validado.

El texto de LM Studio se presenta aparte, marcado como no verificado, con
`Modelo |` en cada línea y un final propio. Si no se consultaron herramientas,
se indica que la comprobación no se ha realizado. Los caracteres de control se
escapan antes de mostrar el texto. El modelo no puede introducir una cabecera
sin el prefijo que identifica su procedencia, ni alterar retroactivamente el
informe de Python o los hechos guardados en la sesión. Sigue pudiendo formular
afirmaciones erróneas dentro de su bloque: no hay validación semántica automática.

La regresión de esta ampliación ejecutó 182 pruebas simuladas, sin procesos de
adquisición ni conexiones a LM Studio. Incluye determinismo, datos desconocidos,
contradicciones y cabeceras falsas del modelo, conservación ante timeout y
reutilización sin incorporar interpretaciones. No cambia los plazos, permisos,
comandos autorizados ni la política de reintentos. El respaldo anterior a esta
ampliación se conservó localmente, fuera del conjunto publicable.
