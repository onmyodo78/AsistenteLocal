# Auditoría de portabilidad de AsistenteLocal

Informe histórico de la revisión indicada abajo. Sus capacidades pendientes
describen aquella fase; el estado vigente está en README.md y ESTADO_VERSION.md.

Fecha: 8 de noviembre de 2026. Auditoría del **árbol de trabajo local**, incluida
su implementación de diagnóstico y preparación APT. HEAD local: `90f2bd0`;
existen modificaciones y archivos sin seguimiento. Este informe no certifica el
contenido publicado actualmente en GitHub ni una versión instalada del helper.

## 1. Alcance, método y conclusiones

Se inspeccionaron código funcional, contratos, procedimientos y pruebas. Se
reutilizó la regresión simulada existente; no se añadieron pruebas al repositorio.
Se comprobaron importaciones con las conexiones bloqueadas únicamente dentro de
un proceso de comprobación y se reprodujo una ruta de error Fedora con mocks.
No se desconectaron servicios, contactó con LM Studio u Ollama, instaló software,
ejecutó sudo, descargaron paquetes ni modificó configuración del sistema.
La única incorporación al proyecto en esta fase es este informe.

Se consultó documentación oficial de Ollama para evaluar su contrato público,
no su servidor ni modelos locales. Las referencias externas se identifican en
la sección 4; su contenido no sustituye pruebas de una versión concreta.

En el informe:

- **Implementado** significa que existe una ruta de código accesible.
- **Probado** especifica si se comprobó con mocks, con datos locales o con el
  servicio/gestor real. Una prueba sintética no acredita una distribución real.
- **Previsto** significa que no existe integración funcional completa.

Conclusiones principales:

1. El motor de auditoría, planificación y diagnóstico funciona sin modelo ni
   proveedor de inferencia. Las operaciones autorizadas APT también están
   implementadas fuera de la conversación; su ejecución real sigue sin validarse.
2. La conversación está acoplada al endpoint y al identificador de LM Studio,
   pero no usa un SDK propietario ni código de entrenamiento de GPT-OSS.
3. Las garantías de ejecución, validación y presentación proceden de Python.
   La exactitud y obediencia del texto interpretativo siguen dependiendo del modelo.
4. Debian y Fedora comparten coordinación y contratos, **no todas las capacidades**.
   Fedora no dispone de descarga o ejecución de actualizaciones en esta aplicación.
5. Ollama es una integración técnicamente viable, todavía no implementada ni
   probada. Cambiar solo `MODEL` o `API_URL` no basta.
6. Hay límites reales de portabilidad: aislamiento Linux x86_64, especialización
   Fedora 44, manejo incompleto de un error DNF4 y diferencias entre documentación,
   árbol local y archivos incluidos en Git.

## 2. Mapa de dependencias reales

```text
cli.py
 ├─ mantenimiento.consultar
 │   ├─ distribucion_linux.detectar_distribucion
 │   ├─ adaptadores.debian.Debian → dpkg / apt_pkg.Policy / APT simulate
 │   └─ adaptadores.fedora.Fedora → RPM / DNF4 o DNF5
 │       └─ mantenimiento_transporte → mantenimiento_worker → aislamiento Linux
 ├─ motor_auditoria.consultar
 │   ├─ auditoria_debian / apt_debian / apt_indices
 │   └─ auditoria_seguridad / correlacion_seguridad (Fedora)
 ├─ diagnostico_mantenimiento → diagnóstico APT local + archivos_apt
 └─ cliente_ejecucion_apt (solo en operaciones específicas)
     └─ helper instalado → autorización humana → diario → bloqueos → APT

AsistenteLocal.py
 ├─ prompts + catálogo TOOLS + preguntar + consultar_modelo
 │   └─ lmstudio_http → POST fijo a 127.0.0.1:1234
 ├─ adquisición y parsers locales, parcialmente duplicados con motor_auditoria
 ├─ informes_factuales / resultado_verificado / control_verificado
 ├─ motor_consultas.ContextoFactual (seguridad Debian)
 └─ ColeccionSesion + preparación humana de exportación
```

| Componente | Dependencia efectiva | Evidencia |
| --- | --- | --- |
| Detección | `/etc/os-release`, después `/usr/lib/os-release`; no modelo | `distribucion_linux.py:detectar_distribucion()` |
| Contratos y presentación | Biblioteca estándar, datos adquiridos y estados explícitos | `contratos_mantenimiento.py:validar()/finalizar()`, `informes_factuales.py`, `resultado_verificado.py` |
| Auditoría Debian | dpkg-query; python3-apt para candidatas; índices locales; aislamiento | `auditoria_debian.py:consultar_auditoria()`, `apt_debian.py:emitir_local()`, `apt_indices.py:seleccionar_indices()` |
| Auditoría Fedora | uname, rpm, DNF con caché y formatos concretos | `auditoria_seguridad.py:CONSULTAS/normalizar()`, `motor_auditoria.py:consultar_auditoria_seguridad()` |
| Plan de mantenimiento | Gestor nativo, inventario y resolvedor; no HTTP de modelos | `mantenimiento.py:seleccionar()/consultar()`, adaptadores y trabajador |
| Diagnóstico de preparación | APT, archivos .deb, statvfs, /proc, helper y diario observables | `diagnostico_mantenimiento.py:diagnosticar()/evaluar()`, `diagnostico_apt_nativo.py:recoger()` |
| Descarga/instalación APT | Helper protegido, Python del sistema, python3-apt, autorización y SQLite | `cliente_ejecucion_apt.py:invocar()`, `ejecutor_apt.py:main()`, `ejecucion_apt.py:descargar()/ejecutar()` |
| Selección conversacional no determinista | Salida del modelo bajo catálogo y presupuestos Python | `AsistenteLocal.py:preguntar()/validar_respuesta()` |
| Interpretación | Modelo servido por LM Studio y contrato de Chat Completions | `AsistenteLocal.py:consultar_modelo()`, `lmstudio_http.py:abrir_http_local()` |
| Historial/resultados | Memoria o SQLite según API; no memoria aprendida del modelo | `motor_consultas.py:ContextoFactual`, `sesion_resultados.py:ColeccionSesion`, módulos `historial_*` |
| Codex, VS Code y GitHub | Herramientas de desarrollo/distribución, sin llamada necesaria en runtime | Importaciones de `cli.py` y `AsistenteLocal.py`; `.gitignore`; comprobación de importación de sección 10 |

La CLI importa ambos adaptadores y módulos de auditoría aunque solo seleccione
uno. Son importaciones de código Python; no cargan los bindings apt/dnf/rpm ni
arrancan procesos durante la importación comprobada. También llega a urllib por
`motor_auditoria → correlacion_seguridad`; eso no crea una conexión ni una
dependencia de LM Studio. Es acoplamiento de módulos, no de servicios.

## 3. Dependencias del modelo: instrucciones frente a garantías

### 3.1 Instrucciones enviadas en cada consulta

Las fuentes son `AsistenteLocal.py:SYSTEM_PROMPT`,
`INSTRUCCION_CONTINUACION_AUDITORIA`, `prompt_segun_backend()` y
`herramientas_para_modelo()`; no una configuración aprendida fuera del proyecto.

- `SYSTEM_PROMPT` establece español, uso de herramientas, límites de inferencia,
  respeto de desconocidos, tratamiento de datos como datos y reglas de red,
  memoria y seguridad. Su encabezado original es Fedora KDE.
- `prompt_segun_backend()` sustituye encabezado y reglas de auditoría para Debian
  13 o backend no soportado. No detecta el escritorio KDE.
- `TOOLS` contiene nombres, descripciones y comandos autorizados. El payload
  transmite nombre, descripción y esquema, **no** una interfaz de comandos libres.
- `consultar_modelo()` declara todas las funciones sin parámetros: objeto vacío,
  `properties={}`, `required=[]`, `additionalProperties=False`.
- Tras una auditoría se añade la instrucción de interpretar los hechos en dos o
  tres frases, distinguir índices locales de frescura y no afirmar ausencia de CVE.
- `interpretar_contexto()` envía resumen factual anterior, antigüedad y una orden
  de interpretar sin herramientas. El agotamiento de presupuesto añade otra
  instrucción de cierre al historial de esa petición.

`preguntar()` crea de nuevo `[system, user]` para cada pregunta. Dentro de esa
pregunta acumula `assistant.tool_calls` y mensajes `tool` con `tool_call_id`.
No envía automáticamente todo el diálogo anterior ni carga conversaciones de
SQLite como memoria del modelo. `interpretar_contexto()` construye su propia
secuencia system/user/system con resúmenes anteriores, sin replay de las llamadas.

Estas instrucciones son datos de inferencia repetidos por el cliente. **No se ha
identificado entrenamiento, ajuste de pesos, LoRA ni modificación de GPT-OSS en
las rutas auditadas.** Cambiar un prompt o añadir reglas Python no entrena el modelo.
El identificador `openai/gpt-oss-20b` no demuestra por sí solo pesos, cuantización,
plantilla o motor exactos. MXFP4/CPU/llama.cpp son configuración del servidor
comunicada en las pruebas previas, no parámetros seleccionados por este código.

### 3.2 Garantías implementadas en Python

| Propiedad | Garantía real y límite | Evidencia |
| --- | --- | --- |
| Herramientas autorizadas | Catálogo fijo y exclusión de `external` por defecto; rechazo de nombres desconocidos | `herramientas_disponibles()`, `ejecutar_consulta()`, `ALLOW_EXTERNAL=False` |
| Argumentos | Rechazo si no son una cadena JSON que decodifique exactamente a `{}`; no se usa el texto como comando | `validar_respuesta()`, bucle de llamadas de `preguntar()` |
| Respuesta estructurada | Exige choices/message assistant, contenido textual o null; llamadas function con ID, nombre y argumentos; IDs únicos en la misma respuesta | `validar_respuesta()` |
| Presupuestos | 120 s por pregunta, 45 s por HTTP; 4 rondas de herramientas más cierre, 4 llamadas/respuesta y 8 totales | Constantes y bucle de `preguntar()` |
| Repetición | Una adquisición de cada nombre por pregunta; rechazos consumen presupuesto; sin reintento automático tras timeout | Conjunto `usadas`, contadores y excepciones de `preguntar()` |
| Solicitudes explícitas | Gramática Python fuerza las dos herramientas de seguridad reconocidas **solo en Debian**; conserva las dos en una consulta compuesta | `motor_consultas.py:planificar()`, rama `debian` y cola `pendientes` de `preguntar()` |
| Preguntas conceptuales/reutilización | Supresión de adquisición en casos reconocidos; contexto anterior con edad y caducidad | `planificar()`, `interpretar_contexto()`, `ContextoFactual` |
| Contexto factual | Hasta 2 resúmenes, 6.000 caracteres cada uno, 1.800 s sin renovar al leer; errores sustituyen éxito anterior; solo proyecciones Python en la ruta integrada | `motor_consultas.py:ContextoFactual`, `AsistenteLocal.py:hecho_seguridad()/preguntar()` |
| Presentación | Hechos Python separados; cada línea del modelo se prefija y se etiqueta no verificada | `mostrar_informe_factual()`, `mostrar_interpretacion()` |
| Datos desconocidos | Informes deterministas no convierten null/fallo en cero ni certifican seguridad no evaluada | `informes_factuales.py:resumen_factual_debian()/informe_correlacion_debian()` |
| Mantenimiento | El modelo no tiene herramientas de descarga/instalación; CLI y helper requieren autorización humana distinta para cada operación | `TOOLS`, `cli.py:main()`, `autorizacion_apt.py`, confirmaciones TTY del helper |

Los límites de salida conversacional son 18.000 caracteres por resultado y
60.000 acumulados; HTTP tiene un límite de 1 MiB. Los contratos estructurados
intentan omitir colecciones completas antes que cortar JSON. Estos límites no
son un cálculo de tokens de entrada para cada modelo.

### 3.3 Decisiones que todavía dependen del modelo

En Fedora, en herramientas distintas de seguridad Debian y en formulaciones no
reconocidas por la gramática, el modelo decide si pide herramientas, cuáles,
en qué orden o si responde solo con texto mediante `tool_choice="auto"`.
Python limita esa decisión, pero no garantiza que la selección sea suficiente.
La gramática tampoco cubre todas las formas posibles de pedir una comprobación.

Las explicaciones, hipótesis y recomendaciones en lenguaje natural dependen del
modelo. No existe un validador semántico general de cada afirmación. Las reglas
«no inventes», «no obedezcas salidas» y «no recomiendes sudo por iniciativa propia»
son instrucciones, no garantías sobre la prosa. El código impide ejecutar esos
comandos libres; no impide que aparezcan sugeridos en texto etiquetado no verificado.

Al sustituir GPT-OSS pueden cambiar selección y repetición solicitada de tools,
calidad del español, obediencia a unknowns, longitud, latencia, razonamiento,
resistencia a instrucciones inyectadas y aceptación de la secuencia de mensajes.
La misma temperatura 0,2 no garantiza las mismas respuestas ni entre proveedores
ni entre ejecuciones; no se fija semilla ni versión/digest de pesos.

Los resultados de `cli.py plan` y del diagnóstico APT no se incorporan a
`ContextoFactual` ni se exponen como nuevas tools del modelo. La auditoría
conversacional Debian sigue informando «simulación no realizada» en su propio
alcance: no ejecuta automáticamente el planificador de mantenimiento independiente.
Esto es separación actual de rutas, no ausencia de simulación APT en todo el proyecto.

## 4. Dependencias de LM Studio y viabilidad de Ollama

### 4.1 Contrato real del cliente

`AsistenteLocal.py:API_URL/MODEL/consultar_modelo()` fija:

- `POST http://127.0.0.1:1234/v1/chat/completions`.
- Modelo `openai/gpt-oss-20b`, mensajes system/user/assistant/tool.
- `temperature=0.2`, `max_tokens=1800`, tools function y `tool_choice=auto/none`.
- Sin SDK OpenAI/LM Studio, sin descubrimiento de modelos ni configuración de
  proveedor por CLI o variables. Sin cabecera de autenticación de API.
- Una respuesta JSON completa; no se solicita ni procesa streaming/SSE. Se
  depende del comportamiento no streaming por defecto del endpoint.

`lmstudio_http.py:ENDPOINT/abrir_http_local()` vuelve a fijar URL, dirección IPv4,
puerto y método. Rechaza otros destinos antes de conectar, elimina proxies y
rechaza redirecciones/túneles. **Modificar solo API_URL no cambia esa allowlist.**
`ALLOW_EXTERNAL` no habilita otros proveedores ni otros destinos de inferencia.

El transporte descuenta un único reloj para conexión, envío, cabeceras y lectura;
usa socket propio y detalles de HTTPResponse de CPython. Corta por tiempo o tamaño,
rechaza JSON inválido y respuestas estructuralmente incompletas, y no reintenta.
El límite de 45 s depende también de hardware, carga del servidor y generación;
no demuestra un problema exclusivo de GPT-OSS. La llamada es síncrona y ocupa el
bucle de la interfaz durante la espera.

`lmstudio_metrics.py:MedicionHTTP` registra fases, tamaño, estado y tipos de error;
no es una inicialización del servidor. `main()` presenta fallos HTTP/conexión.
Cuando ya se mostró una auditoría o interfaces, se conservan los hechos aunque
falle la interpretación. Esas rutas rechazan además `finish_reason=length` o
`content_filter`; no hay igual comprobación global para toda respuesta conceptual
u otra herramienta. Texto genérico truncado puede mostrarse como no verificado.

No se procesa `reasoning_content`/`thinking` como respuesta alternativa: contenido
vacío sin tools se rechaza. Se usa solo la primera choice; no hay adaptación de
otros formatos ni normalización entre proveedores.

### 4.2 Matriz de proveedor

| Función | LM Studio actual | Ollama compatible OpenAI | Ollama nativo | Sin modelo |
| --- | --- | --- | --- | --- |
| Arrancar/importar CLI independiente | No necesario | No necesario | No necesario | Comprobado |
| Auditoría, candidatas y plan | No necesario | No necesario | No necesario | Implementado; pruebas sintéticas y evidencia local Debian |
| Diagnóstico/preparación APT | No necesario | No necesario | No necesario | Implementado; descarga real no validada |
| Informes verificados por flags | No necesario | No necesario | No necesario | Implementados; importan entrada que también contiene cliente HTTP |
| Conversación libre | Cliente implementado; pruebas HTTP simuladas y antecedentes locales comunicados | Viable; sin adaptador/configuración ni prueba local | Requiere adaptación de protocolo | No hay generación conversacional |
| Function calling | Validador y bucle implementados para este contrato | Requiere conformidad del servidor y modelo escogidos | Requiere normalización de mensajes/argumentos/IDs | Solo selección determinista ya existente en las rutas descritas |
| Autorización de mantenimiento | No participa | No debe participar | No debe participar | TTY humana en helper, independiente |

La documentación oficial de [compatibilidad OpenAI de Ollama](https://docs.ollama.com/api/openai-compatibility)
describe un subconjunto de API, muestra servidor local en el puerto 11434 y
enumera `tools`, `tool_choice`, `max_tokens` y mensajes. Eso hace razonable intentar
la ruta compatible; no prueba soporte efectivo de cada combinación en una versión
instalada. Un nombre de modelo de LM Studio tampoco es automáticamente un nombre
de Ollama. No se ha instalado ni sondeado Ollama.

La [API nativa chat](https://docs.ollama.com/api/chat) utiliza `/api/chat`, respuesta
con `message`, `done` y `done_reason`, y streaming activado por defecto. El ejemplo
oficial de [tool calling](https://docs.ollama.com/capabilities/tool-calling) usa
argumentos como objeto y resultados con `tool_name`, frente a la cadena JSON e
IDs exigidos actualmente por AsistenteLocal. No puede conectarse directamente a
`validar_respuesta()` sin traducción.

**Inferencia técnica, no compatibilidad probada:** una primera integración podría
reutilizar HTTP/JSON estándar y el formato interno actual, con perfil local de
proveedor y allowlist explícita. Un adaptador nativo debe traducir respuesta,
argumentos, correlación de llamadas, finalización y parámetros de generación,
además de solicitar respuesta no streaming. Ninguna ruta necesita por sí misma
instalar un SDK. Ambas deben probar `tool_choice=none`, tools omitidas, llamadas
sintéticas del plan Python y continuación tras varios resultados.

El cliente actual suele enviar tools incluso con `tool_choice=none`; solo algunas
continuaciones usan `omitir_tools`. Un modelo que solo interprete texto puede
necesitar omisión declarada de tools, aunque sea suficiente para explicar hechos.
No se propone sustituir las garantías Python por obediencia al proveedor.

### 4.3 Requisitos de un modelo/proveedor alternativo

1. Producir el contrato normalizado assistant/content/tool_calls o aceptar un
   adaptador explícito; IDs correlacionables y argumentos validados, sin ejecutar
   nada a partir de texto libre.
2. Admitir resultados role=tool y continuación después de herramientas, incluidas
   varias en una tanda y llamadas insertadas por Python.
3. Entender español y diferenciar evidencia, unknown/null, instantánea anterior,
   candidata, simulación, descarga e instalación.
4. Mantener tiempos y tamaños dentro de límites medidos; verificar ventana de
   contexto, tokens consumidos por razonamiento y respuesta final. No asumir que
   60.000 caracteres equivalen al mismo número de tokens en todos los modelos.
5. Responder correctamente sin tools cuando el caso sea conceptual o de mera
   interpretación. Las tools finales no autorizadas se rechazan aunque las genere.
6. Superar fixtures de respuestas válidas/inválidas y evaluación semántica sobre
   informes fijos; cambiar el modelo no debe modificar hechos, límites o autoridad.
7. Registrar para reproducibilidad versión del servidor, identificador y digest
   de pesos, cuantización, plantilla de chat, contexto y opciones de razonamiento.
   Es configuración de inferencia, no entrenamiento realizado por AsistenteLocal.

## 5. Matriz Debian / Fedora

| Capacidad | Debian 13 | Fedora | Evidencia y grado de validación |
| --- | --- | --- | --- |
| Detección | ID debian y VERSION_ID exactamente 13 | ID fedora y versión numérica; no lista cerrada de releases | `distribucion_linux.detectar_distribucion()`; pruebas con contenidos sintéticos |
| Derivados | No habilitados por ID_LIKE | No habilitados por ID_LIKE | Detección falla cerrada; no prometer soporte de derivados |
| Inventario | dpkg-query; python3-apt no necesario para inventario | RPM, kernel-core | `auditoria_debian`, `auditoria_seguridad`; contratos probados; evidencia local reciente Debian |
| Candidatas | apt_pkg.Policy, índices locales y preferencias | repoquery DNF4/DNF5 y versiones RPM | `apt_debian`, adaptadores; Fedora probado con datos simulados en esta auditoría |
| Avisos de seguridad | Sin avisos/CVE implementados | updateinfo JSON y detalle DNF5; rpm.labelCompare | `backend_seguridad.estado_herramienta()`, `correlacion_seguridad.correlacionar()`; no equivalen a auditoría CVE exhaustiva |
| Correlación con KEV | No implementada | Opcional solo si autorizada en conversación; CLI fuerza False | `motor_auditoria.consultar()`, `correlacion_seguridad.consultar_kev()` |
| Simulación | APT `--simulate dist-upgrade`, parser estructurado | DNF4 con binding `dnf` y resolve; DNF5 no verificable | `adaptadores.*.simular()`, `mantenimiento_worker.resolver_dnf()`; no llamar a aborto DNF5 simulación válida |
| Retenciones | Plan enumera resultado APT | No enumeradas completamente | `retenciones_estado`; vacío Fedora no demuestra ausencia |
| Diagnóstico de preparación | Implementado; evidencia local de descarga pendiente sin .deb verificados, con recuentos omitidos por privacidad | Sin diagnóstico equivalente en esta fase histórica | `diagnostico_mantenimiento`, `diagnostico_apt_nativo`; no se repitió adquisición real en esta auditoría |
| Descarga autorizada | Implementada mediante helper y Acquire; probada con mocks | No implementada | `ejecucion_apt.descargar()`, `AptNativo.descargar()` |
| Instalación autorizada | Implementada, solo actualizaciones cacheadas; sin añadidos/eliminaciones/degradaciones | **No implementada** | `autorizacion_apt.comprobar_plan()`, `AptNativo.marcar_y_comprobar()/instalar()`; ninguna ejecución real validada aquí |
| Parser de reinicio de kernel | No trasladado desde Fedora | Subconjunto estable `.fc44`, epoch 0 y arquitectura compatible | `auditoria_seguridad.clave_kernel()/normalizar()`; otras versiones quedan desconocidas |
| Hardware/plataforma del aislamiento | Linux x86_64 con Landlock/seccomp disponibles | Misma condición | `auditoria_aislamiento.restringir()`; no soporte ARM64 acreditado |
| Auditorías programadas/systemd | Previstas | Previstas | No unidades `.service`/`.timer` en el árbol funcional inspeccionado; ningún scheduler implementado |

La detección amplia de Fedora no certifica todas sus versiones. La auditoría usa
`dnf updateinfo ... --json` y un aviso stderr exacto de DNF5; el adaptador de
mantenimiento selecciona DNF4/5 por ejecutables y binding. Son dos detecciones de
capacidad distintas, con formatos y cobertura que no deben suponerse equivalentes.
**Evidencia:** `auditoria_seguridad.DNF/AVISO_LOG_DNF`, `adaptadores.fedora.Fedora.__init__/capacidades()`.

### Defecto de contrato Fedora confirmado

En `adaptadores/fedora.py:Fedora.simular()`, el except de error al interpretar la
transacción DNF4 devuelve un diccionario sin `retenciones_estado` ni
`no_actualizados_total`. `contratos_mantenimiento.validar()` exige ambos.
Se reprodujo con salida JSON inválida simulada: la posterior llamada a
`mantenimiento.consultar()` termina con `ValueError('componentes_invalidos')`,
en vez de conservar un plan estructurado no verificable. La CLI puede reducirlo
a un error genérico. No causa ejecución de paquetes ni acredita falsa simulación,
pero perjudica el contrato compartido y el diagnóstico portable de errores.
**No se corrige en esta fase de auditoría.**

## 6. Independencia del núcleo, rutas y entorno

### 6.1 Qué funciona sin modelo ni Internet

| Entrada/API | Sin LM Studio/GPT-OSS | Sin Internet | Condiciones |
| --- | --- | --- | --- |
| `cli.py capacidades`, `actualizaciones`, `plan`, `auditoria` | Sí | Sí, caché local | Binarios/bindings, permisos y aislamiento; puede devolver parcial/error |
| `diagnostico-mantenimiento`, `plan-descarga-apt` | Sí | Sí | Solo Debian 13 y alcance admitido; datos ausentes no son éxito |
| `comprobar-ejecucion-apt` | Sí | Sí | Helper instalado protegido; no usa sudo en el sondeo |
| `historial-apt` | Sí | Sí | Lectura administrativa con sudo; no ejecutado durante auditoría |
| `actualizar-apt` | Sí | La ruta del ejecutor exige .deb cacheados y no descarga | Instalación del helper, autorización y todas las verificaciones; efectos de scripts/hooks administrativos no son una garantía global de ausencia de red |
| `descargar-apt` | Sí | No para obtener archivos remotos ausentes | Repositorios configurados, helper y autorización propia; no se ejecutó |
| Cinco flags `--*-verificad*` de AsistenteLocal | Sí | Sí en las consultas locales | ip/ss/nmcli/systemctl o /proc según modalidad; importan también código conversacional sin abrir HTTP |
| Conversación conceptual/general | No para generar respuesta | Sí si modelo local ya disponible | Servidor en loopback; arrancar la interfaz no requiere conectarlo |
| Auditoría Debian reconocida desde conversación | Adquisición Python puede completarse antes del intento de interpretación | Sí para esa adquisición | Puede mostrar hechos y aviso si el modelo falla; no equivale a conversación completa sin modelo |
| `diagnostico_vpn` / KEV autorizado | No se necesitan para el núcleo | No | Red externa explícita; desactivada por defecto y no usada en esta fase |

Ninguna entrada exige Codex, VS Code o GitHub para ejecutarse. No se encontró una
llamada a estos servicios en las rutas funcionales auditadas. Detectar
`FLATPAK_ID` o `/.flatpak-info` en `entorno_ejecucion()` es informativo: no inicia
VS Code ni usa `flatpak-spawn` para saltar al anfitrión.

Los flags verificados aún viven en `AsistenteLocal.py`; importan `lmstudio_http`
y los dos backends aunque no se use el modelo. Son dependencias de código
innecesarias para esa interfaz, pero no requieren SDK, servidor o pesos. En
contraste, se comprobó que importar `cli` no carga `AsistenteLocal`,
`lmstudio_http`, `lmstudio_metrics`, `openai`, `ollama`, `apt`, `apt_pkg`, `dnf` o
`rpm`, y no conecta. Separar esos wrappers facilitaría pruebas y empaquetado.

### 6.2 Rutas, permisos y Python

- APT/dpkg usa `/usr/bin`, `/var/lib/dpkg/status`, `/var/lib/apt/lists`,
  `/var/cache/apt/archives`; helper en `/usr/local/lib/asistentelocal`, diario en
  `/var/lib/asistentelocal`. Son decisiones Debian, no configuración DNF portable.
  **Evidencia:** `apt_simulacion.COMANDO_SIMULACION`, `AptNativo.bloqueo()`,
  `cliente_ejecucion_apt.HELPER`, `registro_mantenimiento.DIRECTORIO`.
- El helper exige root, protección de padres/archivos y ausencia de enlaces;
  exige arranque aislado sin site y reconstruye rutas `/usr/lib/pythonX.Y` y
  `/usr/lib/python3/dist-packages`. El cliente fija `/usr/bin/python3 -I -S -B`.
  No se debe trasladar esta configuración de imports a Fedora ni a un venv.
  **Evidencia:** `ejecutor_apt.preparar_imports()/verificar_instalacion()`.
- El diagnóstico no eleva privilegios para leer el diario. Un diario inaccesible
  o con operaciones observadas no acredita ausencia de pendientes; la evaluación
  puede permanecer NO_VERIFICABLE tras una descarga correcta. Tampoco se relaja
  custodia root porque un sandbox represente propietarios con otro UID.
  **Evidencia:** `diagnostico_mantenimiento.observar_diario()/evaluar()`.
- Herramientas generales presuponen `/proc`, iproute2, NetworkManager o firewalld;
  disponer de Debian/Fedora no asegura tener esos servicios o ejecutables.
  El catálogo no los filtra todos por capacidad; se informa del fallo al ejecutar.
  **Evidencia:** `TOOLS`, `entorno_ejecucion()`, `memoria.comando_meminfo()`,
  `conexiones.FUENTES`, `servicios.COMANDO`.
- El aislamiento usa syscalls y números x86_64 de Linux; Landlock ABI >=3 y
  seccomp/no_new_privs. Otra arquitectura o kernel/configuración puede fallar
  cerrado. No hay fallback silencioso a adquisición sin protección.
  **Evidencia:** `auditoria_aislamiento.restringir()`.
- Publicación de archivos e historial usan O_NOFOLLOW, descriptores, dir_fd,
  fcntl y semántica POSIX. SQLite requiere tablas STRICT; el historial persistente
  usa `Connection.serialize()/deserialize()`, que debe ofrecer la compilación
  de Python/SQLite. No basta con que exista un ejecutable llamado python3.
  **Evidencia:** `exportacion_escritor._plataforma()`, `historial_persistente._cargar()`,
  `HistorialPersistente`, `historial_sqlite.ESQUEMA` y `registro_mantenimiento`.
- README declara Python 3.13 o 3.14. En esta auditoría solo se ejecutaron pruebas
  en Python **3.13.5**, SQLite **3.46.1**, x86_64. No se certifica Python 3.14,
  otras compilaciones ni se deduce una versión mínima global por inspección parcial.
  Un intérprete alternativo puede no encontrar los bindings de la distribución;
  el helper y la CLI de lectura no eligen necesariamente el mismo intérprete.

Hay además una diferencia de protección de entrada: `cli.main()` rechaza EUID 0,
pero `AsistenteLocal.main()` no tiene rechazo equivalente. La conversación no
ofrece sudo ni comandos arbitrarios, pero no debe anunciarse que toda entrada
impide ejecutarse como root. No se ha ejecutado así en esta auditoría.

### 6.3 Historial y futuro servicio systemd

Se deben distinguir cuatro mecanismos: mensajes temporales de `preguntar()`,
`ContextoFactual`, colección saneada `ColeccionSesion` y APIs SQLite de historial.
El historial de usuario no está integrado como memoria automática de conversación;
`historial_controlador.py` lo indica, y `exportacion_interfaz.preparar_interactiva()`
prepara/autoriza exportación sin invocar el escritor ni SQLite. El diario de
mantenimiento sí se usa en la ruta privilegiada y es otra base, con otra autoridad.
No prometer persistencia conversacional, publicación o aprendizaje automático a
partir de la mera existencia de esos módulos.

Las consultas `systemctl` implementadas son observación de servicios, no un
servicio AsistenteLocal. No hay ejecución periódica, notificador ni políticas de
ventanas de mantenimiento implementadas. Los TTL de sesión son caducidad comprobada
al acceder, no un scheduler. La planificación de transacciones APT/DNF **ya existe**;
no debe confundirse con planificación temporal de tareas, todavía prevista.

Un futuro servicio deberá ejecutar auditorías sin privilegios, manejar falta de
TTY y políticas de sesión/entorno, y mantener la autorización administrativa fuera
del modelo. El helper actual exige `/dev/tty`, SUDO_UID y confirmación humana: no es
una interfaz no interactiva para un timer. Cualquier cambio futuro a esa autoridad
requiere diseño y revisión propios, sin conceder privilegios permanentes al proceso
conversacional. SELinux, namespaces y sandboxing de systemd son validaciones futuras,
no fallos demostrados en Fedora durante esta fase.

## 7. Riesgos y recomendaciones por prioridad

| Prioridad | Hallazgo y evidencia | Recomendación para una fase posterior |
| --- | --- | --- |
| P0 publicación | `git ls-files` no incluye módulos locales esenciales como cli.py, mantenimiento.py, motor_consultas.py y archivos APT nuevos; hay importaciones hacia ellos en el árbol modificado | Preparar y revisar un conjunto completo de fuente/pruebas/docs; comprobar desde checkout limpio antes de afirmar reproducibilidad en GitHub. No se ha añadido ni confirmado nada en esta auditoría. |
| P0 afirmaciones | README aún dice que la versión no instala/actualiza, mientras cli y helper local ya contienen esas rutas | Documentar con precisión «implementado, helper no instalado, solo probado con mocks»; distinguir rama pública y estado local. |
| P1 contrato Fedora | Ruta DNF4 de error incompleta reproducida, sección 5 | Corregir posteriormente el contrato de fallo y comprobar preservación del diagnóstico en CLI; sin ampliar capacidades DNF. |
| P1 soporte Fedora | Detección de cualquier versión numérica frente a kernel `.fc44`, formatos DNF específicos y DNF5 sin simulación estructurada | Publicar matriz por release/gestor/capacidad, conservar unknowns y validar en VM Fedora antes de prometer soporte general. |
| P1 proveedor fijo | URL duplicada y validada en `AsistenteLocal.py` y `lmstudio_http.py`; MODEL constante | Definir perfil explícito local y adaptador de protocolo, conservando allowlist, plazos y rechazo de redirecciones; no abrir destinos libres. |
| P1 comportamiento desigual | Gramática/contexto solo Debian; otras selecciones dependen del LLM | Explicitar alcance; separar política determinista de selección del proveedor y evaluar su reutilización sin atribuirla al modelo. |
| P1 autoridad de entrada | CLI rechaza root, conversación no lo rechaza explícitamente | Unificar posteriormente política de entrada no privilegiada; no ejecutar conversación como root ni convertirla en servicio root. |
| P1 entorno seguro | Linux x86_64/Landlock y ABI de bindings Python no siempre presentes | Matriz real por Python, kernel, arquitectura y distribución; fallo cerrado y diagnóstico explícito, sin rebajar aislamiento. |
| P1 evidencia de mantenimiento | Descarga e instalación solo simuladas; helper sin despliegue validado; diario privado limita preparación verificable | Prueba manual controlada en VM después de revisión, con autorizaciones separadas y recuperación administrativa; no declarar ejecución ya probada. |
| P2 acoplamiento | `AsistenteLocal` mezcla UI, política, prompts, transporte y adquisición; `motor_auditoria` duplica coordinación | Reutilizar coordinadores existentes y extraer únicamente wrappers/catálogo/proveedor, preservando contratos y límites. |
| P2 semántica | Prosa no validada; finish_reason incompleto solo tratado en ciertas rutas | Mantener separación factual; evaluar de forma uniforme finalización incompleta y pruebas semánticas al cambiar modelo. |
| P2 documentación/configuración | Prompts dispersos y configuración de inferencia no versionada por perfil | Distribuir fuentes y referencias a políticas, snapshot de configuración no secreta y criterios de conformidad; no prometer texto idéntico. |

Los problemas confirmados aquí se distinguen de hipótesis pendientes: posible
rechazo de mensajes por otra versión de Ollama, latencias de otro modelo, políticas
SELinux y ejecución concurrente real no se han probado y no se presentan como
fallos demostrados de esos productos.

## 8. Propuesta mínima reutilizando lo existente — no implementada

No hace falta reemplazar el motor ni introducir un framework de agentes.

| Responsabilidad | Base reutilizable | Separación mínima propuesta |
| --- | --- | --- |
| Dominio y hechos | contratos_mantenimiento, resultado_verificado, informes_factuales, parsers | Mantener independientes del proveedor; no guardar interpretación como hecho |
| Auditoría y plan de transacción | motor_auditoria, mantenimiento y adaptadores | Una coordinación por operación; reducir duplicación con AsistenteLocal sin alterar adquisición/validación |
| Política de conversación | motor_consultas, TOOLS, validadores y presupuestos | Catálogo y política comunes, metadatos proyectados para el modelo; autoridad siempre Python |
| Proveedor opcional | consultar_modelo y lmstudio_http | Interfaz pequeña: mensajes normalizados → respuesta normalizada, con perfil explícito de capacidades, endpoint y modelo |
| Interfaz | cli y wrappers de modalidades verificadas | CLI de motor separada; conversación opcional reutiliza API de auditoría y solo interpreta resultados disponibles |
| Autorización/privilegios | autorizacion_apt, cliente, helper, ejecucion_apt y registro | Conservar despliegue protegido y operaciones cerradas; no incluir credenciales ni decisiones de consentimiento en prompts |
| Estado y exportación | ContextoFactual, ColeccionSesion, historial y exportación | Conservar los distintos contratos, ámbitos y consentimientos; no fusionarlos en un historial libre del LLM |
| Servicio futuro | API de auditoría/diagnóstico | Adaptador no privilegiado posterior; sin implementar scheduler, timers ni políticas automáticas en esta fase |

Los contratos Debian/Fedora comparten identidad y grupos de acciones, pero el
proveedor no debe igualar capacidades inexistentes. Un adaptador alternativo de
modelos tampoco debe contener comandos del gestor de paquetes ni resolver planes.
La evolución mínima consiste en desacoplar interfaces ya presentes, no duplicar
APT ni crear un ejecutor DNF no autorizado.

## 9. Qué distribuir y qué afirmar en GitHub

### 9.1 Conjunto necesario para reproducir comportamiento

Distribuir el árbol completo revisado que cierre las importaciones, no solo
AsistenteLocal.py: CLI, motor, adaptadores, parsers, contratos, informes, transporte,
aislamiento, helper y autorización cuando se anuncien esas capacidades. Incluir
pruebas sintéticas/fixtures saneadas, runner seleccionado y procedimientos por
capacidad/distribución. La revisión actual solo propone preparar esa publicación.

Los prompts y definiciones de herramientas están en fuente y son portables; las
políticas y presupuestos Python también. Deben documentarse sus puntos de entrada
y referencias de versión. La configuración del proveedor necesita una receta
reproducible no secreta: endpoint permitido, ID real, servidor, pesos/digest,
cuantización, plantilla, contexto y generación. Esto no incluye distribuir pesos
sin revisar su licencia ni credenciales del sistema.

`documentos/`, bases SQLite, `.vscode`, `.codex`, `.agents`, datos privados y
respaldos están excluidos por `.gitignore`. Por tanto, enlazar solo un diagnóstico
local dentro de documentos/ no lo convierte en evidencia disponible en GitHub.
Publicar en su caso una muestra saneada revisada o describir el procedimiento,
sin copiar automáticamente inventarios, IP, documentos, secretos o diarios root.
Las instrucciones de desarrollo de Codex/VS Code no son instrucciones de runtime
para GPT-OSS; el contrato efectivo está en el código que compone el payload.

### 9.2 Afirmaciones sostenibles y límites

| Se puede afirmar con el alcance indicado | No se puede afirmar actualmente |
| --- | --- |
| Motor independiente del modelo con contratos e informes deterministas | Respuestas idénticas o mismas decisiones conversacionales con cualquier LLM |
| CLI sin dependencia de LM Studio, Codex o VS Code | Que toda la aplicación funcione sin modelo, incluidas respuestas conversacionales |
| Auditorías/planes locales sin refrescar metadatos; red externa desactivada por defecto | Que todas las funciones sean offline: descarga, KEV o diagnóstico VPN pueden usar red al autorizarse |
| Debian 13 con inventario, candidatas, simulación y diagnóstico; límites explícitos | Correlación CVE Debian o certificación de ausencia de vulnerabilidades |
| Fedora con auditoría/consulta y planificación condicionada a gestor/bindings | Ejecución/descarga DNF, equivalencia funcional total Debian/Fedora o soporte acreditado de todas las versiones Fedora |
| Cliente LM Studio implementado y probado en protocolo con mocks; antecedentes locales comunicados | Integración Ollama disponible o intercambiabilidad solo cambiando el nombre del modelo |
| Descarga/ejecución APT implementadas con autorizaciones separadas y pruebas simuladas | Helper instalado, actualizaciones/descargas reales validadas o mantenimiento desatendido |
| Núcleo de Python estándar más herramientas/bindings nativos por capacidad | Ausencia total de dependencias del sistema, soporte de ARM/Windows/macOS o de toda compilación Python |
| Prompts y reglas de inferencia distribuidos como fuente | GPT-OSS entrenado por el proyecto o conocimiento aprendido portable por copiar la carpeta |
| Regresión pasada en el árbol auditado y entorno indicado | Que HEAD, una instalación limpia o el remoto contienen y superan ya esa misma versión |

La README requiere revisión en una fase autorizada antes de anunciar públicamente
las nuevas rutas de mantenimiento. Este informe no cambia esa documentación ni
publica código o realiza operaciones Git de escritura.

## 10. Verificaciones realizadas y evidencia pendiente

Entorno observado de esta auditoría: `/usr/bin/python3` 3.13.5, SQLite 3.46.1,
Linux x86_64. Se ejecutaron:

```sh
/usr/bin/python3 -B -W error::ResourceWarning tests/ejecutar_regresion_motor.py
PYTHONPATH=tests /usr/bin/python3 -B -W error::ResourceWarning -m unittest test_contratos_fedora -q
```

Resultados: **716 pruebas** de la selección existente y **6 pruebas** sintéticas
Fedora, satisfactorias. No se añadieron tests ni se cambió la selección. El runner
fuerza desactivadas las integraciones reales y no es un descubrimiento completo
de todo tests/. Estas cifras no acreditan otras versiones de Python ni un gestor
Fedora ejecutado en su distribución.

En un proceso de comprobación se rechazaron `socket.connect`, `connect_ex` y
`socket.create_connection`; importar cli no cargó clientes de modelos ni bindings
nativos, y después importar AsistenteLocal tampoco abrió conexión. Esto demuestra
que la importación no exige servidor, **no** que se hayan ejecutado sin él todas
las operaciones posibles. No se modificó el entorno de otros procesos.

Se inyectó JSON inválido en `Fedora.simular()` mediante unittest.mock y se pasó
el resultado al coordinador con un adaptador simulado: quedaron ausentes los dos
campos identificados y se obtuvo componentes_invalidos. Solo fue una comprobación
puntual de código existente, sin añadir una prueba permanente ni invocar DNF.

Se contrastaron `git status`, `git ls-files`, imports y entradas funcionales.
Se comprobó la ausencia de unidades de servicio/timer en el ámbito funcional
inspeccionado. Los antecedentes de adquisición Debian de la fase anterior se
conservan como evidencia local, no como una actualización ni prueba real nueva.
No se han validado en esta fase:

- LM Studio/GPT-OSS en vivo, Ollama o ningún modelo alternativo.
- Fedora real/DNF4/DNF5, sus permisos, cachés y APIs de cada release.
- Descarga o instalación APT real, helper desplegado, fallos de alimentación o
  exclusión efectiva entre gestores concurrentes.
- Python 3.14, otras arquitecturas, configuración SELinux o ejecución systemd.
- Contenido remoto de GitHub ni reproducibilidad de un checkout limpio completo.

Las siguientes pruebas futuras útiles serían conformidad de proveedor sobre
mensajes y errores, evaluación semántica sobre hechos fijos, importación y CLI
desde checkout limpio, y matriz de VMs por gestor/Python. Se proponen para revisión:
**no se implementa ninguna modificación de arquitectura ni planificador temporal**.
