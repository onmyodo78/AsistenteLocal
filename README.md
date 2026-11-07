# AsistenteLocal

Versión experimental de un asistente de consultas locales de solo lectura para
Fedora KDE, con **soporte parcial de Debian 13**. En Debian se dispone del
inventario dpkg; la adquisición de candidatas APT puede fallar o ser parcial.
No se implementa correlación CVE Debian ni se certifica ausencia de vulnerabilidades.

El modo conversacional utiliza LM Studio local; los informes verificados de
interfaces, memoria, conexiones, puertos y servicios funcionan sin él. Requiere
Python 3.13 o 3.14. El núcleo utiliza la biblioteca estándar. `python3-apt`
(`apt_pkg`) es opcional para consultar candidatas, no para el inventario dpkg;
debe ser accesible desde el mismo intérprete. No se instala automáticamente.

## Ejecución recomendada

La raíz publicable es la carpeta que contiene este README, `.gitignore`,
`AsistenteLocal.py`, los módulos y `tests/`. Si se trabaja desde un directorio
exterior que contiene otra carpeta `AsistenteLocal/`, entrar primero en ella.
Los ejemplos parten de esa raíz, sin depender de rutas o nombres personales.

Desde una terminal nativa del anfitrión Fedora o Debian 13:

```sh
python3 -B AsistenteLocal.py
```

El modo conversacional espera el servidor de LM Studio en
`http://127.0.0.1:1234/v1/chat/completions` y el identificador de modelo
`openai/gpt-oss-20b`, actualmente definidos en el código. No se configura ni se
inicia LM Studio automáticamente. Los cinco flags verificados documentados
abajo no requieren servidor ni modelo.

`documentos/` se resuelve junto al módulo real, no respecto al directorio de
trabajo. Se mantiene la apertura segura con `O_NOFOLLOW`. Es una carpeta local
para documentos del usuario y queda excluida del repositorio.

El programa informa del intérprete, de indicios de Flatpak y de dependencias
localizables en PATH. No instala paquetes, cambia permisos ni salta automáticamente
al anfitrión. Un binario disponible no garantiza acceso a su servicio.

Dentro de VS Code Flatpak, `/usr/bin` pertenece al runtime de Flatpak y puede no
contener `systemctl`, `ss`, `firewall-cmd`, `nmcli` o `ip`, aunque estén instalados
en Fedora. No añadir `/run/host/usr/bin` al PATH: no resuelve las diferencias de
bibliotecas, intérpretes o acceso a servicios. No se implementa un puente permanente.

Dependencias por herramienta: se muestran al inicio las ausentes o sin permiso de
ejecución; `entorno_ejecucion()` permite inspeccionar también las rutas encontradas.
Los errores al ejecutar distinguen archivo/intérprete ausente, permiso denegado y
otros errores del sistema. Los rechazos de permisos del propio servicio siguen
figurando en stderr y en su código de salida, sin clasificarlos por texto ambiguo.

Las consultas externas están desactivadas por defecto. `diagnostico_vpn` requiere
activación explícita porque incluye llamadas a un servicio externo; está excluida
de las pruebas reales descritas aquí.

## Interfaces verificadas, sin LM Studio

Desde la raíz del proyecto:

```sh
python3 -B AsistenteLocal.py --interfaces-verificadas
```

Esta opción ejecuta una única consulta autorizada a `interfaces_red`, imprime el
informe final generado por Python y termina. No abre la conversación ni hace
llamadas HTTP, consultas al modelo, consultas externas o reintentos.
Solo utiliza los comandos de lectura de esa herramienta:

- `ip -j -s link show`
- `nmcli -t --escape yes -f DEVICE,TYPE,STATE,CONNECTION device status`

Reutiliza la adquisición, normalización, estados desconocidos y resumen existentes.
Añade contadores acumulados y claves de lectura predefinidas, sin interpretación
libre del modelo. Radio desconocida y conectividad no comprobada siguen explícitas;
DOWN no determina la radio, ni se clasifica una interfaz como física o virtual.
Un estado de NetworkManager no se convierte en prueba de acceso a un destino.

| Código de salida | Significado |
|---|---|
| `0` | Adquisición y presentación completas para los campos solicitados |
| `3` | Resultado parcial, vista breve limitada u omisión por presupuesto |
| `1` | Fallo: sin fuentes utilizables, tiempo agotado o error de adquisición/formato |
| `2` | Uso incorrecto de argumentos, gestionado por argparse |
| `130` | Interrupción mediante teclado |

Éxito no significa conectividad, radio encendida, VPN operativa ni ausencia de
problemas. Los fallos parciales muestran el estado de cada fuente y conservan
los datos válidos; desconocido no se convierte en cero. La vista visible se limita
a seis registros; si hay más, se informa y el código es `3`, aunque la adquisición
haya sido completa. Un informe que no cabe se sustituye por un aviso explícito,
sin presentarlo como éxito ni como ausencia de interfaces.

No se puede combinar esta opción con `--permitir-consultas-externas`.
Sin `--interfaces-verificadas`, el uso interactivo habitual permanece igual:
escribir una pregunta, incluso sobre interfaces, sigue usando el modo
conversacional y su explicación del modelo puede contener errores. Esta garantía
no se extiende a consultas mixtas ni a otras herramientas.

## Memoria verificada, sin LM Studio

```sh
python3 -B AsistenteLocal.py --memoria-verificada
```

Obtiene una única instantánea de `/proc/meminfo`, imprime un informe determinista
de Python y termina. No consulta LM Studio, no ejecuta `free` ni otras herramientas
conversacionales y no necesita dependencias adicionales. El lector tiene una ruta
fija y se ejecuta con el propio Python en un subproceso sin shell: esto permite
reutilizar el ejecutor existente, su captura de 64 KiB y timeout de hasta 15 segundos,
acotado por los 120 segundos globales. No recibe rutas del usuario ni realiza escrituras.

Los campos se normalizan a bytes: `kB` de Linux equivale a 1024 B. Se muestran los
bytes exactos y GiB redondeados a dos decimales (empates hacia arriba), usando
aritmética entera sin alterar los bytes. Las magnitudes son:

- Total de RAM visible para el kernel: `MemTotal`.
- Disponible estimada: `MemAvailable`.
- Utilizada estimada: `MemTotal - MemAvailable`, no suma del consumo de procesos.
- Libre: `MemFree`, opcional y distinta de disponible; no se suman ambas.
- Swap total, libre y ocupada: `SwapTotal`, `SwapFree` y su diferencia.

**Actividad de intercambio: `no_medida`.** La ocupación de swap no demuestra
actividad actual ni ausencia de ella. No se muestrean contadores, no se calculan
tasas y no se diagnostican presión de memoria, fugas, rendimiento ni suficiencia
futura de RAM. Disponible es una estimación y total visible no necesariamente
coincide con la RAM físicamente instalada.

Un dato ausente, duplicado, con valor/unidad inválidos o incoherente queda como
`desconocido`/`null`; no se sustituye por cero. Si falta MemAvailable, tampoco se
sustituye por MemFree. Una RAM parcial puede conservar swap válida y viceversa.
Una lectura fallida o truncada se descarta entera, incluso si contiene un prefijo
aparentemente válido. Los campos adicionales de `/proc/meminfo` no se interpretan.

Códigos: `0` para instantánea completa dentro del alcance; `3` para resultado parcial
u omisión por tamaño; `1` para fallo; `2` para argumentos incompatibles/incorrectos;
`130` para interrupción. La actividad deliberadamente no medida y la ausencia del
campo opcional MemFree no convierten por sí solas el resultado en parcial. Un
cero medido en SwapTotal/SwapFree se conserva como cero, sin conclusiones sobre
necesidad o actividad de swap.

`--memoria-verificada`, `--interfaces-verificadas`, `--conexiones-verificadas`,
`--puertos-verificados`, `--servicios-verificados` y `--permitir-consultas-externas`
son mutuamente excluyentes. Sin las opciones verificadas, el modo conversacional
permanece igual: la herramienta `memoria` sigue usando `free -h` y una explicación
del modelo, con sus limitaciones semánticas conocidas.

## Conexiones verificadas, sin LM Studio

```sh
python3 -B AsistenteLocal.py --conexiones-verificadas
```

Ejecuta exclusivamente cuatro consultas locales fijas y secuenciales:

```text
ss -H -O -n -a -t -4
ss -H -O -n -a -t -6
ss -H -O -n -a -u -4
ss -H -O -n -a -u -6
```

No usa shell, DNS, identificación de procesos, conexiones activas ni HTTP. Python
valida y presenta los registros. No altera las herramientas conversacionales
`conexiones` y `puertos`. Esta modalidad aún requiere su primera validación real
con la versión de `ss` del anfitrión.

El parser exige cinco columnas: estado, Recv-Q, Send-Q, extremo local y remoto.
Acepta IPv4/IPv6 numéricas, IPv6 entre corchetes o sin ellos, puertos numéricos
0–65535, comodines y zonas IPv6 ASCII de hasta 64 caracteres (letras, números,
guion, punto o guion bajo). Valida estados TCP/UDP conocidos y colas enteras no
negativas de hasta 64 bits. Un formato nuevo o no admitido descarta la fuente;
no se intenta adivinarlo. Los estados UDP no se presentan como sesiones TCP.
Las colas conservan su valor observado: su significado depende del estado.

Se cuentan **registros de sockets**, manteniendo filas con extremos repetidos.
No son clientes, sesiones lógicas únicas ni prueba de conectividad. Cada fuente
utilizable tiene su recuento y desglose de estados; el total de las cuatro solo
se ofrece si todas son utilizables. Una fuente vacía válida tiene cero registros;
una fuente inválida, truncada, fallida o con stderr tiene recuento desconocido.
Se descarta todo su bloque, sin publicar prefijos como resultados completos.
Las consultas no forman una instantánea atómica y cubren solo el espacio de
nombres de red visible al proceso, con sus permisos actuales.

Límites independientes:

- Adquisición: hasta 15 segundos por consulta dentro del plazo global de 120;
  captura existente de 64 KiB y máximo de 500 registros por fuente. Exceder un
  límite de volumen invalida esa fuente completa.
- Presentación: hasta 20 registros y 18 000 caracteres. Ocultar filas produce
  presentación parcial, conservando los recuentos de fuentes utilizables.
  Un informe que no cabe se sustituye por un aviso, nunca se corta un JSON.

El informe oculta IP y zonas locales y todos los extremos remotos, incluidos sus
puertos. Solo muestra categoría local (comodín, loopback u oculta), puerto local,
estado y colas. No adquiere nombres de procesos. Errores e incidencias utilizan
mensajes predefinidos, sin copiar stderr ni líneas originales. **El resultado
interno contiene direcciones y puertos completos y es sensible**: no se exporta
ni registra automáticamente; no debe confundirse con una estructura anonimizada.

Utiliza directamente `ResultadoVerificado`, sin adaptador heredado, manteniendo
independientes adquisición y presentación. Comparte los códigos `0` (completo),
`3` (parcial u omisión), `1` (fallo), `2` (uso incorrecto) y `130` (interrupción).
No evalúa accesibilidad externa, seguridad, reputación, VPN ni entrega de datos.

## Puertos verificados, sin LM Studio

```sh
python3 -B AsistenteLocal.py --puertos-verificados
```

Vista determinista derivada de una única adquisición y normalización de conexiones:
selecciona exclusivamente TCP `LISTEN` y todos los registros UDP válidos (`UNCONN`
y `ESTAB`). No ejecuta una segunda ronda de `ss`. Los recuentos se calculan en
Python sobre esa misma instantánea, antes de limitar la presentación.

La unidad es el registro de socket: varios registros pueden compartir puerto,
protocolo, familia e incluso extremo local. No se deduplican ni se cuentan como
servicios o clientes únicos. TCP en otros estados queda excluido de la vista;
se muestran los recuentos excluidos por fuente. UDP `UNCONN` indica ausencia de
par conectado; `ESTAB` indica un par conectado, sin probar entrega de datos.

Se mantienen las cuatro consultas fijas numéricas de conexiones, sin procesos,
DNS, consultas externas, privilegios elevados ni pruebas activas. La modalidad
no usa LM Studio ni modifica las herramientas conversacionales.

Una fuente válida sin registros seleccionados da cero conocido. Una fuente
fallida, truncada, con avisos, formato inválido o más de 500 registros se descarta
íntegra: su recuento seleccionado y el total global quedan desconocidos. Esto
incluye el caso de demasiados registros TCP que posteriormente se excluirían.
La adquisición parcial permite presentar las otras fuentes mientras siga vigente
el plazo global. Las consultas son secuenciales y no atómicas; ejecuciones
separadas pueden producir recuentos distintos.

Límites heredados: 64 KiB combinados de stdout/stderr por consulta, hasta 15 segundos
por comando, 120 segundos globales y 500 registros por fuente. La presentación
muestra hasta 20 registros seleccionados y 18 000 caracteres. Una vista limitada
no altera los recuentos ni el estado de adquisición. Si no cabe el informe se
publica un aviso de omisión; si vence el plazo global no se publica el informe tardío.
Códigos: 0 completo, 1 error/plazo global agotado, 2 uso inválido, 3 parcial u
omisión por tamaño y 130 interrupción. El flag es mutuamente excluyente con las
otras modalidades verificadas y la autorización de consultas externas.

Privacidad: se muestran protocolo, familia, estado, puerto local y categoría de
dirección (comodín, loopback o dirección local oculta). Se ocultan las IP concretas
y los calificadores de interfaz, también IPv4. El resultado especializado interno
conserva el extremo local estructurado sensible, pero no copia extremos remotos,
colas ni procesos. No se exporta ni registra automáticamente; `a_json()` no es
una anonimización. El puerto local puede revelar indicios de aplicaciones, pero
no se atribuyen servicios a partir de su número.

La observación solo cubre el espacio de red visible al proceso. Comodín no prueba
accesibilidad externa e IPv6 no implica cobertura IPv4. No se determina apertura
del cortafuegos, publicación en Internet ni accesibilidad desde otra máquina.
Primera validación real autorizada completada con Python nativo 3.14.8: 0,108 s,
código 3, stderr vacío, adquisición completa y presentación parcial de 20/32
registros. TCP4 LISTEN=10, TCP6 LISTEN=3, UDP4 UNCONN=11/ESTAB=1 y UDP6 UNCONN=7.
Se excluyeron 42 registros TCP4 en otros estados. No se detectaron IP, calificadores,
extremos remotos ni campos de procesos en el informe. Los casos de fuente vacía,
fallida y duplicados quedaron cubiertos por pruebas automatizadas; no se ejercitaron
todos en esa ejecución real. No se repitió el diagnóstico.

## Servicios verificados, sin LM Studio

```sh
python3 -B AsistenteLocal.py --servicios-verificados
```

Consulta única y fija de solo lectura:

```text
systemctl --system --no-pager --no-ask-password --plain --no-legend --full list-units --type=service --state=failed
```

Solo enumera unidades `.service` fallidas del gestor systemd del sistema. No
consulta el gestor de usuario, UnitFileState, propiedades adicionales, procesos
ni journald. No ejecuta acciones sobre servicios, consultas externas ni llamadas
a LM Studio. La herramienta conversacional `servicios_fallidos` no cambia.

Python valida la tabla completa, nombres e instancias, escapes literales,
LoadState, ActiveState=failed, sintaxis de SubState, duplicados y límites. Ordena
por nombre y calcula recuentos por estado; no deduce causas. Los subestados nuevos
con sintaxis admitida se conservan sin interpretación. Las descripciones se
separan del resto de columnas y se descartan. No se decodifican nombres escapados
como rutas. Una salida incompatible invalida toda la fuente, sin utilizar prefijos.

Los nombres reales son visibles por defecto por decisión de diseño para este
uso local; pueden revelar información personal en nombres de instancias. No hay
opción de ocultación en esta versión. No se conservan ni muestran descripciones,
rutas independientes del nombre de unidad, mensajes originales de error,
procesos ni logs. El resultado interno conserva los nombres y estados, y no se
exporta ni se envía automáticamente al modelo.

LoadState describe carga; ActiveState y SubState describen ejecución.
UnitFileState no se solicita: disabled no significa failed, inactive no significa
failed y active no prueba funcionamiento correcto. Tampoco se infiere que una
unidad deba estar habilitada. Una unidad masked o not-found puede conservar un
estado de ejecución independiente. No aparecer en la lista no demuestra salud,
ausencia ni descarga. Una lista válida vacía significa cero servicios fallidos
observados, sin garantizar salud general. No se inventarían estados de habilitación
static, generated o disabled a partir de esta consulta.

Límites: 15 segundos por comando, 120 globales, 64 KiB combinados de stdout/stderr,
500 unidades, 20 filas visibles y 18 000 caracteres. Una fuente fallida, con
stderr, truncada, inválida o con exceso de unidades da recuento desconocido, no
cero. No hay reintentos ni consultas alternativas. Errores de D-Bus o gestor no
disponible se agrupan como error de consulta si no existe evidencia estructurada
para distinguir su causa. Los errores originales no se publican.

Una adquisición completa puede tener presentación parcial por superar 20 filas;
los recuentos conservan todas las unidades. Si no cabe el informe se sustituye por
un aviso de omisión. El plazo global impide publicar datos tardíos. La consulta
no se presenta como una instantánea transaccional; los estados pueden cambiar.

Códigos según completitud: 0 completo (también cuando hay servicios fallidos),
1 error, 2 uso inválido, 3 presentación parcial/omitida y 130 interrupción. El flag
es mutuamente excluyente con las otras modalidades y consultas externas.
Primera validación real superada en Fedora KDE 44 con Python nativo 3.14.8:
0,1625 s, código 0, stderr vacío y adquisición/presentación completas. Se observó
`vmware.service` con LoadState=loaded, ActiveState=failed y SubState=failed.
Según la validación posterior comunicada por el usuario, después de instalar los
módulos de VMware una nueva ejecución autorizada observó cero servicios fallidos.
No se atribuye una causa mediante este diagnóstico ni se deduce salud general.
Estas validaciones son antecedentes; no se ejecutan al revisar documentación.

## Política común de las modalidades verificadas

Las cinco modalidades comparten `control_verificado.py`: un mismo plazo global de
120 segundos se comprueba antes y después de adquirir los datos y justo antes de
publicar el informe. No se renueva durante la consulta. Si vence, se devuelve `1`
y no se publica un informe tardío, aunque la adquisición haya llegado a producir
algunos datos. Se mantienen los límites particulares de cada adquisición.

La traducción de estados a códigos está centralizada: completo `0`, parcial u
omisión por límite `3`, error `1`, interrupción `130`. Argparse conserva el código
estándar `2` para uso incorrecto. Los formatos, fuentes y plantillas de cada
herramienta siguen siendo distintos. Esta política no interviene en la conversación.

## Contrato interno de resultados verificados

Las modalidades verificadas usan `resultado_verificado.ResultadoVerificado` como
envoltorio interno con ocho campos: `version`, `herramienta`, `estado_adquisicion`,
`estado_presentacion`, `fuentes`, `datos`, `incidencias` y `alcance`. Los datos de
interfaces, RAM/swap y sockets mantienen sus estructuras y significados específicos.
No cambia el formato visible ni se añade una salida JSON pública.

La adquisición conserva `completo`, `parcial` o `error`. Si un resultado antiguo
ya había omitido los datos por tamaño, se registra `desconocido` sin inventar que
la adquisición fue completa. La presentación comienza como `pendiente` y termina
con el estado que devuelve la plantilla existente. Por ejemplo, una adquisición
completa puede tener presentación parcial por la vista breve. Solo el estado
final de presentación se traduce con la política de códigos ya existente.

La instantánea guarda una única representación JSON inmutable. `a_dict()` devuelve
una copia independiente; `a_json()` reutiliza el texto almacenado. Cambiar la fase
de presentación crea otra instantánea; repetir el mismo estado sin nuevas incidencias
reutiliza la existente. Los adaptadores conservan campos, orden, incidencias y
extensiones de los formatos anteriores sin duplicar sus valores.

**Compatibilidad de `ResultadoInterfaces`:** continúa siendo una subclase de `str`,
con el mismo constructor, JSON y método `ajustar()`. Su propiedad **`.datos` devuelve
ahora una copia independiente**, obtenida de ese JSON. Modificar la copia no cambia
el resultado; asignar directamente `.datos` no está permitido. Los consumidores
que quieran alterar una copia deben construir explícitamente otro resultado.
El modo conversacional sigue utilizando el JSON anterior, no el nuevo envoltorio.

El envoltorio es interno y no impone otro límite de salida que omita datos que
antes cabían. Se conservan los límites de adquisición, serialización de compatibilidad
y presentación. `control_verificado.py` sigue siendo el único responsable de los
plazos y códigos, y acepta transitoriamente la pareja antigua `(texto, estado)`.

## Pruebas

La validación de estabilización registrada superó **621 pruebas unitarias y
simuladas, con 0 fallos, 0 errores y 0 omisiones durante la ejecución**. Se
excluyeron previamente **172 pruebas**:

| Exclusión | Número |
|---|---:|
| Prototipos y diagnósticos experimentales | 106 |
| Integración real | 4 |
| Tres casos P0 que crean procesos Python | 3 |
| Inventario Fedora con procesos sintéticos reales | 6 |
| Aislamiento real | 1 |
| Hojas de cálculo con procesos reales | 52 |

La selección se ejecutó con una barrera preventiva que interrumpía cualquier
intento de crear procesos, acceder a red, cargar aislamiento real o importar APT
real. No registró operaciones prohibidas. Persistencia y exportación usaron
memoria o directorios temporales de prueba; no se contactó con LM Studio.
Estos resultados describen el árbol local validado: incluyen pruebas simuladas
de componentes independientes que se excluyen de la primera publicación. No
representan el recuento de un descubrimiento automático del contenido publicado.
No se han repetido pruebas para esta actualización documental.

**`ASISTENTE_PRUEBAS_REALES=0` solo desactiva la clase de integración optativa.**
No garantiza que el descubrimiento general evite procesos externos: algunas
pruebas P0 y del inventario Fedora ejecutan Python, y otra aplica aislamiento
real. No usar `unittest discover -s tests` como equivalente de la selección
simulada anterior. El seleccionador y la barrera de aquella validación se
utilizaron en memoria; no se incluye todavía un ejecutor que reproduzca las 621.

Una selección limitada de regresiones simuladas, que no reproduce toda esa
batería, puede ejecutarse desde la raíz publicable:

```sh
PYTHONPATH=tests ASISTENTE_PRUEBAS_REALES=0 python3 -B -W error::ResourceWarning -m unittest test_entorno test_infraestructura_integracion test_finalizacion_general test_estabilizacion_debian -v
```

Las pruebas de producción que crean procesos y las integraciones optativas se
conservan como código, pero requieren revisión y autorización separadas antes de
su ejecución. Las integraciones pueden consultar herramientas del anfitrión,
APT y LM Studio; no forman parte de la validación simulada. Publicar sus archivos
no autoriza a ejecutarlas. Los prototipos APT y sus pruebas específicas quedan
fuera de esta primera versión.

La validación Debian distingue el contrato parcial de la cobertura APT completa.
Un inventario dpkg válido se comprueba aunque falte `python3-apt`. Un fallo APT
conserva los datos dpkg y no satisface la prueba estricta de cobertura completa.
La ausencia de dependencias puede justificar una omisión explícita; un error de
adquisición con dependencias presentes no se convierte en una omisión ni en éxito.
Fedora conserva sus contratos y descripciones específicos.

## Metadatos HTTP y recuperación

Cada llamada a LM Studio emite una línea `LMSTUDIO_METRICAS` por stderr con tiempos
de preparación, conexión/espera de cabeceras, lectura, cierre, validación y total;
tamaños observados, estado HTTP, finish_reason y tokens cuando están disponibles.
No crea archivos ni registra mensajes, contenido de herramientas, credenciales,
razonamiento textual o texto de errores. Con urllib no se separan los tiempos
internos del servidor ni DNS/TCP de la espera de cabeceras.

Los límites se mantienen: hasta 45 segundos para conexión/cabeceras y hasta 45
para lectura, acotados por los 120 segundos globales de la petición. No se aumentan
para obtener métricas ni se activan reintentos.

Si LM Studio falla después de mostrar los hechos de interfaces, el resumen factual
permanece visible y se informa de que la interpretación no está disponible. No se
repiten las herramientas. La explicación libre sigue requiriendo contraste con
los hechos, incluso cuando llega sin errores de comunicación.

## Auditoría local de seguridad (fase 1 corregida)

La herramienta conversacional `auditoria_seguridad` se añade a las doce anteriores,
que conservan comandos y comportamiento. Se puede pedir «Usa auditoria_seguridad
y resume los avisos pendientes y el estado del kernel». No añade un flag CLI.
Antes de solicitar interpretación imprime un resumen factual calculado por Python.
Si LM Studio falla o agota su timeout, conserva ese resumen y distingue el fallo
de interpretación del estado real de adquisición. No reintenta ni repite consultas.
La interpretación posterior se identifica como no verificada.

### Fuentes y DNF5 de solo lectura

Cinco fuentes fijas: `uname -r`, inventario `rpm -qa`, consulta independiente
`rpm -q kernel-core` y dos consultas DNF5 de avisos de seguridad, con
`--available` y `--installed`. DNF utiliza:

```text
dnf --cacheonly --no-plugins --setopt=logdir=/proc/self/fd updateinfo list --security --json
```

`logfilelevel=0` era incompatible con DNF 5.4.6.0 y se ha sustituido por `logdir`.
El directorio virtual elegido no permite crear un archivo de log con nombre;
DNF5 continúa descartando logs. Solo se admite el diagnóstico exacto conocido de
ese descarte, con locale C; otro stderr deja la fuente como no utilizable.
No se ignoran avisos de repositorios ni errores de consulta.

Las consultas DNF y el inventario RPM se lanzan con el Python actual y un helper
fijo, sin shell ni argumentos del usuario. **Antes de ejecutar DNF/RPM**, aplica
no_new_privs, Landlock ABI >=3 y seccomp: bloquea escrituras/creaciones/borrados,
truncamiento, cambios de permisos/propietario/tiempos/xattrs, creación de sockets,
ioctl y otras operaciones administrativas. Las restricciones son del subproceso,
se heredan al ejecutar el binario y no cambian la configuración de Fedora.
`--cacheonly` impide actualizar la caché; el bloqueo de sockets y escrituras
refuerza esa política. `--no-plugins` desactiva plugins de libdnf5; las definiciones
de extensiones CLI que DNF carga para resolver aliases quedan sujetas al mismo
aislamiento. No se fuerza su desaparición, que provocaba avisos de aliases rotos.

El helper admite solo tres modos fijos y tiene límites de 1 GiB de espacio de
memoria virtual, 10 segundos CPU (límite duro 11), core y tamaño de archivo cero.
Por ahora soporta Linux **x86_64**. Si faltan Landlock/seccomp, hay una arquitectura
no soportada o falla alguna restricción, devuelve `aislamiento_no_disponible`
(código interno 78), sin ejecutar el binario ni recurrir a una alternativa insegura.
Binario ausente tras el aislamiento: código interno 69. DNF sigue limitado por el
ejecutor compartido a 15 segundos y 64 KiB combinados stdout/stderr.

Ni `--permitir-consultas-externas` habilita red para auditoría. No instala,
actualiza, elimina, reinicia ni modifica configuración, no usa sudo y no solicita
contraseñas, PIN ni credenciales. Solo observa la caché accesible: cobertura y
antigüedad siguen desconocidas. Una caché ausente/incompatible da error, no cero.

### Inventario incremental y límites

El inventario usa un lector específico; el ejecutor general mantiene sus 64 KiB.
Procesa stdout en bloques de hasta 4 KiB, valida filas completas y conserva solo
los registros válidos. Límites: 15 segundos, 4 MiB combinados leídos (más un byte
para detectar exceso), 25.000 registros, 1.024 bytes por fila y 8 KiB de stderr.
No acumula stdout completo ni usa archivos intermedios. Bytes, filas y tamaño
máximo de campo acotan la memoria del padre; el helper limita además al hijo.

Si alcanza un límite, hay líneas inválidas, errores, stderr o timeout, conserva
las filas válidas ya recogidas, marca inventario parcial y deja el total global
en `null`. `paquetes_rpm_recogidos` expresa el número observado, no el total del
equipo. Solo `inventario_completo=true` permite publicar el total confirmado.
La consulta independiente de kernels no depende de completar este inventario.
Se conservan nombre, epoch, versión, release y arquitectura; las pseudoentradas
RPM `gpg-pubkey` con arquitectura `(none)` se representan con arquitectura `null`.
No se leen claves ni se interpretan esas entradas como software vulnerable.

### Resultado local, modelo y métricas

`ejecutar_consulta('auditoria_seguridad')` devuelve `ResultadoAuditoria`, una
subclase de texto: su JSON **versión 2** es el resumen para LM Studio, no el
inventario. `.datos` devuelve una copia del resultado local, incluido el inventario
válido recogido; sigue siendo exclusivamente de memoria, sin exportación ni
persistencia automática. Cambiar esa copia no altera el resultado original.
El formato local conserva versión 1; la versión 2 identifica la vista compacta.
Los consumidores del antiguo JSON conversacional completo deben adaptarse.

El modelo recibe estado, fuentes, kernel, recuentos y hasta 10 IDs de avisos
pendientes y 5 instalados, con número de paquetes por aviso. No recibe el inventario
ni los nombres/NEVRA de los paquetes de esos avisos. El resumen tiene un tope
adicional de 5.000 caracteres, respetando también los 18.000 por resultado y
60.000 compartidos. Si no cabe, omite colecciones con marcas explícitas, sin
cortar JSON. La vista limitada no altera los recuentos locales. Presentación
completa significa que cabe la vista, no que la adquisición sea completa.

`AUDITORIA_METRICAS` emite por stderr fuente, duración, bytes de ambos canales,
estado, código y número de registros/grupos recogidos. No incluye inventarios,
versiones, IDs de avisos, errores originales, rutas de usuario ni credenciales.
No crea archivos de log. Las métricas HTTP existentes no cambian: timeout de
45 segundos para cabeceras y hasta 45 para lectura, acotados por 120 globales;
max_tokens=1800, sin streaming ni reintentos. Rondas y llamadas permanecen iguales.

### Interpretación y limitaciones

Se agrupan los paquetes por identificador de aviso y se eliminan duplicados del
grupo. El recuento es **de avisos, no de vulnerabilidades ni CVE**. Un aviso puede
figurar como pendiente e instalado por paquetes con estados diferentes.
`--installed` incluye versiones iguales o anteriores a las instaladas: no prueba
historial de transacciones ni que todos los paquetes del aviso estén instalados.
La salida DNF truncada o inválida se descarta íntegra; no se interpreta un prefijo
JSON. El listado histórico de instalados puede superar los 64 KiB y quedar
desconocido, conservando las otras fuentes.

El reinicio pendiente solo indica kernel-core estable Fedora 44, epoch cero,
numéricamente posterior al activo y de la misma arquitectura. Kernels RC,
personalizados u otros formatos quedan desconocidos. No verifica cargador,
arranque efectivo, módulos, reinicios de servicios ni necesidad global de reinicio.
Las consultas son secuenciales, no transaccionales. Cero avisos observados no
garantiza seguridad; no se infiere vulnerabilidad por antigüedad de versión.
CVE, backports y bases externas siguen fuera de esta fase.

### Validación

Las pruebas simuladas comprueban contratos Fedora y Debian, resúmenes saneados,
estados parciales, fallos posteriores del modelo y finalización de procesos.
Las pruebas históricas con procesos sintéticos reales y aislamiento no están
incluidas en las 621 de la selección descrita en [Pruebas](#pruebas).

El ejecutor general y los inventarios reservan dentro de su plazo hasta un
segundo para finalizar y recoger al hijo, sin ampliar el presupuesto total.
No usan esperas ilimitadas ni contextos Popen con espera implícita. Esto reduce
ligeramente el tiempo disponible para capturar datos. Si la recogida o el cierre
fallan se comunica un error; agotar la espera tras `kill()` no demuestra que el
proceso haya desaparecido ni garantiza su recogida posterior o la de descendientes.
No se declara una limpieza confirmada cuando no puede verificarse.

Las comprobaciones reales históricas Fedora no sustituyen la validación del
contenido que finalmente se publique ni certifican cobertura de vulnerabilidades.

## Correlación de seguridad Fedora, CVE y CISA KEV

La herramienta `correlacion_seguridad` se invoca con argumentos vacíos desde el
registro conversacional: «Usa correlacion_seguridad y explica el informe».
El módulo independiente `correlacion_seguridad.py` reutiliza
`consultar_auditoria_seguridad` y el ejecutor limitado existente. No cambia los
comandos ni los resultados de las herramientas anteriores.

El alcance son los avisos de seguridad **disponibles** en la caché DNF5 y sus
paquetes instalados. Una consulta adicional fija `dnf5 advisory info --security
--available --json`, con `--cacheonly`, plugins deshabilitados y el aislamiento
existente de red y escrituras, obtiene CVE y NEVRA correctivas. Cruza nombre y
arquitectura con el inventario RPM y compara epoch, versión y release mediante
`rpm.labelCompare`, sin ordenar versiones como texto. Si el binding Python RPM
no está disponible, la valoración queda `no_determinado`; no se instala nada.

`correccion_pendiente_confirmada` requiere versión instalada inferior **y** la
misma NEVRA correctiva en la lista local de avisos pendientes. Una versión igual
o superior se presenta como `version_correctiva_alcanzada`, sin afirmar que el
kernel o los servicios estén usando esa versión. El resto queda sin determinar.
No se deduce vulnerabilidad a partir de KEV.

Solo con `--permitir-consultas-externas` se descarga el catálogo oficial completo
CISA KEV por HTTPS. No se envían paquetes ni CVE locales; no se siguen
redirecciones, no se persiste el catálogo y se limitan tiempo y tamaño. Sin
permiso, o si falla la consulta, `en_kev` queda en `null`, nunca en `false`.
El informe JSON incluye evidencia local, versiones, CVE, coincidencias KEV,
versión/fecha del catálogo cuando está disponible, referencias, limitaciones y
número de resultados omitidos por el presupuesto de salida.

Referencias: [formato y opciones DNF5 advisory](https://dnf5.readthedocs.io/en/stable/commands/advisory.8.html),
[catálogo oficial CISA KEV](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)
y el inventario RPM local.

Comprobación básica realizada: correlación sintética de aviso/CVE/versión,
confirmación de que KEV por sí solo no cambia el estado local y bloqueo de la
consulta sin autorización. Consulta real local: 3107 registros RPM; ningún aviso
pendiente en la caché. La fuente anterior de avisos instalados excede su límite
de salida y se comunica como truncada; no permite concluir que el sistema carezca
de vulnerabilidades. No se amplió la batería de pruebas, ni se consultó KEV en
esta comprobación, ni se modificaron paquetes, configuración o programadores.

## Debian 13: inventario y candidatos APT locales

**Estado de preparación experimental, 7 de noviembre de 2026:** inventario dpkg
validado anteriormente en ejecución real; adquisición de candidatas APT sin
validación real satisfactoria bajo las protecciones actuales.
`apt_pkg.Cache(None)` ha fallado con `SystemError` y código diagnóstico 72.
**Cobertura de actualizaciones no verificada.** Un fallo o un total desconocido
no significa que no existan actualizaciones o vulnerabilidades.

Las tres fases de estabilización añadieron presentación factual independiente
del modelo, mensajes según distribución, contratos de integración parcial y
finalización acotada. La validación simulada registrada es de **621 superadas y
172 excluidas**, con el alcance detallado en [Pruebas](#pruebas). No demuestra
que APT real funcione ni autoriza repetir adquisiciones. Los prototipos y sus
resultados de investigación no forman parte de la implementación publicable.
Landlock, seccomp, `no_new_privs` y los límites de recursos se mantienen.

La auditoría selecciona Debian 13 mediante os-release. Fedora conserva su
implementación y contratos. Se mantienen las 14 herramientas; la correlación
Debian sigue sin implementar y CVE/avisos permanecen no disponibles.

`auditoria_debian.consultar_inventario(timeout)` conserva el contrato dpkg v1.
`consultar_auditoria(timeout)` produce un contrato Debian v2 con inventario,
estado_inventario y actualizaciones independientes. Un fallo APT no elimina
el inventario válido; un inventario parcial impide confirmar totales globales.
Las lecturas son secuenciales y se detectan discrepancias entre ambas fuentes.

`apt_debian.consultar_actualizaciones(timeout)` lanza exclusivamente el modo fijo
`apt-local` del helper. Primero se aplica el mismo Landlock/seccomp y los límites
de recursos existentes, y después se importa apt_pkg. No se invocan explícitamente
Acquire, DepCache, PackageManager, update, upgrade ni simulaciones. El constructor
nativo Cache puede ejecutar internamente BuildCaches, BuildPolicy y BuildDepCache.
Se configura construcción en memoria con cachés persistentes desactivadas; su
apertura real falla actualmente. El recorrido previsto de Policy aplica configuración APT
y preferencias; se conserva la candidata, prioridad y procedencias locales,
distinguiendo arquitecturas y retenciones. No se cambia la selección de paquetes.

El inventario requiere `dpkg-query`; `python3-apt` es opcional y solo afecta
a la adquisición APT. Si falta apt_pkg o APT falla bajo las restricciones, se
conserva el inventario válido y se informa del fallo APT sin fallback fuera del
aislamiento. Este modo continúa limitado a Linux x86_64 con Landlock ABI >=3.
Cada adquisición APT tiene 15 segundos, 4 MiB combinados, 25.000 registros,
16 KiB por línea y 8 KiB de stderr, además de los límites del helper (1 GiB,
CPU 10/11 s). Los registros válidos anteriores a un fallo se conservan como
parciales; total_posibles queda desconocido. Un marcador final valida la
terminación del flujo y sus recuentos.

Una candidata superior no garantiza instalación: no se resuelven dependencias
ni despliegues escalonados. Los retenidos se muestran pero se excluyen del
recuento de posibles actualizaciones. La procedencia candidata no demuestra
el origen de instalación del paquete. Ninguna actualización implica un CVE.

Se detectan índices configurados ausentes. mtime superior a siete días (o futuro)
es solo un aviso de antigüedad potencial: no acredita fecha de publicación,
sincronización completa ni validez de Release. No se revalida firma o caducidad
y frescura sigue no_verificada incluso con archivos recientes. Los índices
parciales impiden confirmar un total global. No se efectúan conexiones de red.

El inventario y las filas de candidatos permanecen locales, en .datos. El modelo
solo recibe estados, recuentos y limitaciones en un resumen de hasta 5.000
caracteres; no recibe nombres de paquetes, versiones ni sitios de repositorios.
Las adquisiciones APT reales autorizadas han fallado bajo el aislamiento. La
validación satisfactoria queda pendiente; la investigación está suspendida y no
se autoriza ninguna nueva ejecución por este documento. Las pruebas automatizadas
indicadas se ejecutaron con las integraciones reales desactivadas.

## Privacidad y alcance de la publicación experimental

La primera versión comprende los módulos Python de la raíz, las pruebas de
producción, `tests/evidencia_local.py`, los fixtures sintéticos y la documentación
pública. El `.gitignore` reserva fuera del repositorio exportaciones privadas,
documentos del usuario, configuraciones personales, entornos virtuales,
bytecode, copias de seguridad, bases de datos, informes, registros y temporales.
También excluye el histórico local, los prototipos APT y sus pruebas específicas,
y los componentes independientes `redes/` y `spreadsheet_anonymizer/` con sus
pruebas. `exportacion_chat/` no es un recurso de la aplicación y debe permanecer
fuera de cualquier publicación, también si se trabaja desde la carpeta exterior.

El `.gitignore` no elimina archivos ya rastreados ni detecta secretos. Los informes
pueden guardarse en rutas elegidas por el usuario: los patrones de exclusión no
cubren todos los nombres posibles. Revisar siempre la selección concreta antes
de incorporarla a Git. No publicar salidas nativas, conversaciones, inventarios
originales o archivos privados por el hecho de que una prueba haya terminado bien.

En Debian, Python muestra primero los hechos saneados de dpkg y APT; después,
la interpretación del modelo se identifica como no verificada. Totales `null`
son desconocidos, nunca cero; una candidata desconocida no prueba ausencia de
actualizaciones. La seguridad permanece no evaluada, incluso con adquisición
completa. Un fallo posterior de LM Studio conserva el resumen factual y no
provoca nuevas adquisiciones.

La colección de sesión conserva únicamente registros saneados en memoria. La
interfaz `:exportar` prepara y autoriza temporalmente una exportación; todavía
no publica archivos. El escritor y la persistencia SQLite son APIs separadas,
sin guardado automático. Véanse [la interfaz local](EXPORTACION_INTERFAZ_LOCAL.md),
[el escritor seguro](EXPORTACION_ESCRITURA_SEGURA.md) y
[la colección de sesión](SESION_RESULTADOS_INTEGRACION.md); estos documentos
contienen etapas históricas que deben distinguirse del comportamiento actual.

La consulta de seguridad aislada requiere Linux x86_64 y Landlock ABI >=3;
si no puede aplicar las protecciones falla cerrado. La correlación Fedora usa
opcionalmente el binding Python RPM; su ausencia deja la comparación sin
determinar. Los ejecutables necesarios varían por herramienta y se informan al
inicio. No se instalan dependencias automáticamente.

**Pendiente antes de la subida:** revisar el contenido final seleccionado. Esta preparación documental no inicializa Git,
no configura remotos, no publica archivos y no acredita una validación real APT.


## Autoría y créditos

Autor y responsable del proyecto: **Onmyodo**.
GitHub: [Onmyodo](https://github.com/onmyodo78).

Copyright (C) 2026 Onmyodo

El desarrollo ha contado con colaboración técnica mediante ChatGPT y Codex
(OpenAI), utilizados como herramientas de asistencia al desarrollo, revisión,
pruebas y documentación. Este crédito no atribuye a OpenAI ni a sus herramientas
la titularidad del copyright del proyecto.

## Licencia

AsistenteLocal se distribuye bajo la **GNU General Public License versión 3
exclusivamente**. Identificador SPDX: **GPL-3.0-only**.

El texto oficial íntegro está disponible en [LICENSE](LICENSE). El aviso de
copyright del proyecto figura por separado en el apartado de autoría; no se han
alterado las cláusulas de la licencia.

Las versiones derivadas que se distribuyan deben cumplir las obligaciones de
GPLv3, incluida la conservación de los avisos aplicables, la licencia de las
obras derivadas cubiertas y la entrega del código fuente correspondiente en los
casos y condiciones establecidos por la licencia. El programa se ofrece sin
las garantías descritas en GPLv3.
