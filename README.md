# AsistenteLocal

AsistenteLocal es una aplicación local de administración, diagnóstico, auditoría y mantenimiento Linux. Su autonomía operativa reside en Python y en políticas explícitas: puede seleccionar comprobaciones e investigar dentro de un alcance autorizado. El modelo local es una interfaz opcional de explicación y conversación; nunca es una autoridad administrativa ni una fuente de hechos verificados.

El núcleo determinista funciona sin LM Studio, GPT-OSS, Codex, VS Code ni Internet. Las auditorías y los planes son de solo lectura. Las rutas administrativas APT están separadas, requieren autorización específica y no forman parte del arranque habitual.

**Estado a 9 de noviembre de 2026:** entrega pública incorporada a la rama `main` de GitHub mediante el commit `9070eae7040be3a961d0852d5ee25d55775738f1`, por avance rápido y sin sobrescribir el historial anterior. No se han creado etiquetas de versión ni GitHub Releases.

El núcleo de lectura está validado en Debian 13, con comprobaciones nativas adicionales en Fedora 45. Las operaciones administrativas APT y la actualización integrada DNF5 siguen sin validación real integral; la actualización directa exitosa de DNF5 no valida AsistenteLocal. Se mantienen las restricciones y los estados conservadores; los avisos de alias persisten con XDG controlado.

Consultar [ESTADO_VERSION.md](ESTADO_VERSION.md), [el inventario de publicación](INVENTARIO_PUBLICACION.md) y [el cierre técnico Fedora](CIERRE_TECNICO_FEDORA.md).

## Autonomía y autoridad

| Nivel | Alcance |
| --- | --- |
| 1: observación | Comprobaciones locales de lectura dentro del objetivo solicitado, sin autorización individual por herramienta. |
| 2: investigación | Ampliaciones locales predefinidas; conexiones externas solo si están expresamente permitidas. |
| 3: automatización autorizada | El mecanismo general de delegación está previsto, no implementado. |
| 4: administración sensible | Exige autorización específica. El modelo no puede concederla ni generar comandos administrativos libres. |

El coordinador `auditoria_basica.py` aplica la política `auditoria_basica_local_v1` y
valida los contratos `autonomia_v1`. Incluye siete áreas, ampliaciones acotadas,
prioridades y motivos de parada. No constituye un planificador general autónomo.
La descarga y la instalación APT tienen autorizaciones independientes. Una recomendación
no autoriza ninguna de ellas. Diseño: [ARQUITECTURA_AUTONOMIA.md](ARQUITECTURA_AUTONOMIA.md).

La entrada conversacional incluye ahora lecturas deterministas de memoria, disco,
interfaces, VPN local y servicios fallidos. Las solicitudes ambiguas no ejecutan
herramientas. Alcance, ejemplos y límites: [autonomía operativa local](AUTONOMIA_OPERATIVA_LOCAL.md).

## Compatibilidad y requisitos

| Componente | Alcance comprobado |
| --- | --- |
| Debian 13 Trixie, x86_64, Python del sistema 3.13 | Auditoría real de las siete áreas y planificación APT local; resultados conservados fuera del conjunto público. |
| Biblioteca estándar de Python | Núcleo, CLI, contratos, SQLite y pruebas; no hay dependencias pip obligatorias. Otras versiones de Python no se certifican con esta validación. |
| `dpkg-query`, APT y `python3-apt` (`apt_pkg`) | Inventario, candidatas y simulación Debian. La ausencia del binding limita APT, no convierte los datos desconocidos en cero. |
| Herramientas de sistema | `uname`, `df`, `free`, `ip`, `ss`, `systemctl` y, según operación, `nmcli`/otros ejecutables detectados por el programa. Tener el binario no garantiza acceso al servicio. |
| Aislamiento Linux x86_64 | Seccomp y Landlock ABI ≥ 3 en las operaciones que lo requieren; si falla, se informa sin rebajar las protecciones. |
| LM Studio 0.4.28+2 + `openai/gpt-oss-20b` | Comunicación local e interpretación probadas en Debian. No certifica otros proveedores, modelos o equipos. |
| Fedora 45, RPM y DNF5 5.4.7.0 | Lecturas nativas comprobadas y regresión previa en Fedora. Preparación estricta no ejecutable; actualización interactiva implementada y experimental, sin validación integral. |
| DNF4 y otras versiones Fedora | Capacidades condicionadas al binding y caché; sin certificación general por las pruebas Fedora 45. |

LM Studio solo se necesita para conversación e interpretación. Su rendimiento depende
del equipo, carga, contexto y motor. La GPU no es una dependencia del núcleo de auditoría.
No se instala ninguna dependencia, controlador ni modelo automáticamente.

## Instalación y arranque

Clonar o copiar **el conjunto completo** indicado en `PUBLICACION_ARCHIVOS.txt`, no
solo el archivo principal. Desde el directorio que contiene `cli.py`:

```sh
/usr/bin/python3 -B cli.py capacidades
/usr/bin/python3 -B cli.py --help
/usr/bin/python3 -B AsistenteLocal.py --help
```

Utilizar una terminal nativa del anfitrión y un usuario normal. La CLI independiente
rechaza la ejecución como root. Un Python de un entorno virtual puede no encontrar
los bindings de la distribución: en Debian se valida `/usr/bin/python3`.
No hay un paso de instalación mediante pip. Si falta una capacidad, revisar sus
requisitos con el administrador; esta documentación no ejecuta instalaciones.
No iniciar AsistenteLocal con sudo.

Los bindings del sistema son opcionales por capacidad: `apt`, `apt_pkg` y
`apt_inst` en las operaciones Debian correspondientes; `rpm` para comparación de
versiones Fedora, `libdnf5` para preparación DNF5 y `dnf` para resolución DNF4.
No se incluyen en el proyecto ni se instalan automáticamente. Las rutas
administrativas requieren además sudo, `/dev/tty` y un helper protegido instalado
por separado; copiar las fuentes no lo instala. SSH no es un requisito de ejecución.

## Diagnósticos sin modelo ni Internet

```sh
/usr/bin/python3 -B cli.py auditoria-basica
/usr/bin/python3 -B cli.py --formato json auditoria-basica
/usr/bin/python3 -B cli.py auditoria-basica --excluir red
/usr/bin/python3 -B cli.py actualizaciones
/usr/bin/python3 -B cli.py --formato json actualizaciones
/usr/bin/python3 -B cli.py plan
/usr/bin/python3 -B cli.py --formato json auditoria
/usr/bin/python3 -B cli.py diagnostico-mantenimiento
/usr/bin/python3 -B cli.py --formato json plan-descarga-apt
```

`--formato` precede al subcomando. `plan-descarga-apt` muestra una propuesta; no descarga.
`auditoria-basica` cubre identidad, disco, memoria, servicios, red, seguridad y
mantenimiento. Se adapta a las capacidades reales y conserva evidencia, errores,
desconocidos, límites, prioridades y pendientes. No modifica paquetes ni consulta CVE
externas. Los resultados JSON conservan el detalle; el informe de terminal selecciona
lo relevante sin convertir ausencias en valores conocidos.

La consulta `actualizaciones` muestra nombres, arquitecturas y versiones instaladas y
candidatas. `plan` añade una **simulación**, separando candidatas y acciones previstas
por el resolvedor. En Debian usa simulación de `dist-upgrade`, que puede proponer
instalaciones o eliminaciones: no equivale a `apt-get -s upgrade` ni ejecuta el plan.
La frescura, autenticidad actual y cobertura de los índices locales no se presuponen.

Otros informes independientes, sin LM Studio:

```sh
/usr/bin/python3 -B AsistenteLocal.py --memoria-verificada
/usr/bin/python3 -B AsistenteLocal.py --interfaces-verificadas
/usr/bin/python3 -B AsistenteLocal.py --servicios-verificados
/usr/bin/python3 -B AsistenteLocal.py --conexiones-verificadas
/usr/bin/python3 -B AsistenteLocal.py --puertos-verificados
```

Detalles y códigos de salida: [motor independiente](MOTOR_INDEPENDIENTE.md) y
[diagnóstico de mantenimiento](DIAGNOSTICO_MANTENIMIENTO_APT.md).

## Conversación con LM Studio

En LM Studio, cargar el modelo y dejar disponible su servidor local en:

```text
http://127.0.0.1:1234/v1/chat/completions
model: openai/gpt-oss-20b
```

Dirección e identificador están fijados en `AsistenteLocal.py`; no hay selección de
proveedor mediante argumentos ni variable de entorno. El cliente actual no envía un
API token. Mantener el servidor restringido al equipo local. La compatibilidad con una
API similar no acredita integración con Ollama ni otros proveedores.

Arrancar como usuario normal:

```sh
/usr/bin/python3 -B AsistenteLocal.py
```

Ejemplos para el indicador `Tú:`:

```text
Realiza una auditoría básica del sistema y explícame los problemas encontrados, ordenados por prioridad.
Consulta ahora las actualizaciones pendientes de Debian.
Explica los resultados anteriores de auditoria_seguridad sin repetir la consulta.
```

Python reconoce las solicitudes explícitas de auditoría básica y las dirige al mismo
coordinador de la CLI. Las consultas específicas Debian usan su ruta independiente.
La salida factual aparece antes de la interpretación y se conserva si falla LM Studio.
En conversación, la auditoría Debian muestra un resumen factual de estados y cantidades;
para el listado por paquete y versiones, usar `cli.py actualizaciones`.

La explicación se etiqueta como texto del modelo no verificado. Puede equivocarse,
responder como JSON o generalizar indebidamente; no hay un verificador semántico completo.
Los contratos y las evidencias de Python no quedan modificados por esa explicación.
Las instrucciones se entregan durante la ejecución; no se ha entrenado ni modificado
GPT-OSS como parte de este proyecto.

### Proyección compacta opcional

El formato explicativo anterior sigue siendo el predeterminado. Para activar
`explicacion_compacta_v1` solo durante un proceso:

```sh
ASISTENTE_PROYECCION_AUDITORIA=compacta /usr/bin/python3 -B AsistenteLocal.py
```

Para volver al anterior:

```sh
ASISTENTE_PROYECCION_AUDITORIA=actual /usr/bin/python3 -B AsistenteLocal.py
```

Si la variable se exportó en la terminal, retirarla con `unset ASISTENTE_PROYECCION_AUDITORIA`.
La compacta se valida contra la traza original; no se recorta para entrar en presupuesto.
Si no cabe o falla la validación, se omite la interpretación conservando el informe.
No envía inventarios completos, aunque las conclusiones seleccionadas pueden contener
identificadores: no es un anonimizador. [Contrato y límites](PROYECCION_COMPACTA.md).

### Presupuestos y errores

- Deadline global monotónico: **120 segundos**, compartido entre herramientas y modelo.
- HTTP ordinario y selección de herramientas: **45 segundos** como máximo.
- Continuación marcada explícitamente como interpretación, sin herramientas: **90 segundos**,
  siempre recortados por el tiempo global restante.
- Cuatro rondas, ocho llamadas, hasta cuatro llamadas por respuesta; salida individual
  hasta 18.000 caracteres y presupuesto compartido de 60.000, según la ruta.
- Parámetros: `temperature=0.2`, `max_tokens=1800`, sin streaming en producción.
- No hay reintentos automáticos ante errores o timeouts. La espera es síncrona;
  cerrar la conexión local no demuestra cancelar la generación en LM Studio.

Los contadores `necesarios`, `opcionales` y `no_aplicables` de
`actualizaciones.indices` cuentan **índices APT**, no actualizaciones ni paquetes.

## Seguridad, permisos y funcionamiento offline

Los diagnósticos usan operaciones y argumentos predefinidos, sin `shell=True` ni terminal
libre para el modelo. No reciben privilegios administrativos permanentes. La consulta
local no refresca índices, instala dependencias ni repara el sistema automáticamente.
Las operaciones de lectura son posibles sin Internet si existen las fuentes locales
necesarias; la falta de caché puede producir un estado parcial o no verificable.

Las conexiones externas están desactivadas por defecto. La opción conversacional
`--permitir-consultas-externas` habilita únicamente las operaciones externas previstas,
como la consulta de IP pública de VPN y KEV cuando corresponda; no es navegación libre.
No activarla para uso exclusivamente local. El cierre validado no requiere esa opción.

Las rutas APT `descargar-apt`, `actualizar-apt`, `comprobar-ejecucion-apt` e `historial-apt`
usan un helper protegido separado; `historial-apt` también requiere autenticación.
`comprobar-ejecucion-apt` verifica la instalación sin sudo. No confundirlas con las consultas locales sin sudo.
El helper no se instala al copiar el proyecto. Su despliegue y ejecución están sujetos a
[EJECUCION_APT.md](EJECUCION_APT.md), validación del plan, autorizaciones, bloqueo,
verificación de archivos y diario SQLite. Estas rutas tienen pruebas simuladas, no una
validación real integral del helper de esta entrega. Un mantenimiento hecho con APT
nativo no acredita el ejecutor del proyecto. No desplegarlo como parte de la instalación
habitual de lectura ni ejecutar opciones administrativas solo para probar la aplicación.

Fedora dispone de entradas separadas `actualizar-dnf5`, `comprobar-ejecucion-dnf5`
e `historial-dnf5`. La actualización interactiva es experimental: los avisos de
alias impiden completar su validación posterior con el aislamiento conservado.
No redesplegar ni probar una actualización como parte de esta instalación.
El preparador estricto conserva `no_verificable` y ejecución deshabilitada; no
autoriza la ruta interactiva. El diario histórico `resultado_desconocido` conserva
su bloqueo. [Estado y restricciones Fedora](CIERRE_TECNICO_FEDORA.md).

Los informes, historiales SQLite y exportaciones son locales y pueden incluir datos
sensibles. No publicarlos ni copiarlos a GitHub. `.gitignore` no protege archivos ya
rastreados ni detecta secretos. No registrar contraseñas en el chat, en scripts o en logs.

## Limitaciones conocidas

- Debian no implementa correlación CVE ni clasificación automática de actualizaciones
  entre normales y de seguridad. Una procedencia APT no sustituye una evaluación CVE.
  No se certifica ausencia de vulnerabilidades, aunque no haya candidatas pendientes.
- El constructor explicativo anterior no admite una rama de memoria `ram=null` en
  ciertos datos parciales. El fallo conserva el informe factual; no se corrige en este cierre.
- Las lecturas Fedora 45 ya cuentan con evidencia nativa. La preparación DNF5 sigue
  sin simulación estructurada verificable y la actualización integrada interactiva
  sin validación completa. El éxito directo de DNF5 no valida AsistenteLocal.
  Se conservan ambos aislamientos de plugins, el rechazo de stderr y los estados
  `no_verificable` y `resultado_desconocido`; no se reclasifica el diario histórico.
- Las transacciones administrativas APT no cuentan con validación real integral.
  La lectura del historial y el mantenimiento manual no sustituyen esa validación.
- Ollama, streaming productivo, planificador general y delegación administrativa son trabajo futuro. El temporizador
  semanal de usuario es optativo y sigue desactivado hasta su instalación y activación voluntarias. Ninguna documentación de diseño los activa.
- Las validaciones de una configuración concreta no garantizan compatibilidad con
  otros modelos, distribuciones, versiones, arquitecturas o equipos.

## Pruebas

No necesitan LM Studio ni conectividad externa. Desde la raíz:

```sh
# Corredor de referencia: 874 casos; integraciones reales desactivadas.
TMPDIR=/tmp /usr/bin/python3 -B -W error::ResourceWarning tests/ejecutar_regresion_motor.py

# Referencia completa Debian: 982 casos, 970 superados y 12 omitidos.
TMPDIR=/tmp /usr/bin/python3 -B -W error::ResourceWarning tests/ejecutar_regresion_completa.py
```

TMPDIR=/tmp respeta la ruta cerrada de scratch del worker; cada prueba crea su
temporal privado único. No se cambia la configuración del sistema.

El segundo corredor reutiliza el primero y añade los módulos públicos complementarios,
sin duplicarlos. Mantiene desactivadas las integraciones reales. No usar descubrimiento
general sobre el workspace: puede incluir prototipos privados excluidos de esta entrega.
Las pruebas reales requieren autorización y revisión separadas; algunas integraciones
históricas realizan varias solicitudes al modelo y pueden imprimir respuestas completas.

Las pruebas simuladas no prueban un despliegue privilegiado ni el comportamiento de un
modelo real. [Estado de validación](ESTADO_VERSION.md), [privacidad y publicación](INVENTARIO_PUBLICACION.md).

## Documentación y licencia

- [Arquitectura de autonomía](ARQUITECTURA_AUTONOMIA.md) y [coordinador](AUDITORIA_BASICA_FASE2.md).
- [Motor independiente](MOTOR_INDEPENDIENTE.md), [planificación y diagnóstico APT](DIAGNOSTICO_MANTENIMIENTO_APT.md).
- [Proyección compacta](PROYECCION_COMPACTA.md) y [auditoría de portabilidad](AUDITORIA_PORTABILIDAD.md).
- [Cambios](CHANGELOG.md), [hoja de ruta](ROADMAP.md) y [revisión de mantenimiento](MANTENIMIENTO.md).

Los documentos de fases y diagnósticos describen momentos concretos del desarrollo;
README y ESTADO_VERSION son la referencia de estado de este cierre.
Licencia: [GNU GPL v3](LICENSE).

## Auditoría semanal y entrada APT independiente

Se reutiliza la auditoría básica mediante `cli.py auditoria-semanal --directorio RUTA`,
con informes privados, sin LM Studio y sin mantenimiento automático.
`cli.py unidades-auditoria-semanal --directorio RUTA_ABSOLUTA` solo imprime las
plantillas systemd de usuario: no las instala ni activa.

`mantenimiento_apt.py` ofrece una entrada dedicada a las operaciones APT existentes,
con autorización del plan y sudo interactivo para descarga/instalación, sin guardar
contraseñas. Requiere el helper protegido existente; no amplía sus políticas.
[Procedimiento, activación, reversión y límites](AUDITORIA_SEMANAL.md).

Validación real de lectura y autenticación: [informe de integración Debian](VALIDACION_INTEGRACION_DEBIAN.md).
