# Inventario de publicación revisado

Revisión: 9 de noviembre de 2026. Preparación local autorizada, sin git add,
commit, push, publicación ni despliegue. La raíz contiene cli.py y AsistenteLocal.py.

## Conjunto exacto propuesto

[PUBLICACION_ARCHIVOS.txt](PUBLICACION_ARCHIVOS.txt) enumera **169 archivos**:
95 rastreados y 74 sin seguimiento al preparar esta revisión. Incluye fuentes,
pruebas, fixtures sintéticos, documentación y licencia; no selecciona el índice Git.
Publicar solo lo ya rastreado dejaría incompleto el motor. No copiar el workspace
entero ni utilizar paquetes antiguos como si representasen esta selección.

| Grupo | Archivos necesarios |
| --- | --- |
| Entradas y núcleo | CLI, conversación, mantenimiento independiente, motor, contratos, adaptadores y todos sus módulos locales importados |
| Diagnóstico y lectura | Auditoría básica, parsers, informes, APT y transporte/worker con aislamiento |
| Administración | Fuentes comunes y específicas APT/DNF5, autorizaciones y registro; incluirlas no instala ni valida el helper |
| DNF5 incorporado | dnf5_preparacion.py, mantenimiento_dnf5.py, dnf5_interactivo.py y MANIFIESTO_DNF5_COMPAT_547.sha256 |
| Pruebas incorporadas | test_cliente_diagnostico_transporte.py, test_tty_confirmacion.py, test_dnf5_interactivo.py y test_dnf5_preparacion.py, bajo tests/ |
| Estado Fedora | CIERRE_TECNICO_FEDORA.md, CORRECCION_DNF5_547.md, MANTENIMIENTO_FEDORA_INTERACTIVO.md y VALIDACION_FEDORA_DNF5.md |
| Historia útil conservada | IMPLEMENTACION_DNF5.md explica la separación del preparador; DIAGNOSTICO_RECHAZO_DNF5.md explica el contenedor modular opaco. Ambos delimitan su fase histórica |

La propuesta inicial PROPUESTA_DNF5.md, CORRECCION_TTY_DNF5.md y
MANIFIESTO_DNF5_TTY.sha256 se conservan intactos únicamente en local y quedan
excluidos expresamente. La propuesta fue sustituida por implementación y cierre;
la corrección TTY está cubierta por el código/pruebas y el manifiesto antiguo no
identifica las fuentes candidatas. Su conservación local no autoriza usarlos para
un despliegue. El candidato vigente coincide con los ocho módulos enumerados.

No hay dependencias pip obligatorias. Los bindings nativos apt, apt_pkg, apt_inst,
dnf, rpm y libdnf5 no se distribuyen; su disponibilidad determina capacidades.
Los requisitos por distribución, arquitectura y operación están en el README.

## Material local excluido y preservado

- Informes reales, historiales, SQLite, exportaciones y documentos privados.
- respaldos_locales/, privado/, documentos/, informes/, exportaciones/ y dist/.
- Entornos, cachés, bytecode, logs, prototipos excluidos y configuración de editor/agente.
- Claves locales, contenedores de claves y ubicaciones específicas de credenciales.
- AsistenteLocal_ESTADO_PROYECTO.md y los tres históricos enumerados arriba.

No se borra ni mueve ese material. No hay archivos rastreados cubiertos por las
exclusiones actuales. .gitignore no elimina archivos ya rastreados ni detecta secretos.
No se excluyen globalmente JSON, Markdown, archivos comprimidos ni unidades systemd.
La selección no contiene certificados públicos o fixtures de claves que requieran
excepciones a las reglas nuevas; futuras incorporaciones necesitarán revisión.

## Privacidad y saneamiento

Se revisaron los 172 candidatos iniciales y todos los objetos Git disponibles
localmente: 123 blobs, seis árboles y tres commits, con referencias y reflogs.
No aparecieron objetos adicionales fuera de ese alcance. No se ha consultado GitHub.
La revisión combinó patrones de credenciales con rutas, red, identificadores,
metadatos y lectura contextual de documentación. No se encontraron credenciales
operativas ni claves privadas. Es una búsqueda limitada, no una garantía absoluta.

Se retiraron la ruta privada del respaldo Fedora y la huella del inventario RPM,
conservando la conclusión de igualdad antes/después. Se omitieron recuentos de
inventario/candidatas, tamaños de descarga, espacio observado y ubicaciones concretas
de registros y respaldos cuando describían el laboratorio. No se inventaron valores
sustitutos ni se modificaron diarios, registros o respaldos originales. Se conserva
una copia privada temporal de los documentos anteriores fuera del conjunto público.

Las credenciales aparentes en test_lmstudio_comunicacion.py y
test_dnf5_preparacion.py son sintéticas y prueban saneamiento. Las rutas, direcciones,
MAC y nombres ficticios de fixtures se conservan por su función de prueba.
Los endpoints públicos predefinidos y loopback son comportamiento del programa,
no direcciones personales detectadas. Los autores de commits usan correo noreply.
Los hashes públicos de fuentes, manifiestos y avisos DNF5 se conservan; no son
huellas de inventario del equipo. Los informes reales permanecen privados.

## Validación de la copia exacta

Se prepara una copia temporal fuera del repositorio usando únicamente el manifiesto,
sin .git, informes reales ni acceso a respaldos como parte de la selección.
La comprobación abarca conjunto exacto y hashes, sintaxis Python, dependencias
locales transitivas, módulos dinámicos de los corredores, enlaces internos,
exclusiones y privacidad. Las importaciones ejecutadas se verifican en un proceso
separado con red y escrituras bloqueadas; los bindings opcionales se identifican
estáticamente y no se instalan ni inicializan para forzar capacidades.

La regresión se ejecutó en Debian 13.7, Python 3.13.5, desde la copia exacta,
con integraciones reales apagadas, HOME privado separado y sin modificar pruebas.
TMPDIR=/tmp respeta el contrato del worker: las pruebas crean sus temporales
privados únicos directamente bajo /tmp, no dentro de la copia de publicación.

| Corredor | Casos | Superados | Omitidos | Fallos/errores |
| --- | ---: | ---: | ---: | ---: |
| Referencia | 874 | 874 | 0 | 0/0 |
| Completo | 982 | 970 | 12 | 0/0 |

El completo incluye los casos del corredor de referencia; no se suman como casos
distintos. Las omisiones son integraciones optativas desactivadas y no certifican
comportamiento administrativo ni actualización nativa.

Se comprobaron 169 archivos y sus hashes, 125 Python, 29 documentos Markdown,
493 referencias de importación local, los módulos dinámicos de ambos corredores,
48 enlaces internos y los ocho módulos del manifiesto candidato. Se importaron
61 módulos en un proceso separado con red y escrituras bloqueadas mediante el
mecanismo existente. Las 15 comprobaciones representativas de exclusión pasaron
y ningún archivo seleccionado queda ignorado. No hay certificados ni fixtures
necesarios ocultos por las reglas nuevas.

Se conservan fuera del repositorio los registros de dos intentos previos fallidos:
el primero usó directorios nuevos de validación con modo 0775 y obtuvo 9 fallos y
15 errores; al crearlos privados quedaron resueltos esos rechazos de custodia.
El segundo mantuvo un fallo porque TMPDIR anidado no cumple la exigencia literal
del worker de usar /tmp. La ejecución final respetó ese contrato y pasó ambos
corredores. No se alteraron aserciones, políticas ni resultados históricos para
obtener ese resultado. No se confunde la copia temporal con un contenedor de todo
el sistema: el bloqueo real de red/escritura se verificó en el proceso de imports;
las suites emplearon sus dobles y barreras de integración existentes.

Las fuentes Python, pruebas, índice Git y HEAD permanecen idénticos a la referencia
anterior a esta tarea. No se revalidó ni modificó el helper instalado. Se conservan
la copia exacta, hashes y logs de validación fuera del repositorio; no forman parte
de la selección pública ni autorizan una publicación.

## Límites y autorización

La actualización integrada Fedora sigue sin validación completa. Se conservan
ambos aislamientos de plugins, rechazo de stderr, no_verificable,
resultado_desconocido y bloqueo histórico; el éxito directo de DNF5 no los cambia.
La preparación estricta no autoriza la ruta interactiva. APT carece de validación
real integral de transacciones; memoria ram=null y correlación CVE Debian siguen
pendientes. Las pruebas simuladas no eliminan estas limitaciones.

Esta preparación no autoriza redespliegues, transacciones, reconciliación del diario
ni publicación. Cualquier futura selección Git o publicación necesita autorización.
