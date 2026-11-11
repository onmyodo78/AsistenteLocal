# Autonomía operativa local: fases 1–3

Implementación local en `mejora-coordinador`, desde `main` (`fb15c95`). No publicada.

## Entrada y alcance

`motor_consultas.planificar()` conserva `Plan`, añade `tipo`, `motivo` y la marca
interna `local`, y clasifica solicitudes operativas, conceptuales y ambiguas.
La gramática reconoce IDs cerrados y peticiones explícitas. No interpreta comandos,
argumentos, destinos ni permisos proporcionados en el texto. Rechaza cambios del
sistema, condicionales, alternativas, referencias locales sin contexto admitido y
mezclas cuyo alcance no puede separar con seguridad. Las exclusiones se aplican
por cláusula; una cláusula afirmativa posterior necesita acción explícita tras una
negación. Los identificadores exactos del catálogo cuentan como selección explícita.

Ejemplos:

| Petición | Comportamiento |
| --- | --- |
| Comprueba la memoria | Lectura de `/proc/meminfo`, normalización e informe Python |
| Revisa memoria y disco | Dos adquisiciones locales, sin repetición |
| Comprueba memoria, sin consultar VPN | Solo memoria |
| Qué es la RAM y comprueba disco | Solo adquiere disco; no llama al modelo para explicar RAM |
| Cómo puedo comprobar la memoria | Respuesta conceptual, herramientas desactivadas y omitidas |
| Mi VPN va mal | Aclaración, sin adquisición ni modelo |
| Comprueba servicios | Solicita precisar servicios fallidos |
| Comprueba servicios fallidos | Consulta existente del gestor systemd del sistema |
| Comprueba conexiones de la VPN | Aclara el alcance; no añade consultas de sockets |
| Actualiza el sistema | Fuera de esta ruta de lectura; no abre administración |
| Comprueba mi IP pública | Capacidad independiente no implementada; consulta externa no ejecutada |

Las auditorías básicas siguen entrando primero en su coordinador existente.
Las auditorías de seguridad y su contexto de sesión mantienen su protocolo previo,
incluida su interpretación opcional. La selección previa de seguridad en Debian no
se sustituye ni se amplía su autorización. Las peticiones no reconocidas de la nueva
entrada pública ya no delegan adquisiciones a `tool_choice: auto`.

## Ejecución y verificación

`operaciones_locales.py` valida IDs y vuelve a comprobar capacidad y política antes
de adquirir. Registra en memoria, separadamente, capacidad, autorización, ejecución,
verificación, motivo e informe. Un binario presente no demuestra que su servicio sea
accesible. Una ejecución finalizada puede tener verificación parcial o errónea.
Las excepciones propias no publican texto original ni provocan reintentos elevados.

Se reutilizan:

- Memoria: adquisición verificada y `normalizar_memoria`/`informe_memoria`.
- Disco: función extraída del adaptador de autonomía, sin cambiar su contrato;
  `df -h` y `statvfs` sobre `/`, `/usr`, `/var` y `/tmp`, deduplicando dispositivos.
  El informe no publica salida libre de `df`; solo representa esos montajes.
- Interfaces: adquisición, parser e informe existentes; conserva resultados parciales.
- Servicios: adquisición y contrato existentes, sin descripciones ni errores originales;
  nombres de servicios visibles como en el modo verificado anterior.
- VPN local: comando escapado de NetworkManager ya incluido en `interfaces_red` y su
  parser existente. Publica solo recuento de tipos túnel y estados cerrados. Es una
  observación parcial: no enumera todos los perfiles VPN ni prueba conectividad,
  encaminamiento, IP pública o ausencia de fugas. No publica nombres de conexiones.

Los demás IDs del catálogo local (`sistema`, `puertos`, `conexiones`, `cortafuegos`,
`trafico_red`, `listar_documentos`) conservan acceso explícito a los comandos previos.
Su salida se etiqueta como dato de herramienta, con verificación de dominio
`no_verificable`, sin inventar éxito global ni ampliar su alcance. Conservan sus
reglas previas de visibilidad y privacidad; no se añaden al historial.

La ruta nueva presenta exclusivamente plantillas y resultados de Python. No solicita
interpretación del modelo ni acepta propuestas de ampliación de este. La respuesta
conceptual se identifica como texto no verificado y comprobación no realizada;
cualquier llamada de herramienta que el modelo devuelva en ella se rechaza.

Se mantienen los límites existentes: plazo total 120 s, hasta 15 s por comando,
8 operaciones, salida por informe 18.000 y total 60.000 caracteres, captura de
comandos 65.536 bytes. Las constantes de rondas, llamadas por respuesta y límites
HTTP/modelo no cambian. La nueva ruta no tiene rondas de herramientas del modelo.
Comprueba plazo antes y después de adquirir y antes de publicar; no presenta datos
tardíos. Los avisos y metadatos también quedan acotados al publicar.

## Autoridad, privacidad y límites pendientes

No hay comandos nuevos, shell libre, instalación de dependencias, acceso
administrativo automático ni cambios en los contratos `autonomia_v1`,
`ResultadoVerificado`, mantenimiento o autorización APT/DNF5. Los resultados de la
nueva ruta no amplían `ContextoFactual`, la colección de sesión, exportación ni
persistencia. No se guardan preguntas o interpretaciones en esos contratos.

La ruta nueva es siempre local: no ejecuta `diagnostico_vpn`, incluso con el flag
externo heredado. El despachador anterior y sus controles de autorización permanecen;
no se modifican sus destinos. No se implementa una herramienta independiente de IP
pública ni una segunda fuente HTTPS. No se debe interpretar el flag heredado como
habilitación de IP pública dentro del nuevo coordinador.

La gramática no es un intérprete general de español. Puede pedir aclaración ante
peticiones válidas no reconocidas. Las cláusulas conceptuales de una solicitud mixta
no reciben explicación adicional en la respuesta operativa. No hay integración nueva
con historial ni reutilización de observaciones locales anteriores. La interpretación
libre de auditorías anteriores conserva su etiqueta de texto no verificado; estas
fases no añaden un validador semántico general del lenguaje del modelo.

## Validación reproducible

Desde el proyecto:

```sh
PYTHONPATH=.:tests python3 -B -m unittest test_operaciones_locales -v
python3 -B tests/ejecutar_regresion_completa.py
```

La suite nueva usa dobles de comandos, adquisiciones, sistema de archivos y modelo,
y barreras ante procesos y HTTP reales. Cubre clasificación, negaciones, mezclas,
IDs desconocidos, dependencias ausentes, denegaciones externas, parcialidad,
permisos, errores, cancelación, presupuestos, datos tardíos, privacidad y texto
incorrecto del modelo. El corredor completo desactiva integraciones reales.

Las suites históricas de protocolo assistant/tool prueban ahora directamente
`_preguntar_con_herramientas`, sin eliminar sus verificaciones de transporte,
denegaciones, límites y presentación. La suite nueva prueba la entrada pública;
las pruebas de auditoría básica y seguridad de sesión conservan cobertura pública.
La recuperación del bucle principal ante fallos HTTP se prueba con preguntas
conceptuales en vez de solicitudes ambiguas que ya no deben llamar al modelo.

No se han ejecutado actualizaciones, consultas externas reales, sudo ni integración
real con LM Studio. No se certifica comportamiento nativo nuevo en este equipo.

Resultado de esta entrega: 27 pruebas nuevas satisfactorias; regresión completa de
1.009 pruebas sin fallos, con 12 omitidas por las condiciones del corredor.
