# Autonomía operativa local: fases 1–3

Implementación local en `mejora-coordinador`, desde `main` (`fb15c95`). No publicada.

## Entrada y alcance

`motor_consultas.planificar()` conserva `Plan`, añade `tipo`, `motivo` y la marca
interna `local`. La revisión de intención añade `explicar`, `pendientes` y el tipo
`mixta`, sin cambiar los contratos de adquisición o autorización existentes.
La gramática reconoce IDs cerrados y peticiones explícitas. No interpreta comandos,
argumentos, destinos ni permisos proporcionados en el texto. Rechaza cambios del
sistema, condicionales, alternativas y referencias locales sin contexto admitido
únicamente en la cláusula afectada; conserva las lecturas independientes reconocidas.
Las exclusiones de consultas, explicaciones y privilegios tienen alcances distintos.
Una negación factual dentro de una explicación no excluye esa explicación. Una
cláusula afirmativa posterior necesita acción explícita tras negar una adquisición. Los identificadores exactos del catálogo cuentan como selección explícita.

Ejemplos:

| Petición | Comportamiento |
| --- | --- |
| Comprueba la memoria | Lectura de `/proc/meminfo`, normalización e informe Python |
| Revisa memoria y disco | Dos adquisiciones locales, sin repetición |
| Comprueba memoria, sin consultar VPN | Solo memoria |
| Qué es la RAM y comprueba disco | Adquiere disco; después LM Studio explica con la pregunta original completa |
| Comprueba memoria sin sudo y explica el resultado | Lee memoria sin elevación y después explica |
| Comprueba memoria y ejecuta id | Lee memoria; informa de la parte no reconocida sin ejecutar comandos libres |
| Comprueba IP pública y explica qué significa | Informa del bloqueo externo y atiende la explicación |
| Comprueba si hay memoria disponible | Consulta operativa; «si» interrogativo no equivale a una condición |
| Cómo puedo comprobar la memoria | Respuesta conceptual, herramientas desactivadas y omitidas |
| Mi VPN va mal | Aclaración, sin adquisición ni modelo |
| Comprueba servicios | Solicita precisar servicios fallidos |
| Comprueba servicios fallidos | Consulta existente del gestor systemd del sistema |
| Comprueba conexiones de la VPN | Aclara el alcance; no añade consultas de sockets |
| Actualiza el sistema | Fuera de esta ruta de lectura; no abre administración |
| Comprueba mi IP pública | Capacidad independiente no implementada; consulta externa no ejecutada |

Las auditorías básicas siguen entrando primero en su coordinador existente.
Las solicitudes simples de seguridad y las referencias a su contexto de sesión
mantienen el protocolo previo. En solicitudes mixtas o con exclusiones separables,
las adquisiciones de seguridad usan el motor independiente existente, siempre local
y sin CISA KEV externa, con el mismo plazo compartido. El sondeo respeta el backend
disponible; una correlación no implementada no impide las demás partes. No se amplía
la autorización ni se incorpora esta ruta mixta a la sesión persistente. Las peticiones no reconocidas de la nueva
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

Las lecturas puramente operativas siguen presentando resultados de Python sin
modelo. Las preguntas conceptuales y las partes explicativas de solicitudes mixtas
se envían a LM Studio con la pregunta original completa, herramientas desactivadas
y omitidas, sin conceder autoridad para reabrir adquisiciones. Los informes factuales
se presentan antes de solicitar explicación; el fallo de esta no repite adquisiciones
ni borra los hechos. El plazo total y el presupuesto de salida son compartidos.

El contexto explicativo es una proyección efímera cerrada: estados de las operaciones,
informes numéricos de memoria/disco, estados VPN sin identificadores y recuento de
servicios fallidos. No envía nombres de servicios, interfaces, conexiones, inventarios,
errores originales ni las salidas libres del catálogo. No retiene un contexto nuevo
en sesión, historial o exportaciones. Los datos omitidos se declaran desconocidos.

La explicación sigue etiquetada como texto del modelo no verificado. Se rechazan
llamadas de herramientas, respuestas incompletas y patrones explícitos de ejecución
atribuida al modelo o de recomendación de elevación. Se permiten las explicaciones
negativas y definiciones legítimas sobre privilegios. Estos controles acotados no
constituyen una validación semántica general del lenguaje generado.

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
partes válidas no reconocidas, sin cancelar las demás cláusulas seguras. La pregunta
original se conserva para la explicación, sin reconstruirla a partir de palabras
clave. Una explicación puede faltar si LM Studio falla, su respuesta es rechazada o
se agota el presupuesto; se informa de ello sin volver a adquirir datos. No hay integración nueva
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

La entrega inicial añadió 27 pruebas. La revisión de preservación de intención añade
23 casos (50 pruebas específicas en total) sobre solicitudes mixtas, exclusiones,
negación de privilegios y de explicaciones, preguntas operativas interrogativas,
partes bloqueadas o desconocidas, errores del modelo, presupuesto compartido,
privacidad del contexto y conservación de las adquisiciones de seguridad locales.
Los casos reprodujeron los defectos antes de corregirlos.

Resultado de la revisión: regresión completa de 1.032 pruebas sin fallos, con
12 omitidas por las condiciones del corredor. Sin validación real con LM Studio.

## Diagnóstico de rechazos de explicación

La prueba funcional con HTTP 200, `finish_reason=stop`, 1331 tokens de entrada y 33
de salida no permite determinar la forma de `message`. En la versión anterior,
`fase_error=validacion` y `tipo_error=RespuestaInvalida`, junto con finish reason y
uso ya extraídos, sitúan el fallo después de decodificar JSON y dentro del validador
estructural de `consultar_modelo`. El filtro textual de la explicación se ejecutaba
después de emitir esas métricas: no explica ese registro concreto. Tampoco había
un mínimo de longitud de texto que rechazase por sí mismo una explicación breve.

Payload conservado: POST al único endpoint local
`http://127.0.0.1:1234/v1/chat/completions`, modelo `openai/gpt-oss-20b`,
`temperature=0.2`, `max_tokens=1800`, `tool_choice=none`, sin `tools`, `stream`,
`response_format` ni `reasoning_effort`. Los mensajes siguen siendo system con las
reglas, user con la pregunta original completa y system con la proyección factual
reducida. El modo interno `solo_explicacion` no añade campos al payload, no modifica
el plazo de 45 s del modelo ni el plazo global de 120 s, y exige herramientas
omitidas y desactivadas. El planificador no cambia.

El contrato sigue siendo Chat Completions: objeto JSON, `choices` no vacío, primer
`message` con `role=assistant` y contenido textual público. Una respuesta breve no
vacía se admite. Los campos adicionales, incluido razonamiento separado, no se
usan como texto público. No se adaptan listas de contenido, otros endpoints ni
formatos Harmony sin evidencia de que sea el formato servido. `tool_calls=null`
sigue siendo ausencia de llamadas; las llamadas efectivas, también el campo legado
`function_call`, se rechazan en la explicación. Se rechazan contenido solo de
espacios y finales distintos de `stop` o del campo omitido/nulo ya admitido.

El filtro textual previo se extrae a `validar_explicacion` y se aplica dentro de la
fase de validación HTTP cuando se solicita ese modo. Así los rechazos estructurales
y los del filtro textual quedan diferenciados. Se conserva su comprobación en el
consumidor para dobles y otros llamadores; nunca habilita ejecución de herramientas.

Cada rechazo tiene ahora un código cerrado (`motivo_validacion`) y las métricas
incluyen `forma_respuesta`: tipo de contenido, vacío/solo espacios y presencia de
campos conocidos de razonamiento o herramientas. Ambas proyecciones se sanean de
nuevo en el emisor. No se registran prompts, respuestas, razonamiento, nombres de
campos desconocidos ni mensajes originales de excepciones. El aviso al usuario
puede incluir el código seguro; conserva el informe factual y no reintenta.

Una simulación con `content=null` y `reasoning_content` separado reproduce exactamente
la combinación HTTP 200/stop/33 tokens y el rechazo estructural, ahora identificado
como `sin_texto_ni_herramientas`. Otras formas inválidas también podrían explicar
el registro anterior. Es una reproducción posible, **no la causa real confirmada**.
Sin la estructura de la respuesta real o los nuevos metadatos no se puede elegir
entre esas causas. La compatibilidad del formato Chat Completions se prueba con
dobles; no se certifica aquí la configuración real de LM Studio o su plantilla del
modelo. No se convierte razonamiento en respuesta para evitar el rechazo.

Validación: 11 regresiones nuevas de payload, respuesta corta, contenido ausente,
vacío, solo espacios, no textual, campos adicionales, JSON/roles inválidos,
llamadas de herramientas, finales, filtro textual y privacidad de las métricas.
Regresión completa: 1.043 pruebas sin fallos, con 12 omitidas. Sin consultas reales,
reintentos automáticos nuevos, cambios de permisos ni relajación global del validador.
