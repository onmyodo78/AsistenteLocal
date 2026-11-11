# GPT-OSS: contenido final vacío, inspección estática y pruebas propuestas

Rama: `mejora-coordinador`. Sin llamadas reales a LM Studio, Internet, sudo,
instalaciones ni cambios de configuración del equipo. No se cambia el planificador
ni el validador. Las pruebas de transporte usan dobles; los JSON de esta entrega
son propuestas, no instrucciones ejecutadas ni resultados reales.

## Qué confirma la segunda prueba

Con los metadatos comunicados (`content_tipo=texto`, `content_vacio=true`, HTTP 200,
`stop`, 33 tokens de salida y 6 de razonamiento), `message.content` decodificado es
una cadena **vacía**, no una cadena solo de espacios ni un tipo de contenido no
soportado. El rechazo `sin_texto_ni_herramientas` es correcto. El cliente extrae
metadatos y valida directamente el JSON, sin borrar el texto final ni sustituirlo
por razonamiento. `reasoning_presente` indica presencia de una clave conocida,
no demuestra por sí solo el contenido o longitud de su valor.

Los contadores de tokens no son una medida de caracteres visibles ni permiten
atribuir los 27 tokens restantes a una respuesta final entregada al cliente.
`stop` tampoco garantiza una respuesta pública no vacía. Las simulaciones con
los mismos contadores aceptan texto final válido y rechazan final vacío. No se
ha demostrado si faltó generación final o si el servidor la perdió al formatear.

## Payload exacto y presupuestos

`AsistenteLocal.consultar_modelo()` construye POST al único endpoint permitido:
`http://127.0.0.1:1234/v1/chat/completions`, `Content-Type: application/json`.

- `model`: `openai/gpt-oss-20b`.
- `temperature`: `0.2`.
- `max_tokens`: `1800`; no hay un límite de 33 tokens en AsistenteLocal.
- `tool_choice`: `none`; `tools` ausente.
- Ausentes: `response_format`, `stream`, `reasoning_effort`,
  `thinking_budget_tokens`, `max_completion_tokens`, `stop`, `seed`, `preset`,
  `top_p`, `top_k`, `min_p` y `repeat_penalty`.
- Plazo HTTP/modelo: 45 s, acotado por el plazo global de 120 s. Sin reintento.
  `solo_explicacion` es una opción interna: no se serializa como parámetro API.

No fijar esfuerzo de razonamiento no equivale a desactivarlo. No hay un presupuesto
independiente de razonamiento en el cliente. El backend puede completar antes
del máximo; el dato 33 no demuestra que se haya alcanzado el límite solicitado.

El cuerpo A propuesto reproduce el orden anterior: `system` con reglas y contrato
de explicación, `user` con la pregunta íntegra, `system` con proyección factual.
El cuerpo B contiene exactamente las mismas reglas, pregunta y proyección; une
ambos textos system con dos saltos de línea y deja el user al final. No se añaden
mensajes assistant ni tool, herramientas ni historial conversacional previo.

## Inspección local de LM Studio y del modelo

Fuentes leídas, sin ejecutar código de la aplicación instalada:

- `/opt/LM-Studio/resources/app/package.json`: versión `0.4.28+2`.
- `$HOME/.lmstudio/settings.json`: `developer.separateReasoningContentInAPI=true`,
  contexto predeterminado personalizado 8192 y protocolo runtime3 habilitado.
  Es configuración persistida, no una prueba de los ajustes efectivos de la
  instancia cargada durante el fallo.
- `$HOME/.lmstudio/.internal/backend-preferences-v2.json`: runtime preferido
  `llama.cpp-linux-x86_64-nvidia-cuda12-avx2`, versión `2.73.0`.
- Descriptor local `hub/models/openai/gpt-oss-20b/model.yaml`: modelo de razonamiento,
  campo `reasoningEffort` con `low` predeterminado y efecto sobre variable Jinja
  `reasoning_effort`. Muestreo declarado: temperatura 0.8, top-k 40, top-p 0.8,
  repeat penalty 1.1 y min-p 0.05. No se presupone que todos sean los valores
  efectivos de la petición API; AsistenteLocal sobreescribe temperatura con 0.2.
- Metadatos del GGUF local `gpt-oss-20b-MXFP4.gguf`: arquitectura `gpt-oss`, contexto
  declarado 131072; la plantilla usa canales `analysis`, `commentary`, `final`,
  tiene generación assistant y valor `medium` si no recibe `reasoning_effort`.
  Descriptor, plantilla y valores efectivos no son intercambiables.
- Bundle instalado `/opt/LM-Studio/resources/app/.webpack/main/index.js`:
  SHA-256 `0584020c477313953d8c30426072e736e8575114526e37b39a42fc6ce7f004c2`.

La inspección estática del bundle encuentra estas rutas relevantes:

1. El manejo de parámetros admite `max_tokens` y `max_completion_tokens` y ambos
   se asignan al mismo campo de configuración de predicción. No hay evidencia
   estática de que sustituir uno por otro resuelva el fallo; se propone como
   control, manteniendo 1800 y sin enviar ambos a la vez.
2. Hay soporte de `thinking_budget_tokens`, pero AsistenteLocal no lo envía.
3. La serialización Chat Completions toma `nonReasoningContent` cuando separa el
   razonamiento, y publica este por separado en `reasoning_content` o `reasoning`.
   Esto demuestra el mecanismo de separación, **no** que haya eliminado texto
   final válido en esta petición. El cliente acepta texto final presente en ambos
   casos y sigue rechazando razonamiento como sustituto del final.
4. Hay una ruta nativa `formatOpenaiChatToText` que agrupa contenidos system en
   instrucciones developer y una ruta alternativa Jinja. La ruta nativa tiene
   un valor de esfuerzo de reserva `medium`; no se ha probado qué variables ni
   ruta se aplicaron efectivamente a la ejecución del usuario.
5. La configuración persistida del servidor incluye `logSensitiveData=true` y
   `verbose=true`. No se han leído ni copiado conversaciones, logs de prompts o
   razonamiento. No se ha cambiado esa configuración. Las propuestas usan solo
   datos sintéticos precisamente para no enviar mediciones privadas a esos logs.

No se invoca el CLI `lms`, no se consulta el servidor para enumerar modelos, no
se carga un modelo ni se lee su contenido de pesos: únicamente metadatos GGUF.

## Defecto demostrado y corrección mínima

Se ha renderizado **offline** la plantilla completa incluida en el GGUF, con
marcadores sintéticos, usando Jinja2 ya disponible en el entorno. No se ha instalado
ni añadido Jinja2 como dependencia del proyecto. SHA-256 de la plantilla:
`f8d9255777615591a7cc1a7c932f5a69e181128902295e1b81221d20d983cac7`.

| Disposición | Instrucciones | Pregunta | Hechos |
| --- | --- | --- | --- |
| system / user / system | presentes | presente | **omitidos** |
| system con ambos textos / user | presentes | presente | presentes |

La plantilla extrae solo el primer system/developer; el bucle posterior procesa
assistant, tool y user, sin rama para otro system. Esto demuestra una pérdida de
contexto en la ruta Jinja de ese GGUF. La pregunta conceptual sigue presente;
por ello tampoco demuestra que perder los hechos cause un final vacío.

Corrección aplicada únicamente a `_explicar_peticion_local`: incorporar el bloque
factual al primer system y mantener al final la pregunta original completa. No
cambiar sus textos, adquisición, proyección de privacidad, herramientas, límites,
razonamiento, parser o validación. La ruta nativa encontrada agrupa los system,
por lo que tampoco puede atribuirse el fallo real a Jinja sin confirmar su uso.
No se declara resuelto el vacío observado hasta contrastarlo en ejecución real.

## Conversación directa y API: diferencias relevantes

No son una comparación controlada por el mero hecho de seleccionar GPT-OSS:

- La GUI puede tener historial, instrucciones, preset y ajustes por conversación;
  esta explicación API es una petición independiente con contexto explícito.
- Muestreo GUI/modelo declarado 0.8 frente a temperatura API 0.2; los demás valores
  omitidos pueden heredarse de configuraciones distintas.
- El nivel de razonamiento efectivo debe comprobarse, no deducirse de la UI,
  descriptor o plantilla por separado.
- La GUI puede mostrar bloques internos; el cliente solo admite el final público.
- Streaming, formateador nativo/Jinja, extracción de canales y condición de parada
  pueden seguir rutas diferentes. Que una conversación directa muestre texto no
  prueba que esta petición API haya recibido un final público correcto.

No se han reproducido conversaciones de la GUI ni se ha modificado su configuración.

## Pruebas reales propuestas: petición exacta y datos, aún NO ejecutadas

Todos los cuerpos son archivos JSON completos, revisables y sin marcadores a
sustituir. Mismo POST local y Content-Type indicado arriba. Contienen:

- Las reglas actuales de AsistenteLocal para Debian 13 y el contrato de explicación.
- La pregunta original: «Comprueba cuánta memoria RAM y swap tengo disponible,
  explícame para qué sirve la swap y no utilices sudo».
- Un resultado **sintético** etiquetado de memoria, con RAM disponible 4096 B y swap
  libre 2048 B; sin nombres, archivos privados, lecturas reales ni credenciales.
  No se ejecutaría una adquisición antes de enviar estas propuestas.

| Caso | Archivo con cuerpo exacto | Cambio y justificación |
| --- | --- | --- |
| A | [A_system_user_system.json](tests/fixtures/lmstudio_explicacion/A_system_user_system.json) | Orden anterior; control sintético, no copia del payload privado de la prueba real |
| B | [B_system_user.json](tests/fixtures/lmstudio_explicacion/B_system_user.json) | Solo agrupar system; contrastar el defecto de roles demostrado |
| C | [C_sin_tool_choice.json](tests/fixtures/lmstudio_explicacion/C_sin_tool_choice.json) | Respecto de B, solo omitir `tool_choice`, manteniendo `tools` ausente; aislar el procesamiento de esa opción |
| D | [D_reasoning_low.json](tests/fixtures/lmstudio_explicacion/D_reasoning_low.json) | Respecto de B, solo `reasoning_effort=low`; aislar herencia del esfuerzo sin desactivar razonamiento |
| E | [E_max_completion_tokens.json](tests/fixtures/lmstudio_explicacion/E_max_completion_tokens.json) | Respecto de B, sustituir el nombre `max_tokens` por `max_completion_tokens`, ambos 1800; comprobar el alias sin ampliar presupuesto |

Estos cuerpos se construyeron capturando el Request de producción con transporte
simulado. Las variantes no cambian la configuración ni los defaults del programa.
Los contadores 1331/33/6 de las pruebas simuladas son fixtures, **no** una estimación
de los tokens que generarían estos cuerpos en una ejecución real.

Si se autorizan después: empezar por A/B con el mismo modelo cargado y ajustes
estables, 45 s por petición, 120 s totales y límite de cuerpo 1 MiB; sin reintento
automático ni ejecución de ninguna herramienta devuelta, también en C. Los demás
casos se solicitarían por separado si A/B no discriminan. No se han enviado estos
Requests ni existe aquí un corredor que los ejecute automáticamente. La variación
estocástica exige cautela: una sola respuesta distinta no demuestra causalidad;
una comparación repetida necesitaría un número finito y presupuesto autorizados.

Registrar únicamente códigos, forma pública, tokens y duración; no capturar texto
interno. Para distinguir generación sin final de un error de extracción del
servidor también se necesitarían metadatos de la ruta de formato activa y condición
real de parada (EOS, cadena de parada, límite/cancelación), o longitudes antes y
después de separar canales. Los contadores API actuales no proporcionan eso. No
se activan logs adicionales ni se solicitan aquí registros de razonamiento.

## Hipótesis pendientes y discriminación

| Hipótesis | Estado | Prueba que la distingue |
| --- | --- | --- |
| El cliente vacía el final al separar razonamiento | Contradicha por el código y los dobles con final válido | Parser acepta el mismo final con/sin campo de razonamiento |
| 33 tokens implican agotar el máximo de AsistenteLocal | Sin soporte: se envía 1800 | E comprueba alias; conocer configuración efectiva/stopReason antes de atribuir un límite del servidor |
| System tardío omitido | Demostrado en la plantilla Jinja local | Confirmar ruta activa y comparar A/B; no prueba todavía la causa del final vacío |
| Nivel de razonamiento efectivo distinto entre GUI/API | Pendiente | D y metadatos efectivos del backend |
| Interacción `tool_choice=none` sin herramientas | Pendiente | C frente a B, manteniendo rechazo local de herramientas |
| Generación termina sin final o se pierde al extraer canales | Pendiente | Ruta y condición de parada más longitudes pre/post; no leer ni aceptar razonamiento como respuesta |
| Historial, instrucciones o muestreo de GUI explican la diferencia | Pendiente | Comparación realmente pareada con datos sintéticos y ajustes equivalentes |

## Regresión

Seis pruebas nuevas: pérdida del system tardío en un doble reducido, preservación
completa con el nuevo orden, igualdad del payload de producción con B, variantes de
una variable con presupuestos iguales, final válido con/sin razonamiento y
33 tokens/6 de razonamiento tanto con final vacío como válido. El doble reducido
no pretende sustituir la prueba local con la plantilla completa ni simula inferencia.
El validador sigue rechazando final vacío y razonamiento interno como respuesta.

Comandos de pruebas simuladas:

```sh
PYTHONPATH=.:tests python3 -B -m unittest test_lmstudio_comunicacion -q
python3 -B tests/ejecutar_regresion_completa.py
```

Resultado: 44 pruebas de comunicación simulada satisfactorias; regresión completa
con 1.049 pruebas sin fallos y 12 omitidas por las condiciones del corredor.
`git diff --check` satisfactorio. Sin prueba funcional nueva con el modelo.
