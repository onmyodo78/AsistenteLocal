# Validación funcional real de GPT-OSS y AsistenteLocal

Fecha: 11 de noviembre de 2026. Rama `mejora-coordinador`. Endpoint exclusivo
`127.0.0.1:1234`; sin servicios externos, paquetes, sudo ni cambios en el modelo.
Este informe conserva solo resultados técnicos y contadores, no cuerpos de
peticiones, respuestas completas, documentos privados ni razonamiento interno.

## Resultado y alcance causal

El caso A (`system/user/system`) produjo final vacío en **3 de 3** ejecuciones;
el caso B (`system con los dos bloques/user`) produjo explicación válida en **3 de 3**.
La tercera comparación invirtió el orden B/A para reducir la confusión con calentamiento
u orden de ejecución. Dos parejas usaron la misma semilla de petición, 20261111.
La semilla no produjo respuestas B idénticas: no se presupone determinismo bit a bit.

A/B conservan modelo, temperatura 0.2, límite de 1800 tokens, `tool_choice=none`,
`tools` ausente, pregunta y textos factuales sintéticos. Solo difiere la posición
del bloque factual. En estas condiciones, el factor discriminante es la disposición
de mensajes procesada por la ruta API de LM Studio/GPT-OSS. No es el rechazo local
de razonamiento, el límite de 33 tokens ni una ausencia de datos reales de memoria.

La corrección de roles de `3cf9a19` queda validada en ejecución real. Es coherente
con la pérdida de system tardío demostrada en la plantilla Jinja del GGUF. A usa
1330 tokens de entrada, B 1435, diferencia estable de 105. Sin traza interna de la
ruta activa no se atribuye el fallo a una función concreta del formateador nativo,
Jinja o motor. Tampoco se afirma un defecto universal de GPT-OSS. El componente
queda acotado con evidencia a la construcción/formateo de esta conversación en
la ruta local LM Studio/GPT-OSS, antes de validar el contenido final en Python.

No se ejecutaron C, D o E: A/B ya discriminan sin cambiar razonamiento, herramientas,
alias del límite de tokens ni parámetros de muestreo. No se hicieron comparaciones
con historiales privados de la GUI ni se cambió su configuración de generación.

## Metadatos reales de A/B

Todos los casos obtuvieron HTTP 200 y `finish_reason=stop`. Razonamiento separado
activado tanto en los casos vacíos como en los válidos.

| Orden | Caso | Semilla | Entrada | Salida | Razonamiento | Caracteres finales | Segundos | Validación |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| 1 | A | no fijada | 1330 | 33 | 6 | 0 | 2,08 | sin_texto_ni_herramientas |
| 2 | B | no fijada | 1435 | 319 | 22 | 1285 | 22,89 | válida |
| 3 | A | 20261111 | 1330 | 33 | 6 | 0 | 3,10 | sin_texto_ni_herramientas |
| 4 | B | 20261111 | 1435 | 439 | 28 | 1727 | 28,63 | válida |
| 5 | B | 20261111 | 1435 | 510 | 30 | 2061 | 32,78 | válida |
| 6 | A | 20261111 | 1330 | 33 | 6 | 0 | 3,09 | sin_texto_ni_herramientas |

Una consulta de metadatos GET a `/api/v1/models`, también solo local, identificó
`openai/gpt-oss-20b`, arquitectura GPT-OSS, instancia cargada con contexto 8192 y
paralelismo 4. No se guardaron rutas de modelos ni información de otros modelos.

## Privacidad del servidor: cambio específico autorizado

La configuración preexistente tenía `logSensitiveData=true`. La primera pareja
A/B usó exclusivamente los cuerpos sintéticos ya documentados; se confirmó que
el servidor estaba persistiendo peticiones completas. Se detuvieron nuevas
solicitudes y se pidió autorización específica antes de cambiar configuración.

El usuario autorizó solo desactivar esa opción. Se cambió **únicamente**
`logSensitiveData` a `false` en el archivo técnico local de configuración del
servidor, verificando igualdad de todos los demás campos JSON. No hubo sudo,
instalación, reinicio, cambio de modelo, sampler o límites. Se deja esa opción
segura a false, sin restaurar la persistencia sensible.

Se comprobó el efecto en los segmentos nuevos de logs, desde offsets anteriores
al ensayo: no aparecían la pregunta sintética, el campo `messages`, `choices` ni
los campos de razonamiento de la respuesta. Solo se emitieron booleanos de esas
comprobaciones, nunca los segmentos. Las pruebas con memoria real se hicieron
**después** de esa verificación. No se borraron ni copiaron logs anteriores.

## Petición mixta con datos reales

Se ejercitó la entrada pública `preguntar()` con la petición de memoria RAM,
swap, explicación de su función y exclusión explícita de sudo. No se recurrió
a una plantilla con valores simulados para esta validación.

1. Primera ejecución con la corrección de roles: adquisición `/proc/meminfo`
   completa; informe factual mostrado antes de pedir explicación. HTTP 200/stop,
   1813 tokens de entrada, 429 de salida, 10 de razonamiento, 30,97 s. Respuesta
   conceptual presente. Se observó una inferencia demasiado fuerte del modelo
   sobre actividad/suficiencia a partir de la instantánea.
2. Se reforzó la instrucción de explicación sobre ocupación frente a actividad de
   intercambio y ausencia de evidencia para diagnosticar suficiencia. Una ejecución
   instrumentada agotó 45 s esperando cabeceras. No fue un final vacío ni hubo
   relajación del plazo; se conservaron los hechos, sin reintento automático.
3. Se añadió una instrucción de brevedad para preguntas conceptuales sencillas y
   se hizo **una nueva prueba manual finita**. HTTP 200/stop, 1883 tokens de entrada,
   343 de salida y 7 de razonamiento; 27,26 s. Informe factual completo y explicación
   de la función de la swap, movimiento de páginas y limitaciones, separada de los
   hechos y etiquetada como texto no verificado.

En las dos ejecuciones instrumentadas se envolvió el ejecutor con una comprobación
que solo admitía exactamente el lector fijo de `/proc/meminfo`; cualquier otro
comando habría sido rechazado antes de ejecutarse. Resultado de la última prueba:

- Una única ejecución del lector permitido; ninguna ejecución de sudo ni otro comando.
- Solo operación `memoria`, ejecución finalizada y verificación completa.
- Una petición al modelo, con herramientas desactivadas, omitidas y validación de
  explicación exigida. No se ejecutó ninguna herramienta propuesta por el modelo.
- `ALLOW_EXTERNAL=false`, contenido final no vacío y validación satisfactoria.
- Sin nuevos registros en historial/exportaciones ni persistencia de prompts.

Las cifras reales de RAM/swap son instantáneas variables y se mostraron al usuario
mediante el informe factual; este documento no las incorpora como datos de fixture.
No se guardó la explicación completa ni el razonamiento del modelo en artefactos.

## Cambios de esta entrega

- La disposición de roles que resuelve los vacíos ya estaba corregida en `3cf9a19`;
  no se ha reemplazado el parser ni aceptado final vacío o razonamiento como respuesta.
- Instrucciones más precisas y breves para explicación conceptual de memoria/swap.
  Se conserva la pregunta íntegra y el contexto reducido, con todos los límites.
- Corredor optativo `tests/diagnostico_gptoss_local.py`: solo A–E sintéticos,
  destino fijo mediante el transporte privado, máximo cinco solicitudes y plazo
  global 120 s/45 s por caso. Sin reintentos ni ejecución de herramientas. Retorna
  únicamente métricas, longitud final y resultado de validación. Requiere `--real`
  y confirmar por lectura de configuración que no se habilita logging sensible;
  no modifica configuración por sí mismo. El sondeo de archivo no sustituye la
  comprobación de que el servidor haya aplicado efectivamente esa opción.
- Regresiones con HTTP simulado para límites, privacidad, fallos, rechazo de
  herramientas, opt-in y bloqueo del corredor cuando la privacidad no está confirmada.

Ejemplo de corredor **real optativo**, no incluido en la regresión automatizada:

```sh
python3 -B tests/diagnostico_gptoss_local.py --real --casos A B --seed 20261111
```

## Problemas pendientes y límites de la validación

- Hubo un timeout de 45 s durante la prueba funcional. La explicación breve posterior
  completó el flujo; no demuestra eliminar todos los timeouts futuros. El límite y
  la conservación de hechos se mantienen.
- El modelo no siempre respeta la brevedad ni todas las cautelas: incluso la última
  explicación sugirió ausencia de necesidad histórica de swap a partir de una
  instantánea vacía. Esa inferencia **no está verificada**. No debe confundirse con
  el informe factual, que conserva actividad de intercambio `no_medida`. La etiqueta
  de texto del modelo se mantiene; no hay un validador semántico general.
- La función interna exacta del runtime responsable de la disposición anterior
  sigue sin identificarse; no ha sido necesario modificar LM Studio para recuperar
  una respuesta final válida. El cambio de logging solo protege privacidad.
- Esta evidencia corresponde a Debian 13, LM Studio 0.4.28+2 y el modelo local
  probado; no certifica otros modelos, versiones o configuraciones.

## Regresión automatizada final

Ocho pruebas nuevas del corredor real optativo, ejecutadas exclusivamente con
dobles. La regresión completa (`python3 -B tests/ejecutar_regresion_completa.py`)
terminó con **1.057 pruebas sin fallos, 12 omitidas**. Las integraciones reales del
corredor automatizado siguen desactivadas; las pruebas funcionales descritas arriba
se ejecutaron separadamente con autorización. `git diff --check` satisfactorio.
