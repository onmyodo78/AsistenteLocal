# Continuación de auditoría: diagnóstico local

## Diagnóstico histórico

La inspección inicial confirmó que, tras presentar un ResultadoDebian o
ResultadoAuditoria, preguntar() seguía permitiendo herramientas hasta consumir
los presupuestos generales. La continuación incluía los mensajes iniciales,
la llamada del asistente, el resultado limitado y todos los esquemas de
herramientas, con tool_choice="auto".

La primera modificación reutilizó la fase final existente al haber mostrado hechos de auditoría:
tool_choice="none" y rechazo local de llamadas posteriores aunque el servidor
ignore esa opción. En esa etapa los esquemas seguían presentes; no se modificó el cliente
HTTP, la validación, los plazos, los presupuestos ni la serialización factual.
Las llamadas de la misma tanda inicial siguen procesándose con las reglas
existentes. Las auditorías rechazadas no activan la fase final.

Esto corrige una continuación innecesariamente abierta a herramientas. No
prueba la causa del timeout: las pruebas usan HTTP simulado y no miden LM Studio.
Ese resultado simulado no demostró una mejora de latencia.

## Estado actual y resultados A/B

La continuación posterior a una ejecución autorizada de auditoria_seguridad con
resultado estructurado omite el campo tools y conserva tool_choice="none".
Mantiene una instrucción breve en el mensaje system existente: interpretar los
hechos en dos o tres frases, distinguir las actualizaciones detectadas en índices
APT locales de su frescura no verificada, conservar desconocidos y limitaciones
y no afirmar ausencia de vulnerabilidades. La primera petición conserva tools.
El resumen factual de Python, los mensajes tool con sus tool_call_id y su orden,
max_tokens=1800, la temperatura y los límites permanecen sin cambios en estas
dos pruebas A/B.

Según la prueba real comunicada por el usuario, añadir solo la instrucción breve
no mejoró la latencia: la segunda petición volvió a agotar 45 segundos en
espera_cabeceras. La posterior omisión de tools conserva esa instrucción para
cambiar una sola variable. Tiene pruebas simuladas satisfactorias (56 pruebas
en la selección limitada), pero aún no se ha validado con LM Studio real.
La aceptación de tools ausente junto con tool_choice="none" por la versión
instalada y su efecto sobre la latencia siguen pendientes. El timeout no está
resuelto y su causa concreta no está demostrada. No hay reintentos automáticos.

## Prueba posterior desde Konsole

Desde el directorio que contiene AsistenteLocal.py:

```sh
python3 -B AsistenteLocal.py
```

Solicitar una auditoría de seguridad y comprobar:

- Una única consulta autorizada de auditoria_seguridad.
- Hechos de Python visibles antes del comentario, con desconocidos y limitaciones.
- Dos registros LMSTUDIO_METRICAS si el modelo selecciona directamente la auditoría.
- En la segunda petición, observar espera_cabeceras y total_s, o fase_error y
  tipo_error si falla. No se han ampliado los 45 segundos por petición.
- Si falla la interpretación, se conservan los hechos sin reintentos.

Consultar memoria en otra pregunta para comprobar su continuación habitual.
Repetir en sesiones nuevas manteniendo modelo y ajustes constantes. Una mejora
frente al timeout comunicado sería indicio, no prueba causal. Para aislar la
hipótesis actual se necesita una comparación local pareada del mismo cuerpo de
continuación cambiando únicamente la presencia de tools, conservando la
instrucción breve y tool_choice="none", bajo el mismo
límite de 45 segundos y sin ejecutar las tool_calls devueltas. No basta comparar
con un prompt abreviado que cambia también los mensajes y el contexto.

## Regresión simulada histórica

```sh
PYTHONPATH=tests ASISTENTE_PRUEBAS_REALES=0 python3 -B -W error::ResourceWarning -m unittest test_continuacion_auditoria test_lmstudio_comunicacion test_entorno test_infraestructura_integracion test_finalizacion_general test_estabilizacion_debian test_auditoria_debian test_auditoria_seguridad.Auditoria test_interfaces_red test_memoria_verificada test_backend_seguridad test_errores test_resultado_verificado test_finalizacion_debian test_captura_conversacional -q
```

Resultado registrado en aquella etapa: 243 pruebas, sin fallos, errores ni omisiones. Se excluyó la integración
real y las clases que crean procesos o aplican aislamiento real; no se ejecuta
el descubrimiento general (véase README.md). No se han instalado dependencias
ni se contactó con LM Studio o servicios externos durante esa regresión simulada.
No se han ejecutado pruebas reales ni simuladas en esta actualización documental.
