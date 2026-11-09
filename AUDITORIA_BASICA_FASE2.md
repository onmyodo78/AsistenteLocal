# Fase 2: coordinador determinista implementado

Política `auditoria_basica_local_v1`; registros `autonomia_v1`. No se añaden
políticas administrativas, accesos externos ni operaciones privilegiadas.
Implementación validada únicamente con pruebas simuladas; no se ha ejecutado
una auditoría real del anfitrión en esta fase.

## Uso disponible, no ejecutado durante el desarrollo

Desde el proyecto, sin sudo:

```sh
/usr/bin/python3 -B cli.py auditoria-basica
/usr/bin/python3 -B cli.py --formato json auditoria-basica
/usr/bin/python3 -B cli.py auditoria-basica --excluir red --excluir mantenimiento
```

Códigos del nuevo comando: 0 cobertura completa dentro del alcance declarado,
3 parcial, 130 cancelación; errores de entrada se mantienen en la CLI existente.
Completo no significa sistema seguro, sin anomalías o completamente actualizado.
JSON devuelve la traza íntegra validada, no una interpretación del modelo.

La frase conversacional «Realiza una auditoría básica del sistema» y las formas
breves «auditoría básica»/«haz una auditoría básica» usan el mismo coordinador,
antes de consultar LM Studio. Devuelven informe factual y traza en memoria;
la continuación explicativa autorizada posteriormente se describe al final.
La selección de esta intención acepta también un sufijo de presentación como
«y explícame los problemas encontrados, ordenados por prioridad». Una pregunta
conceptual, negación o petición con otros modificadores no se fuerza a esta ruta. Las exclusiones
explícitas se admiten mediante CLI y API Python; no hay parser natural de
exclusiones. Las consultas conversacionales anteriores conservan su ruta habitual.
No se ha expuesto una herramienta administrativa ni un nuevo permiso al modelo.

API Python: `auditoria_basica.auditar(exclusiones=...)`, `Coordinador.ejecutar()` e
`informe(traza)`. Las dependencias y el reloj son inyectables para pruebas.
El backend local rechaza root; la CLI mantiene su rechazo previo de ejecución root.
El objetivo solo se ejecuta una vez por instancia del coordinador.

## Cobertura y decisiones efectivas

Siete áreas en orden fijo: identidad, disco, memoria, servicios, red,
inventario/seguridad y planificación. Cada área registra capacidad y resultado,
una exclusión o el motivo de no completarse. Solo Debian 13/Fedora soportados;
un entorno no soportado produce informe limitado sin ejecutar adaptadores.
Las capacidades son observaciones informativas, nunca garantías de adquisición.
Se conserva la distinción entre entorno observado y anfitrión físico desconocido.

Se reutilizan:

- `motor_auditoria`: capturas acotadas y adquisiciones de seguridad existentes.
- Normalizadores de `memoria`, `servicios` e `interfaces_red`; no se interpreta
  texto libre del modelo como evidencia.
- `mantenimiento.consultar`: candidatas y resolvedor. Recibe plazo restante,
  inventario previo compatible y observador de etapas compuestas.
- Adaptadores Debian/Fedora: reutilización del inventario del objetivo; si el
  inventario falla, no se repite automáticamente a través de la planificación.
- `diagnostico_mantenimiento.diagnosticar(plan=...)`: mismo plan y plazo global;
  comprobación del helper de lectura con espera acotada, sin cliente administrativo.
- `correlacion_seguridad.consultar`: reutiliza auditoría Fedora y fuerza acceso
  externo falso, incluso si otras rutas conversacionales tienen permiso VPN.

La lectura numérica de espacio usa stat/statvfs de `/`, `/usr`, `/var` y `/tmp`,
deduplicados por dispositivo de filesystem, junto a la consulta de disco existente.
No se deduce espacio cero de porcentajes redondeados. No se busca ni borra archivos.

Tras las siete áreas puede quedar una llamada de investigación:

- INV-APT-01: plan Debian completo con actualizaciones sin instalaciones ni
  eliminaciones, sin adquisición de seguridad fallida: diagnóstico de preparación.
  INV-DISCO-01 comparte esa consulta cuando hay falta de espacio; no abre otra
  adquisición ni autoriza reparaciones.
- INV-FED-01: avisos Fedora con identificadores y paquetes: correlación local.
- INV-SVC-01 e INV-RED-01: se registran necesidades concretas; las herramientas
  específicas de estado de unidad y rutas/enlace siguen sin implementarse.

Las prioridades PRI-01 a PRI-05 se calculan en Python con referencias JSON Pointer
a evidencias: impedimentos APT, servicios/espacio/avisos pendientes, actualizaciones
previstas, cobertura desconocida y observaciones informativas. El informe no
atribuye explotabilidad a un aviso ni inferencias de presión sostenida a la swap.
La regla de prioridad nunca concede permiso para ejecutar nada.

## Contratos y memoria

`contratos_autonomia.py` valida los siete tipos aprobados: objetivo, capacidad,
evidencia, decisión, hallazgo, actuación y cierre. Campos cerrados, versión y tipos
exactos, UTC, presupuestos máximos, permisos locales fijos, hash de payload y
referencias del mismo objetivo. Rechaza referencias inexistentes, evidencia
truncada como soporte de decisiones, actuaciones sin decisión permitida, reglas
no autorizadas, operaciones repetidas y cambios de objetivo o límites.

Las evidencias usan el contrato cerrado `observacion_autonomia_v1` (versión 1):
`estado`, `resultado` y `subconsultas`. El resultado conserva datos de los
normalizadores y motores nativos. El plan de mantenimiento conserva su propio
validador y huella, sin duplicar el contrato APT. Las subconsultas de captura,
fuentes nativas y etapas de mantenimiento incluyen estado y duración; el registro
no es una traza de syscalls ni un profiler de todos los pasos internos del gestor.

El coordinador devuelve copias de la traza validada. No persiste SQLite ni altera
el diario administrativo protegido. Límite de traza 4 MiB, con reserva para cierre,
64 evidencias y 128 decisiones/actuaciones. Un exceso no publica el payload como
evidencia completa; produce cierre parcial con motivo. Las interpretaciones del
modelo no entran en la traza factual.

## Presupuestos

Un deadline monotónico de 120 s; hasta ocho intentos y cuatro por tanda, sin
presupuesto nuevo para ampliaciones. El número de rondas deterministas se obtiene
de tandas de cuatro y nunca supera el máximo de cuatro; ocho llamadas caben en
dos tandas. La CLI no solicita inferencias al modelo; la continuación conversacional
posterior comparte el mismo deadline y no dispone de herramientas.

Se conserva la captura de comandos de 65536 bytes y el límite nativo de 30 s por
trabajador de mantenimiento; cada uno recibe el mínimo con el plazo restante.
Las operaciones compuestas registran subconsultas y no reinician el deadline.
La proyección resumida de cada resultado conserva 18000 caracteres por salida y
60000 acumulados; la traza íntegra es un artefacto separado de hasta 4 MiB, no un
mensaje truncado presentado como contrato válido. El informe textual se limita
a 18000 caracteres e indica si se abrevia; JSON conserva la traza validada.

Los plazos son cooperativos para código Python y lecturas del filesystem. Un
bloqueo del kernel en I/O de disco no puede garantizarse interrumpible por este
coordinador. Los procesos de lectura mantienen su terminación acotada existente;
no se ejecutan transacciones privilegiadas ni se altera cómo deben finalizar.

## Límites pendientes

- Sin integración de solicitudes administrativas, delegación, temporizadores,
  persistencia general, red ni fuentes oficiales nuevas.
- Correlación CVE Debian no implementada. Fedora conserva las limitaciones de sus
  metadatos y formatos DNF; DNF5 no se anuncia como simulación verificable.
- Siete áreas más una ampliación no garantizan investigación exhaustiva. El tiempo
  puede agotarse antes: se informa cobertura parcial y pendientes.
- No se han validado adquisiciones reales Debian/Fedora ni LM Studio real en esta
  fase. El cambio conversacional solo reconoce la intención básica documentada;
  no incorpora planificación libre del modelo. La explicación posterior autorizada
  está validada de forma simulada y no concede autoridad al modelo.
- No se ha instalado ni modificado el helper; todas sus protecciones siguen vigentes.

## Validación

```sh
PYTHONPATH=.:tests /usr/bin/python3 -B -W error::ResourceWarning -m unittest test_auditoria_basica -v
/usr/bin/python3 -B -W error::ResourceWarning tests/ejecutar_regresion_motor.py
PYTHONPATH=.:tests /usr/bin/python3 -B -W error::ResourceWarning -m unittest test_despliegue_helper_apt -q
```

Las pruebas nuevas usan backend, reloj y fuentes simulados, y prohíben procesos
reales en las rutas del coordinador. Incluyen Debian/Fedora, capacidades ausentes,
exclusiones, prioridades con referencias, permisos, plan reutilizado, cancelación,
tiempo, registro excesivo, contratos corruptos, ausencia de repetición y uso de la
misma API desde CLI/conversación. Las pruebas previas de caracterización siguen
en el corredor una sola vez; la caracterización de intención se adapta a la ruta
nueva, conservando las restantes comprobaciones.

Respaldos previos de los archivos afectados en
`respaldos_locales/autonomia_fase2_20261108/`. No se ejecutó sudo, descargas,
instalaciones ni una auditoría real como parte de la validación.

Resultado final de esta implementación: **19 pruebas nuevas del coordinador y sus
adaptaciones superadas**, incluidas en **739 pruebas de regresión superadas**;
**12 pruebas del desplegador superadas** por separado. Importación aislada del
núcleo y la CLI comprobada sin cargar `AsistenteLocal` ni `lmstudio_http`, sin
invocar consultas. Los SHA-256 de los nueve módulos protegidos coinciden con los
anteriores a esta fase.


## Corrección de enrutamiento conversacional

La frase «Realiza una auditoría básica del sistema y explícame los problemas
encontrados, ordenados por prioridad.» no coincidía con el fullmatch original:
solo se admitía el objetivo sin sufijos. Por ello `preguntar()` continuaba hacia
`motor_consultas.planificar()`, que seleccionaba `auditoria_seguridad` en Debian.
El timeout posterior del modelo era un fallo distinto: no causaba el desvío.

Se amplía únicamente `es_objetivo_basico()` para admitir peticiones explícitas de
explicación, resumen o presentación de problemas/hallazgos/resultados y prioridad.
La ruta ya existente sigue ejecutándose antes del planificador de seguridad;
no se modifica su orden, ni se relaja la política de adquisición. Los sufijos
administrativos, negaciones y referencias históricas no activan esta ruta.
No es un clasificador semántico general; las formulaciones fuera de la gramática
conservan el enrutamiento anterior. Las exclusiones siguen disponibles por CLI/API.

En esa corrección de enrutamiento, el informe completo se obtenía del coordinador
y su presentador determinista, con prioridades y traza validada, sin solicitar
interpretación de LM Studio. La continuación autorizada después se detalla abajo. La petición
específica de seguridad conserva su consulta independiente, interpretación
opcional y fallback factual ante timeout, sin repetir la adquisición.

Validación exclusivamente simulada: frase exacta, equivalencia de cobertura y
operaciones con CLI, ocho adquisiciones únicas, permisos locales y límites
originales, separación de consultas específicas y timeout de interpretación.
No se repite la auditoría real. Respaldos previos en
`respaldos_locales/enrutamiento_basico_20261108/`.

Resultado de esta corrección: siete pruebas del módulo de caracterización
superadas (cuatro nuevas) y **750 pruebas de regresión superadas**. Comparación
AST contra el respaldo: en `auditoria_basica.py` solo cambia el reconocedor de
intención; coordinador, reglas, límites y presentación permanecen iguales.


## Continuación explicativa autorizada: implementación actual

Tras el informe factual, la interfaz conversacional solicita una explicación breve
una sola vez, siempre que quede presupuesto. La CLI mantiene su independencia.
La frase «Realiza una auditoría básica del sistema y explícame los problemas
encontrados, ordenados por prioridad» produce primero los hechos y después,
si la respuesta es válida, un bloque `Interpretación del modelo — no verificada`.

`AsistenteLocal.preguntar()` crea un deadline monotónico de 120 s y lo pasa al
coordinador. El parámetro opcional `Coordinador(deadline=...)` únicamente reduce
su plazo interno: `min(inicio+120, deadline)`. No cambia contratos, políticas,
prioridades, llamadas o reglas de investigación. La continuación recibe ese
mismo deadline; el HTTP conserva `min(deadline, ahora+45)`. Si no queda tiempo,
se explica la omisión sin contactar al modelo ni reintentar.

`proyeccion_auditoria_basica.proyectar()` valida y copia la traza y selecciona
cobertura, prioridades, hallazgos y referencias, recuentos y estados de fuentes,
actuaciones, pendientes, desconocidos y limitaciones. No envía inventarios,
hostname, nombres de conexiones, interfaces personales, salidas brutas ni el
informe de terminal. No envía la pregunta libre del usuario: usa instrucciones
fijas y un JSON de datos. El resultado incluye `autoriza_actuaciones=false`.
La proyección es independiente de los contratos autonomia_v1 y no los modifica.

Máximo 18000 caracteres JSON; si es necesario se abrevian textos y se omiten
listas, indicándolo mediante `abreviada` y contadores por sección. No se corta
la serialización JSON. Los recuentos de prioridades y la cobertura se conservan;
la traza original permanece íntegra. Proyección y respuesta se ajustan al margen
restante de salida acumulada, sin ampliar los límites existentes.

`interpretar_auditoria_basica()` llama a `consultar_modelo()` con
`permitir_herramientas=False, omitir_tools=True`: no se envía catálogo y se usa
`tool_choice=none`. Solo acepta texto no vacío dentro del límite, una respuesta
válida según `validar_respuesta()` y `finish_reason=stop`. Rechaza tool_calls,
respuestas incompletas, inválidas o tardías. Nunca remite la respuesta al
planificador ni al despachador de herramientas. No llama a clientes administrativos.

Ante timeout, error HTTP/comunicación, respuesta inválida o cancelación se muestra
el motivo por categoría y se devuelve la traza original. No se repite el modelo
ni las adquisiciones. No se añade memoria conversacional ni persistencia. Las
consultas específicas de seguridad mantienen sus rutas y gestión de errores.

Límite pendiente: no puede garantizarse fidelidad semántica del texto libre. La
etiqueta de interpretación y las restricciones de ejecución impiden que ese texto
se convierta en evidencia, prioridad, decisión, autorización o actuación de Python.
No se ha contactado LM Studio ni ejecutado una auditoría real en esta tarea.

Pruebas de esta continuación:

```sh
PYTHONPATH=.:tests /usr/bin/python3 -B -W error::ResourceWarning -m unittest test_interpretacion_auditoria_basica -v
/usr/bin/python3 -B -W error::ResourceWarning tests/ejecutar_regresion_motor.py
```

Respaldos previos en `respaldos_locales/interpretacion_basica_20261108/`.

Resultado final: **759 pruebas de regresión superadas**, incluidas nueve nuevas
de continuación explicativa; **12 pruebas del desplegador superadas** por separado.
La comparación AST confirma que las funciones de consultas específicas, cliente
HTTP y validación previas no cambian. No se modifican los nueve módulos protegidos.
