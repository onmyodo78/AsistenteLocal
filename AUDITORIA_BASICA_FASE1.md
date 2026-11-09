# Fase 1: definición de auditoría básica autónoma y políticas iniciales

Estado: diseño detallado y contratos propuestos, pendientes de revisión. La
arquitectura general está aprobada; este documento no activa herramientas,
permisos, consultas externas ni un coordinador. Versión propuesta de política:
`auditoria_basica_local_v1`; contratos `autonomia_v1`, separados de los contratos
vigentes de mantenimiento. No se cambian las garantías del helper APT.

## 1. Alcance mínimo y adaptación

«Realiza una auditoría básica del sistema» define un objetivo de observación
local y permite investigaciones locales acotadas por esta política. No autoriza
red, descarga de paquetes, instalación, reparación ni cambios de configuración.
Un usuario puede excluir áreas; una exclusión prevalece sobre modelo y política.
Cada área termina en comprobada, parcial, no disponible, excluida o pendiente por
presupuesto. No se sustituye un fallo por un resultado vacío correcto.

Preflight: identificar Debian 13 o Fedora mediante `detectar_distribucion()`;
registrar intérprete, entorno observado, binarios y capacidad real por operación.
Las lecturas de metadatos de detección no abren procesos ni gastan llamadas de
herramienta; todo proceso/consulta posterior pertenece a una acción contabilizada.
No aceptar derivados por ID_LIKE. Distribución no soportada: informe limitado,
sin ejecutar adaptadores APT/DNF; no atribuir al anfitrión los datos de un sandbox.

| Orden | Área / operación lógica | Debian 13 | Fedora | Evidencia mínima y limitaciones |
| --- | --- | --- | --- | --- |
| 1 | Identidad / `sistema` | Kernel y arquitectura | Igual | Distribución detectada + kernel observado; no certifica estado de parches. |
| 2 | Almacenamiento / `disco` | Consulta fija existente | Igual | Sistemas de archivos visibles, capacidad, uso y disponibilidad; no verifica integridad del disco. |
| 3 | Memoria / `memoria` | Consulta existente | Igual | RAM disponible, swap y alcance puntual; no demuestra presión sostenida. |
| 4 | Servicios / `servicios_fallidos` | systemd si es accesible | Igual | Estado de unidades fallidas y éxito de la adquisición; ausencia de systemd no es cero fallos. |
| 5 | Red / `interfaces_red` | ip/nmcli según disponibilidad | Igual | Estados y contadores visibles, fuentes independientes; no comprueba Internet, radio, procesos ni puertos por sí sola. |
| 6 | Inventario y seguridad / `auditoria_seguridad` | Inventario dpkg y candidatas locales | RPM y avisos DNF locales según capacidad | Estado separado de inventario y avisos; Debian CVE no evaluadas; caché ausente no demuestra sistema seguro. |
| 7 | Mantenimiento / `plan_mantenimiento` (fachada futura de lectura) | `mantenimiento.consultar('plan')` | Mismo motor con adaptador Fedora | Candidatas frente a resolvedor, instalaciones, eliminaciones, retenciones y desconocidos; nunca ejecutar la transacción. |

Las siete acciones no son siete llamadas obligatorias: si falta capacidad o el
usuario excluye un área, se registra el motivo y se omite. El orden fija cobertura
estable y deja, como máximo, una llamada para investigación si todas se ejecutan.
Un hallazgo no fuerza a ejecutar herramientas adicionales inexistentes.
`plan_mantenimiento` aún no está en TOOLS: se propone reutilizar el motor, no
implementar su integración en esta fase. La auditoría básica no exige que el helper
esté instalado y no instala dependencias para completar cobertura.

No se repite adquisición dpkg/APT/DNF ya obtenida dentro del objetivo cuando un
contrato íntegro y compatible permita reutilizarla. La adaptación futura deberá
registrar subconsultas reales y sus tiempos; una fachada compuesta no obtiene
rondas, tiempo ni llamadas adicionales. La redundancia actual entre inventario
y planificación es una limitación a resolver al integrar, no una optimización ya
implementada. Si no es posible reutilizar sin cambiar motores, se explicará y se
respetará el plazo global, sin ocultar el coste.

## 2. Selección autónoma de ampliaciones

Reglas propuestas cerradas; se evalúan tras cada resultado estructurado. Cada
candidato requiere evidencia válida, operación disponible, permiso y presupuesto.
El modelo puede proponer un identificador del catálogo; no inventa reglas,
argumentos, paquetes, destinos ni permisos. Python decide aunque el modelo no
esté disponible. Una propuesta sin regla aplicable se rechaza y registra.

| Regla | Disparador verificable | Ampliación y ganancia esperada |
| --- | --- | --- |
| INV-APT-01 | Debian, plan completo con actualizaciones, sin instalaciones ni eliminaciones y sin fallo previo de adquisición | Proponer `diagnostico_mantenimiento_apt` de lectura mediante `diagnosticar(plan=plan_existente)`: dpkg, archivos, espacio, concurrencia y preparación. No descarga. Su ausencia actual del catálogo se registra como pendiente. |
| INV-FED-01 | Fedora, avisos locales pendientes con identidad verificable | `correlacion_seguridad` local si capacidad y presupuesto: relación verificable con avisos/CVE/versiones correctivas. Forzar acceso externo falso para esta política. Reutilizar fuentes previas cuando el contrato lo permita. |
| INV-RED-01 | Fuente de interfaces completa identifica una interfaz no loopback administrativamente activa y operativamente no disponible | Solo proponer inspección local de rutas/enlace si existe una herramienta cerrada que aporte evidencia distinta. Hoy no hay tal herramienta específica: registrar pendiente; no usar diagnostico_vpn ni generar comandos. |
| INV-SVC-01 | Adquisición completa identifica unidades fallidas | Proponer lectura específica de estado de unidad únicamente si existe un contrato validado para ella. Hoy pendiente; no pasar nombres libres a systemctl ni leer logs arbitrarios. |
| INV-DISCO-01 | Fuente completa identifica un filesystem relevante sin espacio disponible | Consultar evidencia de espacio del diagnóstico APT solo si también se cumplen INV-APT-01 y el plan se reutiliza. No iniciar búsqueda de archivos, limpieza ni reparación. |

Una memoria con swap ocupada, un puerto abierto o un nombre de paquete antiguo
no justifican por sí solos una investigación de vulnerabilidades. Un fallo de
consulta no habilita repetirla bajo otro nombre. La identidad de adquisición es
`operacion + argumentos canónicos + alcance + instantánea de origen`;
la misma adquisición no se repite en el objetivo, incluso tras timeout/error.

Seleccionar primero candidatos que puedan aclarar un impedimento verificado de
mantenimiento; después avisos pendientes verificables; después otras anomalías.
Empates: prioridad del hallazgo, orden de regla y nombre de operación. Si quedan
varios candidatos y solo una llamada, ejecutar uno y registrar los restantes como
pendientes por presupuesto. No presentar la cobertura parcial como exhaustiva.

## 3. Reglas de prioridad, distintas del permiso

Prioridad describe qué revisar primero; nunca concede autoridad ni prueba impacto
que no conste en la evidencia. Reglas propuestas sin umbrales porcentuales nuevos:

| Regla | Prioridad | Predicado y conclusión permitida |
| --- | --- | --- |
| PRI-01 | P1: impedimento comprobado | Diagnóstico con dpkg en incidencias, plan nativo divergente, archivo no verificado/corrupto, espacio insuficiente según criterio existente o actividad APT observada. Bloquea mantenimiento en este diagnóstico; no demuestra fallo general del sistema. |
| PRI-02 | P2: revisión necesaria | Unidad fallida identificada, filesystem relevante con disponibilidad cero o aviso de seguridad local pendiente con paquetes afectados identificados. Impacto funcional o vulnerabilidad efectiva no se infieren automáticamente. |
| PRI-03 | P3: mantenimiento pendiente | Resolvedor completo prevé actualizaciones sin evidencia de urgencia. Candidatas sin resolvedor completo se informan como candidatas, no transacción ejecutable. |
| PRI-04 | P3: comprobar cobertura | Fuente incompleta, inaccesible, contradictoria, caducada o no verificable. Es una carencia de evidencia, nunca ausencia de riesgo. Registrar alcance desconocido. |
| PRI-05 | Informativa | Adquisición completa sin incidencias dentro del alcance medido; no afirmar seguridad global ni ausencia de CVE. |

Para PRI-02 e INV-DISCO-01, filesystem relevante significa el que aloja `/`,
`/usr`, `/var` o `/tmp`, deduplicado por identidad de montaje. El criterio exige
bytes disponibles iguales a cero en una fuente numérica validada: no convertir
porcentajes redondeados de `df -h` en ese hecho. La normalización numérica de la
herramienta actual es un requisito de integración pendiente. PRI-01 reutiliza
exclusivamente la evaluación de espacio existente en el diagnóstico APT.

No se asigna P0/emergencia sin un criterio verificable adicional aprobado.
La antigüedad o gravedad de un aviso solo se cita cuando conste en su fuente;
un aviso pendiente no acredita explotabilidad. Una contradicción conserva ambas
referencias y baja verificabilidad, sin resolverla por votación del modelo.
Cada hallazgo incluye regla, referencias a campos concretos, razonamiento
producido por plantilla Python, limitaciones y siguiente paso permitido.

## 4. Política de permisos niveles 1 y 2

- Nivel 1: catálogo anterior, lectura local, sin sudo y sin red. La aceptación del
  objetivo autoriza el conjunto en su alcance, sin confirmación individual.
- Nivel 2 local: solo ampliaciones de la tabla, evidencia de disparador y datos
  esperados nuevos. Comparte los presupuestos y restricciones del nivel 1.
- Nivel 2 externo: denegado en `auditoria_basica_local_v1`. No hay conmutación
  automática, ni siquiera por insistencia del modelo o texto de un repositorio.
  El ALLOW_EXTERNAL global existente no amplía esta política. Una futura variante
  requerirá autorización explícita, proveedor/operación, destinos y métodos
  cerrados, datos permitidos a transmitir, caducidad y límites; no se diseña aquí
  un navegador libre ni se usa el permiso VPN para consultar CVE.
- Operación desconocida, schema inválido, exclusión del usuario, fuente ajena al
  objetivo o presupuesto agotado: denegar antes de ejecutar.
- Niveles 3 y 4 fuera del objetivo. Descarga APT requiere su autorización separada;
  tampoco es una consulta externa de nivel 2. Instalación/actualización/eliminación
  y cambios de configuración mantienen autorización específica y helper protegido.

Solo lectura significa no modificar paquetes, configuración ni cachés del sistema;
permite temporales y registros locales acotados como los motores actuales.
No se leen documentos personales, credenciales ni logs completos para esta auditoría.

## 5. Contratos Python propuestos: autonomia_v1

Representación: diccionarios JSON estrictos, versión entera 1, tipos exactos
(sin aceptar bool como int), campos adicionales rechazados. Validadores Python
futuros, sin dependencia externa; no están implementados por este documento.
Los payloads conservan sus contratos nativos; no se copia su lógica al coordinador.
Identificadores generados por Python, no aceptados como autoridad desde el modelo.
UTC para trazabilidad; reloj monotónico para duración y plazos.

| Registro | Campos obligatorios propuestos |
| --- | --- |
| Objetivo | version, tipo=`objetivo_auditoria`, id, creado_utc, alcance (enumerados de áreas), exclusiones, distribucion (contrato existente), politica_id, politica_version, permisos (nivel1_local, nivel2_local, externo=false), limites, estado, motivo_parada (nullable mientras activo). |
| Capacidad | version, tipo=`capacidad`, id, objetivo_id, operacion_id, estado (disponible/no_disponible/no_verificable), fuentes, motivo, observado_utc. Un binario presente no acredita la adquisición. |
| Evidencia | version, tipo=`evidencia`, id, objetivo_id, operacion_id, subconsulta_id (nullable), adquirido_utc, duracion_ms, estado (completo/parcial/error/no_disponible/no_verificable), contrato_origen, version_origen, datos (payload validado), sha256_payload, limitaciones, truncado, procedencia (local/cache_local). |
| Decision | version, tipo=`decision`, id, objetivo_id, secuencia, creado_utc, proponente (python/modelo), operacion_id, argumentos_validados, evidencias (referencias), regla_id, politica_id, resultado (permitida/denegada/omitida), motivo, ganancia_esperada, presupuesto_antes, presupuesto_despues. |
| Hallazgo | version, tipo=`hallazgo`, id, objetivo_id, regla_id, prioridad (P1/P2/P3/informativa), verificabilidad (comprobada/parcial/no_verificable), evidencias (referencias), conclusion_python, limitaciones, siguiente_paso (operacion_id nullable; nunca comandos). |
| Actuacion | version, tipo=`actuacion`, id, objetivo_id, decision_id, operacion_id, inicio_utc, duracion_ms, estado (completo/parcial/error/cancelado/no_verificable), evidencias_generadas, error_codigo (nullable), efectos (lectura_local), reintentada=false. Una decisión permitida sin actuación no demuestra ejecución. |
| Cierre | version, tipo=`cierre`, objetivo_id, terminado_utc, estado (completo/parcial/cancelado/error), motivo_parada, cobertura (estado por área y referencias), hallazgos, actuaciones, pendientes, presupuesto_final. |

Referencias a evidencias: `{ "evidencia_id": "e1", "campo": "/dpkg/estado" }`;
el campo es un JSON Pointer existente en el payload validado. Las referencias
no pueden salir del objetivo ni apuntar a texto del modelo. Hash SHA-256 sobre
JSON canónico de `contratos_mantenimiento.serializar(datos)`; prueba integridad,
no autenticidad ni privilegios. No aceptar referencias a payloads truncados para
conclusiones que requieran el contenido omitido.

Ejemplo propuesto de hallazgo (los identificadores son ilustrativos):

```json
{
  "version": 1,
  "tipo": "hallazgo",
  "id": "h1",
  "objetivo_id": "o1",
  "regla_id": "PRI-01",
  "prioridad": "P1",
  "verificabilidad": "comprobada",
  "evidencias": [{"evidencia_id": "e1", "campo": "/hechos/dpkg/estado"}],
  "conclusion_python": "dpkg presenta incidencias; no continuar el mantenimiento.",
  "limitaciones": ["No se ha intentado reparar el sistema."],
  "siguiente_paso": null
}
```

Invariantes: todas las referencias resuelven; actuación solo tras decisión
permitida; nueva adquisición nunca sobrescribe una evidencia ya referenciada;
una consulta de instantánea no renueva su antigüedad; un fallo invalida su uso
como estado actual. Para el objetivo activo solo usar adquisiciones dentro de
su plazo global; las instantáneas históricas se muestran como contexto, no como
comprobación nueva ni autorización. Una salida del modelo se guarda, si procede,
separada y etiquetada como interpretación, nunca dentro de datos/conclusion_python.

Almacenamiento previsto: registro por objetivo en memoria inicialmente; futura
persistencia sqlite3 estándar local del usuario, separada del diario root APT.
No crear ahora base ni tablas. No fingir que la traza propuesta ya es persistente.
Propuesta de límites para revisar: máximo 128 registros de decisión/actuación,
64 evidencias y 4 MiB serializados por objetivo. Al excederlos, cerrar parcial sin
borrar datos referenciados; no truncar en silencio. Persistencia futura con ruta
fija del usuario, directorio privado 0700, fichero 0600, rechazo de enlaces y
retención explícita a aprobar. El resumen al modelo conserva límites existentes.

Motivos de parada cerrados: `cobertura_completada`, `tiempo_agotado`,
`rondas_agotadas`, `llamadas_agotadas`, `salida_agotada`, `registro_agotado`,
`sin_ampliacion_permitida`, `capacidad_insuficiente`, `evidencia_insuficiente`,
`cancelacion_usuario`, `error_interno`. Cierre completo solo con todas las áreas
no excluidas comprobadas en su alcance; no_disponible significa cierre parcial.
Denegar una propuesta aislada no termina necesariamente otras lecturas permitidas.

## 6. Presupuestos: no se amplían

| Límite vigente | Aplicación propuesta al objetivo completo |
| --- | --- |
| MAX_SECONDS=120 | Un único deadline monotónico compartido por detección, herramientas y modelo; no reiniciar por subconsulta ni por ampliación. |
| MAX_MODEL_SECONDS=45 | Cada petición al modelo recibe min(45, tiempo restante). Si no cabe interpretación, presentar hechos sin ella. |
| MAX_ROUNDS=4 | Cuatro rondas de selección/adquisición como máximo; cierre posterior sin herramientas, como permite el bucle actual. No crear otro contador para Python. |
| MAX_CALLS_PER_RESPONSE=4 | Como máximo cuatro solicitudes por tanda, tanto de Python como del modelo. |
| MAX_CALLS=8 | Todo intento, incluso rechazado o fallido, consume llamada; sin presupuesto nuevo para el modo sin modelo. |
| MAX_OUTPUT=18000; MAX_TOTAL_OUTPUT=60000 | Mantener límites de salida por herramienta y acumulado; no enviar JSON cortado como contrato válido. |
| MAX_HTTP_BYTES=1 MiB; MAX_COMMAND_BYTES=65536 | Conservar límites del cliente conversacional; no confundirlos con los 4 MiB del transporte independiente de mantenimiento. |

Secuencia determinista orientativa: cuatro lecturas en primera tanda, tres en
segunda, una ampliación posible en tercera; cuarta queda disponible sin conceder
más llamadas. No es una reserva de tiempo garantizada. No llamar al modelo si su
coste impide completar lecturas deterministas pendientes; el informe factual puede
cerrarse sin interpretación. No prometer cubrir todas las áreas en 120 segundos.

En el motor actual, mantenimiento crea su plazo de 120 s, diagnosticar su plazo
interno de 90 s y el transporte acota cada trabajador a 30 s. **No basta con
llamarlos directamente**: la fase de integración deberá propagar el plazo restante
como mínimo de esos límites, sin elevarlos ni matar transacciones privilegiadas.
Los límites son por operación lógica de catálogo; sus subprocesos fijos no son
nuevas elecciones del modelo, pero se registran y comparten deadline y límites
nativos. Prohibido agrupar acciones arbitrarias para eludir las ocho llamadas.
El contexto actual (dos hechos, 6000 caracteres, 1800 segundos) no se amplía en
esta fase; los nuevos registros propuestos son una estructura futura separada.

## 7. Criterios de aceptación antes de integrar

1. Objetivo básico: siete áreas y omisiones explícitas, selección según capacidades
   Debian/Fedora y sin depender del modelo; sin implementar un backend nuevo.
2. Investigación: cada llamada adicional enlaza evidencia y regla; se ejecuta una
   vez, dentro de alcance y presupuesto, o queda pendiente con motivo verificable.
3. Prioridades: mismo conjunto de hechos produce mismas prioridades; referencias
   válidas, desconocidos preservados, ningún salto de aviso a vulnerabilidad efectiva.
4. Permisos: red denegada por defecto y para esta política incluso con permiso VPN
   global; ninguna operación APT administrativa, sudo, reparación o cambio automático.
5. Registro: validación estricta de los siete contratos y referencias; sin texto
   del modelo como hecho, datos sensibles innecesarios ni persistencia root nueva.
6. Presupuestos: pruebas de reloj/rondas/llamadas/salida y fachadas compuestas;
   tiempo agotado produce informe parcial, no reintento ni aumento de límites.
7. Modelo propone una acción inválida: denegación registrada sin invalidar hechos
   adquiridos. Cancelación humana impide nuevas adquisiciones.
8. La regresión actual pasa, incluyendo exactamente las tres caracterizaciones
   existentes. Estas caracterizaciones no demuestran el coordinador futuro.

## 8. Validación de esta fase

Único cambio ejecutable: inclusión de `test_autonomia_actual` una vez en
`tests/ejecutar_regresion_motor.py`. No se modifican ni duplican las tres pruebas,
ni se añaden validadores o tests de un coordinador inexistente. La batería sigue
sin descubrimiento general y mantiene los indicadores de pruebas reales apagados.

Comando:

```sh
/usr/bin/python3 -B -W error::ResourceWarning tests/ejecutar_regresion_motor.py
```

Resultado: **720 pruebas superadas**. Comprobación adicional de los identificadores
de la suite: las tres pruebas `test_autonomia_actual.AutonomiaActual.*` aparecen
exactamente una vez; el módulo aparece una sola vez en MODULOS. No se han creado
pruebas adicionales ni contactado LM Studio para esta validación.

Respaldos previos en `respaldos_locales/autonomia_fase1_20261108/`.
No se ejecutaron operaciones administrativas, descargas ni instalaciones.
