# Autonomía operativa: arquitectura aprobada y fases pendientes

La arquitectura general y la definición detallada de fase 1 han sido aprobadas.
El coordinador de fase 2 está implementado y probado de forma simulada; véase
[AUDITORIA_BASICA_FASE2.md](AUDITORIA_BASICA_FASE2.md). La matriz que sigue
conserva el diagnóstico anterior a la implementación como antecedente histórico.
La definición detallada de la fase 1 figura en
[AUDITORIA_BASICA_FASE1.md](AUDITORIA_BASICA_FASE1.md), aprobada como referencia para la implementación. Esta revisión documenta el objetivo del proyecto y caracteriza el comportamiento
existente. No implementa un planificador, motor de políticas ni nuevas operaciones.
La autonomía puede combinar coordinación determinista y modelo local opcional;
ninguna respuesta del modelo es una autorización administrativa.

## Capacidades observadas en el código

| Capacidad | Estado | Evidencia y límites |
| --- | --- | --- |
| Detección Debian 13/Fedora y capacidades | Implementada | `distribucion_linux.detectar_distribucion()`, `mantenimiento.seleccionar()/consultar()`, adaptadores Debian/Fedora. Las capacidades se sondean; no equivalen a transacciones reales probadas. |
| Selección conversacional de herramientas locales | Implementada, acotada | `AsistenteLocal.TOOLS`, `herramientas_disponibles()`, `consultar_modelo()`, `preguntar()`: catálogo fijo, argumentos vacíos, cuatro rondas y ocho llamadas. |
| Adquisición explícita independiente del modelo | Parcial | `motor_consultas.planificar()` fuerza dos herramientas de seguridad Debian; no planifica una auditoría integral de recursos, servicios y red. |
| Ampliación de investigaciones | Parcial | `preguntar()` admite rondas sucesivas del modelo; no hay reglas generales de anomalía, evidencias requeridas o prioridades verificadas. Tras presentar auditoría estructurada se cierra la adquisición para interpretar. |
| Auditoría básica de extremo a extremo | Prevista | «Realiza una auditoría básica del sistema» no garantiza hoy cobertura de disco, memoria, servicios, red, mantenimiento y seguridad. |
| Datos e interpretación separados | Implementada | `mostrar_informe_factual()`, `mostrar_interpretacion()`, `informes_factuales.py`. El texto del modelo no adquiere categoría de hecho. |
| Reutilización factual de sesión | Parcial | `ContextoFactual` admite dos nombres, caducidad y tamaño limitado; no es un grafo general de evidencias ni almacén de planes APT. |
| Investigación externa | Parcial | `ALLOW_EXTERNAL=False` por defecto; `diagnostico_vpn` es una consulta externa concreta. No existe una herramienta general para investigar fuentes oficiales. Activar ese permiso actual no autoriza ampliar sus destinos. |
| Correlación de seguridad | Parcial | `backend_seguridad`, `correlacion_seguridad`: capacidades Fedora sujetas a evidencia disponible; correlación CVE Debian no implementada. No deducir vulnerabilidad por antigüedad. |
| Diagnóstico y planes de mantenimiento | Implementada en CLI | `cli.main()`, `diagnostico_mantenimiento.diagnosticar()/evaluar()/plan_descarga()`, `mantenimiento.consultar()`. No están registrados como herramientas LM Studio. |
| Autorización y ejecución administrativa | Implementada para APT, validación real pendiente | `autorizacion_apt`, `ejecutor_apt`, `ejecucion_apt`, `apt_ejecucion_nativa`: descarga e instalación separadas, confirmación TTY y revalidación. Fedora no dispone de ejecución de actualizaciones. |
| Registro de evidencias y decisiones | Parcial | Historial/sesiones existentes y SQLite administrativo en `registro_mantenimiento.Registro`. No existe una traza uniforme de objetivo, decisiones, permisos, investigaciones y resultados. |
| Políticas de automatización delegada | Prevista | No hay política general verificable de nivel 3 ni delegación administrativa de nivel 4. Los permisos actuales no se amplían por esta definición. |
| Programación periódica | Prevista | Sin timers systemd ni servicio de auditoría implementados en esta fase. |

«Implementada» describe el código; «probada» requiere evidencia separada. Las
pruebas simuladas no acreditan gestores reales, cobertura de vulnerabilidades,
compatibilidad con otros modelos ni ejecuciones administrativas reales.

## Arquitectura propuesta, reutilizando el código

1. **Objetivo y alcance.** Una solicitud de auditoría básica crea un objetivo local
   de nivel 1. Resolver distribución y capacidades sin consultar al modelo. El
   objetivo autoriza la investigación de lectura dentro de su alcance, sin pedir
   aprobación herramienta por herramienta. Una negación o exclusión explícita
   del usuario restringe el alcance.
2. **Coordinador.** Ampliar el coordinador existente para una secuencia acotada de
   observación, evidencia, hipótesis, comprobación adicional y cierre. Reutilizar
   `ejecutar_consulta()` y el motor independiente mediante adaptaciones pequeñas.
   El modelo puede sugerir un siguiente paso; Python valida su permiso y utilidad.
   Sin modelo, una secuencia determinista debe permitir completar la auditoría
   básica y presentar los datos disponibles.
3. **Políticas.** Separar la propuesta de acción de la decisión de permitirla.
   Cada operación debe tener identificador cerrado, nivel, precondiciones,
   alcance de datos, efectos, red, privilegios y límites de ejecución. Una regla
   desconocida se deniega. No implementar un intérprete de shell ni aceptar
   comandos libres. Mantener las autorizaciones y bloqueos del helper.
4. **Evidencia y decisiones.** Conservar contratos íntegros y referencias con
   fecha, origen, estado y limitaciones; ampliar con control el contexto actual.
   Registrar la herramienta propuesta, evidencia que la justifica, regla aplicada,
   resultado y motivo de parada. El texto explicativo del modelo sigue separado.
5. **Administración.** Solicitudes APT pendientes mediante fachada del motor
   existente; nunca invocar sudo como efecto de una llamada del modelo. La acción
   humana local y la confirmación del helper siguen siendo necesarias. No crear
   delegación ni privilegios persistentes. No duplicar el resolvedor ni el diario.
6. **Presentación.** Informe determinista: cobertura, hallazgos, prioridades
   justificadas, acciones realmente ejecutadas y pendientes. La interpretación
   opcional explica el informe, sin convertir hipótesis en hechos.

## Flujo propuesto para una auditoría básica

- Detectar capacidades; consultar disco, memoria, servicios fallidos y estado de
  red con herramientas locales disponibles. No activar `diagnostico_vpn` ni
  conexiones externas por el mero objetivo de auditoría.
- Consultar inventario, candidatas y simulación de mantenimiento mediante motores
  existentes; distinguir candidatas de acciones previstas y desconocidos. La
  ausencia de una dependencia o permiso produce cobertura parcial, no un cero.
- Ante una anomalía, seleccionar una comprobación adicional del catálogo solo si
  aporta evidencia nueva, cumple la política y cabe en el presupuesto. Por ejemplo,
  un servicio fallido justifica investigar su estado únicamente cuando exista una
  herramienta concreta permitida; no fingir que el catálogo ya la contiene.
- Correlacionar solo fuentes disponibles. En Debian, CVE no comprobadas mientras
  falte el backend correspondiente; una futura consulta oficial exigirá destinos,
  método, datos enviados y acceso externo expresamente autorizados.
- Derivar prioridades por reglas explícitas, con evidencia asociada: una incidencia
  dpkg o un plan divergente bloquean mantenimiento; un servicio fallido exige
  contexto de impacto; un puerto abierto no demuestra vulnerabilidad. No inventar
  umbrales ni justificar prioridades por la opinión del modelo.
- Cerrar al completar cobertura, agotar presupuesto, repetir una comprobación sin
  ganancia de información o faltar permiso/evidencia. Una consulta fallida no se
  repite automáticamente. No aumentar límites actuales sin justificación aprobada.

El cierre anticipado actual de auditoría estructurada debe revisarse antes de
permitir ampliaciones, conservando sus protecciones contra repeticiones. Los
plazos internos de mantenimiento deben coordinarse con el presupuesto global;
una transacción privilegiada no puede heredar el mecanismo de terminación de
consultas de lectura. La recomendación nunca autoriza descargar o instalar.

## Fases propuestas, todavía sin implementación

1. Aprobar alcance de «auditoría básica», reglas de selección, contratos de
   decisiones y política inicial de niveles 1/2; cerrar denegaciones por defecto.
2. Integrar observaciones y mantenimiento de lectura, contexto y ampliaciones
   acotadas; ofrecer el flujo determinista independiente del modelo.
3. Añadir justificación verificable de hallazgos y registro local mínimo de
   decisiones, con saneamiento, retención y límites de privacidad definidos.
4. Integrar solicitudes APT pendientes y comprobación posterior conservando TTY,
   separación de autorizaciones y estados inciertos. Sin operaciones reales al
   desarrollar o probar.
5. Proponer por separado investigación oficial externa, políticas de nivel 3,
   programación y cualquier delegación administrativa futura. Nada de ello queda
   autorizado por documentar los niveles de autonomía.

## Pruebas y criterios de aceptación

Las pruebas existentes `test_motor_consultas_fase1.py`, `test_ejecucion_apt.py` y
`test_diagnostico_mantenimiento.py` cubren partes de selección, evidencia,
autorización y fallos. Las pruebas de caracterización añadidas en
`tests/test_autonomia_actual.py` comprueban selección acotada, ampliación basada
en una respuesta simulada y rechazo de herramientas/argumentos no autorizados.
No certifican el futuro motor de políticas ni decisiones justificadas por reglas.

Tras aprobar el diseño, añadir pruebas funcionales de estos requisitos pendientes:

| Escenario | Criterio de aceptación propuesto |
| --- | --- |
| Objetivo general en Debian/Fedora y sin modelo | Cobertura determinista según capacidades, sin requerir órdenes individuales. |
| Anomalía local y comprobación adicional | Referencia a evidencia previa, regla permisiva y dato nuevo esperado; sin bucle. |
| Priorización | Cada prioridad enlaza hechos y regla; evidencia incompleta conserva incertidumbre. |
| Red sin permiso o dominio fuera de política | Denegación antes de abrir conexiones, incluso si el modelo insiste. |
| Tarea de nivel 3 sin política verificable | Sin ejecución; solicitar permiso o informar del requisito pendiente. |
| Solicitud sensible o autorización textual del modelo | Solo propuesta pendiente; ninguna escalada ni autorización implícita. |
| Negación, timeout, evidencia caducada y cambio del plan | Respetar alcance, no repetir, invalidar y cancelar de forma segura. |
| Resultado administrativo simulado | Verificar después; distinguir éxito, cancelación e incertidumbre y registrar. |

No se añaden pruebas vacías, omitidas ni de una política ficticia para aparentar
cobertura implementada. Los requisitos futuros se probarán contra su implementación.

## Validación de esta revisión documental

```sh
PYTHONPATH=.:tests /usr/bin/python3 -B -W error::ResourceWarning -m unittest test_autonomia_actual test_motor_consultas_fase1 -q
/usr/bin/python3 -B -W error::ResourceWarning tests/ejecutar_regresion_motor.py
```

Resultado: 22 pruebas de caracterización/consultas superadas (3 nuevas y 19
existentes); 717 pruebas de la regresión seleccionada superadas. Las nuevas
se ejecutaron mediante el primer comando, entonces fuera de la lista del corredor.
En la fase 1 se incorpora `test_autonomia_actual` una sola vez al corredor general;
los resultados de esa validación se registran en AUDITORIA_BASICA_FASE1.md.
Sin contactos reales con el modelo ni operaciones administrativas. Respaldo del
README previo en `respaldos_locales/autonomia_20261108/README.md`.
