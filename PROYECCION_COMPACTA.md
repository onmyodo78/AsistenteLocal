# Proyección explicativa compacta aislada

Estado: integrada de forma opcional y probada con datos sintéticos; **desactivada por defecto**.
No realiza adquisiciones, solicitudes HTTP, autorizaciones ni actuaciones. No sustituye
la traza `autonomia_v1`, su informe factual ni el constructor explicativo predeterminado.

## API y contrato `explicacion_compacta_v1`

Módulo: `proyeccion_compacta_auditoria.py`. Solo depende de la biblioteca estándar,
`contratos_autonomia` y `contratos_mantenimiento`.

```python
from proyeccion_compacta_auditoria import (
    proyectar, validar, evaluar_presupuesto, resolver_alias, resolver_referencia,
)
compacta = proyectar(traza_validada)  # vuelve a validar la fuente
validar(compacta, traza_validada)
tamano = evaluar_presupuesto(compacta)  # metadatos; no autoriza un envío
```

`proyectar` no cambia su argumento. La salida es independiente de él y contiene
`formato="explicacion_compacta_v1"`, `version=1`. Cualquier cambio incompatible de
estructura, selección o significado requerirá otra versión. No se acepta una
proyección generada por el modelo como fuente de hechos.

| Campo | Contenido y asociaciones |
| --- | --- |
| `objetivo`, `huella_traza` | ID original y SHA-256 del JSON canónico de la traza validada completa. Vinculan esta representación a una fuente y orden concretos. |
| `distribucion` | ID, versión y estado comprobados. |
| `estado`, `motivo`, `alcance`, `exclusiones` | Valores originales del objetivo/cierre. |
| `cobertura` | Las siete áreas con estado, motivo y aliases de sus evidencias. |
| `prioridades` | Recuentos originales por P1/P2/P3/informativa, sin reclasificación. |
| `hallazgos` | P1/P2/P3 individuales: regla, prioridad, verificabilidad, conclusión íntegra, limitaciones, siguiente paso, alias del hallazgo y referencias. |
| `informativas` | Esos mismos campos comunes y `miembros`, cada uno con su alias de hallazgo y sus referencias propias. |
| `operaciones` | Por operación: diccionarios de evidencias y actuaciones, indexados por alias. No colapsa varias adquisiciones en una. |
| `operaciones.*.evidencias` | Estado, truncamiento de origen, procedencia, limitaciones y hechos seleccionados de cada evidencia. |
| `operaciones.*.actuaciones` | Decisión original, estado, evidencias generadas y código de error. |
| `efectos_comunes` | Lectura local y ausencia de reintento; invariantes exigidas también al validar la fuente. |
| `no_realizadas` | Decisiones denegadas/omitidas con motivo y referencias, capacidades no disponibles/no verificables y áreas excluidas/pendientes por presupuesto. Conserva sus diferentes categorías. |
| `desconocidos` | Por evidencia: rutas ausentes, valores null/estados desconocidos con sus rutas, adquisición parcial, fuente truncada o resultado no utilizable. |
| `limitaciones` | Tabla de textos exactos compartidos. Cada `lim` conserva índices **desde cero**, orden y multiplicidad de su asociación original. |
| `pendientes` | Lista íntegra del cierre, sin reinterpretar ni autorizar sus propuestas. |
| `omisiones` | `por_presupuesto=false`; `detalle_fuera_del_resumen` enumera las evidencias cuyo contenido nativo completo debe consultarse en la traza. |
| `autoriza_actuaciones` | Siempre `false`. Ningún campo de esta representación confiere permisos. |

Las claves abreviadas son: `h` hallazgo; `e` lista de evidencias; `refs` referencias;
`lim` índices de limitaciones; `d` decisión; `c` capacidad; `paso` siguiente paso.

### Agrupación y referencias

Se agrupan exclusivamente hallazgos informativos con igualdad exacta en regla,
prioridad, verificabilidad, conclusión, lista de limitaciones (incluidos orden y
repeticiones) y siguiente paso. Las referencias NO se mezclan: cada miembro conserva
las suyas. Dos textos parecidos no se consideran equivalentes. P1/P2/P3 nunca se
agrupan. Se mantienen tanto los recuentos de hallazgos como los miembros del grupo.

Aliases `E1`, `H1`, `A1`, `D1`, `C1`, etc.: ordinal desde uno de evidencia, hallazgo,
actuación, decisión y capacidad, respectivamente, según el orden de la traza validada.
Son locales al objetivo y a su huella; no son IDs globales. Python reconstruye la
correspondencia usando la **traza original**. No se envía otra tabla de UUID repetidos
ni se reemplazan cadenas arbitrarias dentro de conclusiones o motivos.

Una referencia es `["E3", "/resultado/ram/total_bytes"]`, con JSON Pointer relativo
a `evidencia.datos`. Se preservan los escapes `~0` y `~1`. `resolver_alias` y
`resolver_referencia` verifican antes el documento completo contra su fuente; rechazan
aliases desconocidos, referencias a otro tipo, otra traza y rutas inexistentes.
El resolver es una API **local Python**: puede devolver detalle nativo no seleccionado,
incluso la raíz si así se consulta. No debe conectarse al modelo ni reenviar su resultado
sin una política de selección propia. No confiere acceso a herramientas del sistema.

La huella detecta cambios de fuente; no es firma digital, autenticación ni autorización.
No sustituye la custodia de la traza. Para resolver aliases es imprescindible conservar
esa traza exacta; esta fase no incorpora persistencia.

### Hechos y desconocidos

Selección cerrada por operación:

- Distribución en cabecera; no se copia `uname -a`, que puede incluir hostname.
- Disco: montajes `/`, `/usr`, `/var`, `/tmp`, espacio disponible y total.
- Memoria: RAM total/disponible estimada, swap total/ocupada, estado de medición de actividad.
- Servicios: total de unidades; red: recuento de interfaces y estados de alcance/conectividad/radio.
- Seguridad: completitud del inventario, totales, estados y recuento de avisos.
- Plan: estados de candidatas/simulación/retenciones y recuentos separados de candidatas,
  actualizaciones previstas, instalaciones, eliminaciones y retenciones.
- Diagnóstico APT: evaluación, impedimentos, no comprobado, pendiente de ejecución y estados
  de dpkg, comprobación nativa, espacio, ejecutor, diario y concurrencia.
- Correlación: estado de detalle DNF5, total de resultados y estado de CISA KEV.

No se deducen nuevos hechos, prioridades o diagnósticos. Los recuentos proceden de
listas nativas completas; una lista parcial o retenciones no verificables produce
`null`, nunca un cero supuesto. Los campos ausentes, null, cero y false se distinguen.
Una rama null se conserva así; estructuras incompatibles y tipos incorrectos (incluido
booleano en un campo numérico) se rechazan. Un resultado de adquisición fallida no se
convierte en hecho. Se conservan sus estados y errores.

Las limitaciones del hallazgo, de la evidencia y de la raíz del resultado nativo quedan
asociadas a sus registros. Las listas de impedimentos, no comprobado y pendientes de
preparación permanecen dentro de la evidencia correspondiente.

### Alcance de la equivalencia y pérdidas declaradas

Se conserva íntegramente el significado de los campos seleccionados y las conclusiones
de Python; **no es una serialización reversible de toda la traza**. Inventarios,
paquetes/versiones individuales, detalles internos de subconsultas, nombres de interfaces,
servicios y dispositivos, hostname, tiempos y presupuestos internos, argumentos de
planificación y otros campos no seleccionados permanecen en la traza original. Tampoco
se promete transportar toda limitación anidada de cualquier contrato nativo futuro.
La lista `detalle_fuera_del_resumen` declara esta selección para cada evidencia; no significa
que su adquisición haya fallado. Los hallazgos y sus referencias no se eliminan por ello.

Una conclusión o limitación original puede contener texto identificativo: la selección
cerrada evita copiar inventarios indiscriminadamente, pero **no es un anonimizador**.
Los casos sintéticos incluyen marcadores que verifican que campos nativos ajenos a la
selección no se filtran. No puede prometerse ausencia de información personal en todo
texto factual futuro sin una política adicional revisada.

`validar(proyeccion, traza)` reconstruye la representación esperada directamente desde
`validar_traza(traza)` y compara JSON canónico, incluidos tipos, miembros, orden de
listas, referencias y asociaciones. No compara contra la proyección antigua. Rechaza
campos adicionales, prioridades alteradas, agrupaciones inconsistentes y cambios de fuente.
Es validación canónica deliberadamente estricta; no admite reordenaciones semánticamente
plausibles de listas. Verifica fidelidad a la fuente, no la veracidad del sistema ni la
exactitud futura de un texto generado por LM Studio.

## Tamaño: no hay recorte por presupuesto

`evaluar_presupuesto` devuelve bytes del JSON canónico ASCII de producción (UTF-8),
meta orientativa 6.000, referencia superior 18.000, flags de exceso y `recortada=false`.
No es un validador de relaciones ni una autorización de envío: debe precederle `validar`.
No modifica documentos ni límites de políticas. El constructor devuelve todo aunque
exceda ambas referencias. Una futura integración deberá omitir la interpretación y
explicar el exceso si no cabe, conservando el informe factual; no enviar ni recortar
silenciosamente. No se ha cambiado ningún límite del consumidor actual.

Comparación local reproducida sobre **la misma traza sintética para ambos constructores**:

| Escenario simulado | Actual (bytes) | Compacta (bytes) | Observación |
| --- | ---: | ---: | --- |
| Debian, siete áreas y ampliación | 7.494 | 5.392 | Siete informativas en un grupo, un P3. |
| Debian, 35 actualizaciones ficticias | 7.496 | 5.394 | No se transmite inventario por paquete en ninguna. |
| P1, dos P2 y P3 | 7.553 | 5.994 | Cuatro informativas; prioridades individuales. |
| Memoria parcial con rama null, dos capacidades ausentes | No construye | 5.098 | El constructor actual arroja AttributeError; se deja intacto. |
| Fedora simulado | 6.634 | 4.694 | No demuestra funcionamiento real de Fedora. |
| Cancelación antes de adquirir datos | 1.601 | 2.139 | No siempre es menor: preserva motivos/asociaciones adicionales. |
| Veinte limitaciones extensas | 12.593, abreviada | 25.978, íntegra | No son equivalentes en contenido: la actual abrevia textos. La compacta marca ambos excesos. |

Son bytes **de proyección**, sin prompts ni envoltorio HTTP; no reproducen la referencia
histórica de 9.450 bytes. UUID/fechas sintéticos conservan longitudes y las dos variantes
se calculan sobre cada misma fuente. No se han contado tokens ni medido rendimiento del
modelo. Menos bytes no garantizan una respuesta dentro de 45 segundos.

## Pruebas y reproducción local

```sh
python3 -B -m unittest discover -s tests -p test_proyeccion_compacta_auditoria.py
/usr/bin/python3 -B -W error::ResourceWarning tests/ejecutar_regresion_motor.py
```

Las trece pruebas específicas bloquean procesos y sockets reales y reutilizan fixtures
de herramientas simuladas. Cubren determinismo/no mutación, referencias tipadas y
cruzadas, otra fuente, integridad de origen, prioridades y cobertura alteradas, cambios
de tipos, agrupación estricta y miembros duplicados, textos largos/literales, limitaciones
con orden y repeticiones, null/ausente/cero, cancelación, plazos, fallos, exclusiones,
Fedora, recuentos del resolvedor, retenciones no verificables, escapes de JSON Pointer,
exceso de presupuesto y exclusión de datos nativos ajenos a la selección.

Las funciones `escenario` del módulo de pruebas generan las siete variantes de la tabla;
no usan herramientas reales. El corredor general registra el nuevo módulo una sola vez.
Regresión del módulo aislado: **772 pruebas superadas**, incluidas sus trece nuevas pruebas.

## Activación explícita y reversión

Desde el directorio del proyecto, estas opciones seleccionan el formato para el proceso
conversacional. Son instrucciones para una ejecución futura; no se han realizado
solicitudes reales durante la integración.

```sh
# Predeterminado: constructor existente, sin opción adicional.
python3 AsistenteLocal.py

# Activación explícita solo para este proceso.
ASISTENTE_PROYECCION_AUDITORIA=compacta python3 AsistenteLocal.py

# Reversión explícita solo para este proceso.
ASISTENTE_PROYECCION_AUDITORIA=actual python3 AsistenteLocal.py
```

Si se exportó la variable en una terminal, puede retirarse antes de arrancar de nuevo:

```sh
unset ASISTENTE_PROYECCION_AUDITORIA
python3 AsistenteLocal.py
```

Valores admitidos exactos: `actual` y `compacta`. Variable ausente equivale a `actual`.
Un valor vacío o desconocido omite la interpretación y conserva el informe factual;
no selecciona silenciosamente otro formato. No se modifica ninguna configuración
persistente. La opción afecta únicamente a `interpretar_auditoria_basica()`, no al
saludo ni a consultas específicas de seguridad. Se lee en ese único punto de consumo.

### Flujo integrado

1. El coordinador y la presentación inmediata del informe factual permanecen intactos.
2. Para `actual`, se utiliza el constructor y el mensaje de sistema anteriores.
3. Para `compacta`, se construye directamente desde la traza, se valida contra ella y
   se serializa el resultado validado. Solo se añade al mensaje de sistema una breve
   explicación del formato y de sus referencias; no cambia la autoridad de Python.
4. Se aplica el presupuesto existente: `min(MAX_OUTPUT, disponible // 2)`, con
   `disponible = MAX_TOTAL_OUTPUT - salida_del_coordinador - salida_factual`.
   El JSON canónico ASCII permite comparar bytes y caracteres sin ambigüedad.
   Los 6.000 bytes siguen siendo orientativos: superarlos no impide enviar si cabe
   dentro del presupuesto vigente. Ese presupuesto corresponde a la proyección,
   no a una garantía de tamaño o tokens de todo el envoltorio HTTP.
5. Si no cabe, se omite la interpretación y se explica el exceso sin recortar datos.
   Si falla la importación, construcción o validación compacta, no se realiza el envío
   ni se vuelve automáticamente al formato anterior. El informe factual permanece.
6. Se conserva una sola solicitud sin herramientas, con el mismo modelo, parámetros,
   timeout explicativo de hasta 90 segundos, recortado por el deadline monotónico
   compartido de 120 segundos. Las llamadas ordinarias mantienen 45 segundos. Las respuestas siguen
   pasando por las mismas comprobaciones de contenido, finalización y tool_calls.
   Los fallos no causan reintentos ni nuevas adquisiciones.

No hay doble solicitud ni punto nuevo de ejecución administrativa. La reversión
operativa consiste en desactivar la variable o usar `actual` al iniciar el proceso;
no requiere revertir código, cambiar contratos ni reconstruir la traza.

### Validación de la integración

A las trece pruebas del módulo se añaden seis pruebas de integración simulada en
`tests/test_interpretacion_auditoria_basica.py`: selección explícita y validación,
selección predeterminada/reversión sin reiniciar el proceso de pruebas, fallos de
construcción y validación, prioridades alteradas/opción desconocida, exceso de los
presupuestos compartido y máximo, y HTTP simulado por encima de la meta orientativa.
Se comprueban ausencia de fallback, conservación factual, ausencia de adquisiciones
adicionales y parámetros de generación intactos. El transporte real permanece bloqueado.
Regresión completa tras integrar: **778 pruebas superadas**, incluidas las quince
pruebas de continuación explicativa y las trece del constructor compacto.

El defecto independiente del constructor anterior ante `ram=null` no se corrige aquí.
No hay prueba real de latencia o calidad interpretativa con esta opción todavía.
El respaldo previo a integrar está en
`respaldos_locales/integracion_compacta_20261108_164227/`.

La actualización del límite explicativo se valida con ocho pruebas simuladas en
`tests/test_limite_interpretacion.py`, incorporadas una sola vez al corredor general.
No cambia la selección predeterminada del formato ni añade reintentos.

Regresión completa tras separar los plazos ordinario/explicativo: **786 pruebas
superadas**, incluidas las ocho nuevas pruebas de límites. Sin inferencias reales.
