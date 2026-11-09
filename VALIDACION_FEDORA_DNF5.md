# Validación de Fedora y DNF5

Estado vigente del 9 de noviembre: [cierre técnico Fedora](CIERRE_TECNICO_FEDORA.md).
La corrección del argumento incompatible está en fuentes; la comparación XDG
no elimina los cuatro avisos de alias. La actualización integrada sigue sin
validación completa y no se reclasifican resultados históricos.

La implementación inicial del preparador estricto se conserva en
[IMPLEMENTACION_DNF5.md](IMPLEMENTACION_DNF5.md) como referencia histórica.
Ese preparador mantiene la ejecución bloqueada; la ruta interactiva separada
es experimental y sigue sin validación integral. El resto de este documento conserva el
diagnóstico y los procedimientos de las revisiones anteriores; las referencias
a la ausencia total de backend de preparación describen ese estado anterior.

## Consultas quiet: cambio y validación pendiente

La prueba comunicada desde Fedora 45 obtuvo stderr informativo con
`dnf --cacheonly check-update`; con `dnf -q --cacheonly check-update` obtuvo
stderr vacío y código 100. Es evidencia favorable a quiet, pero no sustituye
la validación de los subcomandos que realmente usa el proyecto:

| Consulta | Antes | Ahora |
| --- | --- | --- |
| Candidatas de mantenimiento | `/usr/bin/dnf5 --cacheonly --no-plugins repoquery --upgrades --qf <formato>` | Mismos argumentos, con `-q` inmediatamente después del ejecutable |
| Avisos pendientes/instalados | `dnf --cacheonly --no-plugins --setopt=logdir=/proc/self/fd updateinfo list --security --json --available/--installed` | Mismos argumentos, con `-q` inmediatamente después del ejecutable |
| Detalle para correlación | `dnf5 --cacheonly --no-plugins --setopt=logdir=/proc/self/fd advisory info --security --available --json` | Mismos argumentos, con `-q` inmediatamente después del ejecutable |

`<formato>` es el argumento literal `%{name}\t%{arch}\t%{evr}`. La opción
también se usa en la consulta de avisos a través del alias `dnf` de Fedora.
La consulta de mantenimiento DNF4 y los sondeos `--version` no cambian.
`adaptadores/fedora.py` delega los comandos en el worker: se revisó, sin requerir
otro cambio. Su simulación DNF5 sigue devolviendo `no_verificable` sin lanzar
un comando. El antiguo modo `dnf5-simular` del catálogo no se invoca ni se amplía.

La [documentación general DNF5](https://dnf5.readthedocs.io/en/stable/dnf5.8.html)
define `-q` como opción global válida para todos los comandos y destinada a
suprimir mensajes de estado en consultas no interactivas. En el
[código upstream revisado](https://github.com/rpm-software-management/dnf5/blob/main/dnf5/context.cpp),
la carga de repositorios usa `print_info`, condicionado por quiet;
`print_error` no está condicionado por quiet. Esto justifica evitar esos
mensajes en origen, sin eliminar stderr en Python ni cambiar configuraciones
de registro o repositorios. No garantiza que toda versión de DNF5 clasifique
correctamente todos sus avisos: queda pendiente comprobar los subcomandos en
el binario concreto de la VM. Cualquier stderr residual desconocido sigue
rechazándose, incluso si parece informativo; se conserva únicamente la
excepción exacta preexistente `AVISO_LOG_DNF` de seguridad.

El proyecto no ejecuta `check-update`/`check-upgrade`. El
[código 100 documentado para check-upgrade](https://dnf5.readthedocs.io/en/stable/commands/check-upgrade.8.html)
indica actualizaciones disponibles, y 0 indica ninguna. No se generaliza esa
excepción: `repoquery` y `advisory` siguen requiriendo código 0, y errores con
stderr vacío también se rechazan. No se incorpora un parser de `check-update`.

Validación local de esta revisión: Python 3.13.5, corredor completo **895
pruebas, 12 omitidas, sin fallos**, incluidas Debian 13. Las pruebas comprueban
los argumentos exactos y, con respuestas sintéticas, salida limpia, mensajes
informativos residuales, avisos desconocidos, errores con/sin stderr, códigos
0/1/100, y conservación de la simulación no verificable. Estas pruebas no
ejecutan DNF5 ni acreditan por sí solas su comportamiento quiet real.

Para trasladar **esta revisión incremental**, copiar conservando rutas:
`mantenimiento_worker.py`, `auditoria_seguridad.py`, `correlacion_seguridad.py`,
`tests/test_motor_independiente.py`, `tests/test_auditoria_seguridad.py`,
`tests/test_contratos_fedora.py` y este documento. Presupone que ya se trasladó
la revisión anterior, incluido `autonomia_herramientas.py`.

En la VM, desde el proyecto y como usuario normal:

```bash
python3 -B -W error::ResourceWarning tests/ejecutar_regresion_completa.py
python3 -B cli.py --formato json actualizaciones
python3 -B cli.py --formato json plan
python3 -B cli.py --formato json auditoria --herramienta auditoria_seguridad
python3 -B cli.py --formato json auditoria --herramienta correlacion_seguridad
```

Verificar candidatas completas si la caché y el inventario están disponibles;
simulación DNF5 no verificable y ejecución deshabilitada; fuentes de avisos
correctas y JSON interpretable. En correlación, inspeccionar
`diagnostico_detalle.stderr_bytes`, `motivo`, `codigo`, `truncado` y
`estado_adquisicion`. Puede persistir parcialidad por causas distintas del ruido
informativo. Registrar versión exacta de DNF5 y comparar los datos estructurados
con la lectura anterior; quiet no debe alterar paquetes, avisos ni CVE.
No atribuir un stderr vacío a ausencia de vulnerabilidades. No usar sudo,
refresco de caché ni comandos de transacción. Código 3 del CLI significa parcial.

La VM independiente Fedora 45 KDE con Python 3.15 y DNF5 ha confirmado,
según la validación comunicada, detección de distribución, inventario RPM,
candidatas de actualización y consultas factuales de identidad, disco,
memoria, red, servicios y kernel. Su regresión anterior obtuvo 883 pruebas,
14 omitidas y ningún fallo. Estos resultados no certifican la simulación ni
la ejecución administrativa Fedora. Las correcciones siguientes se prueban en
el proyecto Debian con datos sintéticos; requieren repetir la validación en la VM.
Se omiten los recuentos del inventario y candidatas reales por privacidad.

## Datos que consume el proyecto

* `adaptadores/fedora.py`: inventario RPM tabulado `NAME`, `ARCH`,
  `EPOCHNUM:VERSION-RELEASE`; candidatas de `repoquery --upgrades --qf`
  con nombre, arquitectura y EVR. Una candidata no es una acción resuelta:
  no acredita dependencias, instalaciones, eliminaciones ni retenciones.
* Simulación DNF4: JSON interno versión 1, resolvedor `dnf4` y acciones
  `actualizar`, `instalar`, `eliminar`, `reemplazado`, procedentes de la API
  nativa `resolve()`. Se contrastan con el inventario; no se llama a descarga
  ni a ejecución de transacciones. El JSON no es un formato de salida de DNF5.
* `auditoria_seguridad.py`: inventario RPM separado en nombre, epoch, versión,
  release y arquitectura. `updateinfo list --security --json` espera una lista
  de objetos con `type=security`, `name` y `nevra`; agrupa por aviso.
* `correlacion_seguridad.py`: `dnf5 advisory info --security --available --json`
  espera una lista con `Type`, `Name`, `references` (campos `Type` e `Id`)
  y `collections`, objeto cuyo `packages` opcional contiene NEVRA.
  No interpreta tablas humanas ni adivina otros esquemas. Una colección sin
  paquetes puede ser válida; un tipo incorrecto se rechaza.

Los esquemas JSON y la equivalencia de `updateinfo` con `advisory` están
documentados en https://dnf5.readthedocs.io/en/stable/commands/advisory.8.html.

## Fallos, controles y funciones pendientes

* **Función pendiente:** no existe un backend DNF5 validado de simulación en
  este proyecto. Se conserva `dnf5_transaccion_estructurada_no_disponible`,
  `simulacion=False` y `ejecucion=False`. Se elimina la llamada innecesaria a
  `upgrade --assumeno` en el adaptador: su texto ya se descartaba siempre.
  DNF5 documenta `upgrade --store=PATH`, pero almacenar una transacción tiene
  efectos y un formato que aquí no se han implementado ni validado.
  Referencia: https://dnf5.readthedocs.io/en/stable/commands/upgrade.8.html.
* **Control deliberado:** `avisos_no_verificados` rechaza stderr desconocido
  del transporte de mantenimiento. No demuestra que falte JSON ni permite
  ignorar globalmente mensajes de DNF. Sin stderr y código del sondeo de la
  VM no se puede determinar qué aviso lo produjo. No se modifica ese control.
  En seguridad solo se admite el aviso exacto `AVISO_LOG_DNF` ya existente;
  cualquier otro aviso sigue impidiendo verificar la fuente.
* **Defecto corregido:** un JSON correcto no basta para cerrar la correlación
  como completa si faltan inventario, avisos pendientes o comparación de las
  filas con `rpm.labelCompare`. El coordinador respeta ahora ese cierre parcial.
* **Defecto de diagnóstico corregido:** se conserva `detalle_dnf5` por
  compatibilidad y se añade `diagnostico_detalle`: código, bytes capturados,
  truncamiento y motivo acotado. Distingue aislamiento, dependencia ausente,
  error de comando, stderr desconocido, truncamiento, formato, tiempo y sistema.
  No incluye stdout ni stderr crudos. El límite compartido de captura sigue
  siendo 65.536 bytes: un detalle grande puede truncarse y no se acepta.
* **Defecto de representación corregido:** `total_resultados=None` cuando
  falla el detalle o el inventario es incompleto. `resultados=[]` en esos casos
  no significa cero vulnerabilidades. Un detalle válido sin coincidencias y
  un inventario completo sí permiten contar cero correlaciones dentro del
  alcance de la consulta, sin certificar seguridad.

## Significado de los avisos

`--available` consulta avisos con versiones posteriores de paquetes instalados;
`--installed` incluye versiones iguales o anteriores, sin probar historial ni
la presencia de todos los paquetes de un aviso. Un aviso puede referirse a
varios paquetes y arquitecturas: se cruza por nombre y arquitectura, nunca por
el número total de RPM o de actualizaciones.

La corrección pendiente solo se confirma si `rpm.labelCompare` indica que la
versión instalada es anterior y el mismo NEVRA correctivo figura en los avisos
pendientes del mismo identificador. Sin binding RPM no se sustituye la
comparación por orden lexicográfico: queda `no_determinado`. Las consultas son
secuenciales, sin instantánea transaccional. La caché no garantiza cobertura ni
frescura; cero coincidencias, corrección alcanzada o ausencia en KEV no prueban
ausencia de vulnerabilidades ni activación de un kernel actualizado.

La comparación de kernels de `auditoria_seguridad.py` sigue limitada al formato
estable Fedora 44. En Fedora 45 una consulta de kernel correcta puede coexistir
con `reinicio_pendiente_kernel=None`; no se amplía esa inferencia en este cambio.
KEV sigue desautorizado por defecto y no determina la vulnerabilidad local.

## Repetición en la VM, sin privilegios

Copiar desde el proyecto Debian estos archivos conservando rutas:
`adaptadores/fedora.py`, `correlacion_seguridad.py`, `autonomia_herramientas.py`,
`tests/test_contratos_fedora.py`, `tests/test_motor_independiente.py`,
`tests/test_auditoria_basica.py` y este documento. Conservar también la corrección
previa de `distribucion_linux.py`. No sustituir indiscriminadamente otros cambios
de la copia de Fedora.

Desde la raíz del proyecto, como usuario normal:

```bash
python3 -B -W error::ResourceWarning -m unittest discover -s tests -p test_contratos_fedora.py -v
python3 -B -W error::ResourceWarning tests/ejecutar_regresion_completa.py
python3 -B cli.py --formato json capacidades
python3 -B cli.py --formato json plan
python3 -B cli.py --formato json auditoria --herramienta auditoria_seguridad
python3 -B cli.py --formato json auditoria --herramienta correlacion_seguridad
python3 -B cli.py --formato json auditoria-basica
```

Las consultas nativas usan caché y aislamiento, sin refrescar repositorios,
transacciones, LM Studio ni ejecución administrativa. `plan` debe seguir siendo
parcial con simulación DNF5 no verificable. Código de salida 3 significa parcial.
Comprobar en correlación `diagnostico_detalle`, `estado_adquisicion`,
`inventario_completo`, `fuentes_locales` y los estados de cada fila. Si el motivo
es `formato_invalido`, será necesaria una muestra JSON de la versión concreta
de DNF5 para justificar otro parser; si es truncamiento, no afirmar lista vacía.
Si hay stderr desconocido, conservarlo localmente para revisión explícita,
sin relajarlo ni ejecutar `upgrade` manualmente para investigar.

No instalar dependencias para conseguir un cierre completo. No usar sudo,
refresh, download, store, replay ni otras operaciones de transacción durante
esta validación. La regresión tiene selección explícita y desactiva integraciones
reales; no sustituirla por descubrimiento general de prototipos.
