# Diagnóstico y preparación APT independientes de LM Studio

La evaluación es determinista, versión 1, y no concede autorización. Solo Debian
13; Fedora y la conversación conservan su funcionamiento. No se añaden paquetes
Python ni dependencias externas: se utiliza python3-apt del sistema.

## Comandos

Desde el proyecto, como usuario normal:

```sh
/usr/bin/python3 -B cli.py diagnostico-mantenimiento
/usr/bin/python3 -B cli.py --formato json diagnostico-mantenimiento
/usr/bin/python3 -B cli.py plan-descarga-apt
/usr/bin/python3 -B cli.py --formato json plan-descarga-apt
```

Estos comandos no requieren sudo ni acceden a red. El sondeo del helper existente
usa únicamente `comprobar`. El trabajador aplica el aislamiento de lectura sin red
ya existente. Se reutilizan el planificador, el parser de simulación y las
verificaciones de custodia del ejecutor; la segunda selección usa las marcas en
memoria de python3-apt, sin crear PackageManager ni invocar una transacción.

El JSON incluye el plan original y hechos separados: dpkg, selección nativa,
python3-apt, archivos, espacio, ejecutor, concurrencia, diario e índices. Los tamaños,
versiones y hashes esperados se distinguen de los observados en cada .deb. Un
archivo se verifica con tamaño, SHA-256, cabecera Package/Architecture/Version y
custodia root sin enlaces ni escritura de otros usuarios. Una coincidencia de
hash con otro nombre no acredita la ruta requerida en archives.

El informe contiene impedimentos, datos no comprobados, requisitos pendientes
para ejecutar, riesgos, limitaciones y una recomendación. Texto y JSON conservan
los mismos hechos; la CLI sanea caracteres de control al presentar texto.

## Estados y significado

| Estado | Criterio |
| --- | --- |
| NO_VERIFICABLE | Faltan comprobaciones críticas o no puede completarse la verificación previa a ejecutar. |
| BLOQUEADO | Hay incidencias dpkg, selección diferente, espacio insuficiente, actividad APT observada o archivos presentes inválidos. |
| PENDIENTE_DE_DESCARGA | Plan completo dentro del alcance, selección coincidente, dpkg limpio, espacio suficiente y sin actividad observada; faltan .deb. |
| APTO_PARA_PREPARAR | Archivos verificados pero helper aún no preparado; falta completar despliegue y diagnóstico. |
| APTO_PARA_EJECUCION_CONTROLADA | Todas las observaciones anteriores completas, archivos verificados, helper preparado, entorno protegido y ausencia verificable de operaciones en el diario. |

El orden da prioridad a impedimentos demostrados, después a comprobaciones críticas
incompletas. PENDIENTE_DE_DESCARGA no implica helper instalado ni diario comprobado:
se muestran como pendientes para ejecutar, y el helper volverá a comprobarlos antes
de descargar. En ningún estado se descarga o instala automáticamente.

El diario es privado de root. Un usuario sin acceso no puede acreditar ausencia de
operaciones pendientes; el informe lo expresa. Incluso tras una descarga correcta,
un diario inaccesible puede causar NO_VERIFICABLE al evaluar la ejecución. No se
relajan permisos ni se infiere éxito de su inaccesibilidad. Esta versión requiere
revisión administrativa de ese requisito; no añade un sondeo privilegiado automático.

## Observaciones y garantías

- `/proc/locks` se correlaciona por dispositivo/inodo con los cuatro locks APT/dpkg.
  También se observan nombres de procesos de gestores conocidos. Procesos efímeros,
  namespaces y permisos pueden limitar esa observación. Ni ausencia ni presencia de
  un archivo llamado lock prueban que el gestor esté libre.
- La exclusión la garantiza únicamente el helper al adquirir los bloqueos nativos;
  un conflicto cancela. No se borran locks, matan procesos ni reparan paquetes.
- Se comprueba espacio disponible para el usuario en `/`, `/usr`, `/var/lib/dpkg`,
  archives y `/tmp`. El umbral conservador es descarga pendiente + tamaño instalado
  de las versiones propuestas + 256 MiB. Se aplica a cada destino, incluso si
  comparten filesystem. Es una estimación de admisión, no un máximo demostrado de
  los scripts de paquetes. El helper comprueba de nuevo espacio para descargar.
- APT local aporta orígenes y marca trusted. No se revalidan firmas ni Release,
  expiración o sincronización de índices. `trusted=yes` puede influir en esa marca.
  El mtime máximo observado solo es un indicio de antigüedad. No hay consultas CVE.
- Los límites existentes del trabajador (salida 4 MiB, tiempo y aislamiento) siguen
  vigentes. Un fallo parcial se informa; no se repite automáticamente la consulta.

## Operación explícita de descarga

`descargar-apt` implementa una operación independiente, `apt_descargar_plan_v1`.
Su petición tiene nonce, UID, caducidad, política fija, huella del plan y manifiesto
con versiones, tamaños, SHA-256 y orígenes. No se acepta esa petición como una de
instalación, ni la frase de descarga como autorización para instalar.

El cliente exige helper protegido y usa la ruta fija existente con Python aislado
`-I -S -B`. Solo la invocación explícita de descargar-apt solicita autenticación
administrativa; el diagnóstico nunca lo hace. Dentro del helper se muestra todo el
manifiesto en `/dev/tty`, tamaño máximo y alcance, y se pide escribir:

```text
AUTORIZAR DESCARGA APT <digest de esta petición>
```

Después de autorizar, se registra el plan y el manifiesto en SQLite. Se adquieren los
bloqueos nativos, se comprueba dpkg, se repite simulación/candidatas y se compara la
transacción y el manifiesto completos. Si cambia algo se cancela antes de la red.
Se comprueba de nuevo la caducidad. Solo entonces se permite una llamada a Acquire.run
con los archivos de esa transacción y los repositorios ya configurados. No hay
apt update, cambio de repositorios, Cache.commit, do_install ni comandos del modelo.
El presupuesto de esta fase solo permite actualizaciones de paquetes existentes,
sin instalaciones adicionales, eliminaciones ni degradaciones.

Tras la adquisición se comprueban todos los archivos finales. No se corrigen
propietarios/permisos automáticamente: archivos dejados como _apt u otra custodia
no admitida provocan fallo cerrado. La instalación existente mantiene su propia
comprobación de los destinos exactos seleccionados por PackageManager.

Una descarga incompleta/interrumpida puede dejar archivos en partial y un estado
SQLite desconocido. No se reintenta ni se elimina el diario para continuar. Se
aplica la recuperación administrativa de EJECUCION_APT.md; en la primera prueba se
recomienda restaurar la instantánea en lugar de habilitar reparaciones automáticas.
El historial resumido existente no distingue todos los detalles: revisar política
JSON y eventos para identificar una descarga; un estado completo no prueba instalación.

## Primera descarga autorizada: procedimiento futuro, no ejecutado

1. Usar una VM Debian 13 desechable con consola e instantánea previa. Un administrador
   debe revisar e instalar el bundle protegido descrito en EJECUCION_APT.md, que ahora
   contiene **nueve archivos**, incluido archivos_apt.py. No ejecutar el checkout
   editable como root ni modificar sudoers/polkit. No instalar dependencias automáticamente.
2. Como usuario normal, ejecutar comprobar-ejecucion-apt y diagnostico-mantenimiento.
   Revisar que el plan esté dentro del alcance y consultar plan-descarga-apt. Revisar
   versiones, repositorios, hashes y estimación. No refrescar índices por rutina;
   si están obsoletos, decidir y autorizar su renovación por separado.
3. Solo si se aprueba la adquisición de red y escritura de caché, ejecutar:

   ```sh
   /usr/bin/python3 -B cli.py descargar-apt
   ```

   Autenticar y escribir la frase exacta del helper. Este paso **sí puede descargar**,
   escribir archives/partial y el diario; no instala paquetes. La recomendación del
   diagnóstico nunca sustituye la frase. Mantener disponible la consola.
4. Consultar historial-apt y repetir diagnostico-mantenimiento. Revisar archivos
   verificados, resultados y diario. Ante error o resultado desconocido detenerse y
   seguir recuperación administrativa; no reenviar silenciosamente la petición.
5. Para instalar hay que iniciar actualizar-apt y autorizar un plan nuevo con la
   frase de instalación. No encadenar automáticamente descarga e instalación.

APT utiliza métodos y configuración administrativa existentes; hooks, redirects,
credenciales del gestor y comportamiento de Acquire requieren validación real en
la VM. La descarga mantiene bloqueos durante la operación y puede tardar. No se
promete atomicidad ni recuperación automática de fallos de alimentación.

## Ejemplo de lectura y validación (histórico)

La observación real de aquella fase se conserva en informes privados excluidos
de la publicación. Se omiten sus nombres, recuentos de paquetes y tamaños locales;
los registros originales no se modifican ni se sustituyen por datos ficticios.

Resultado: PENDIENTE_DE_DESCARGA; actualizaciones previstas, sin instalaciones,
eliminaciones ni retenciones; python3-apt 3.0.4; dpkg limpio; selección nativa coincidente;
ningún .deb verificado y descarga pendiente. No se observaron locks
ni procesos APT, sin garantía de exclusión. Helper no instalado y diario no accesible.
En aquel entorno la custodia de rutas del sistema no pasó la validación root;
se conserva el requisito y se muestra pendiente de ejecución.
No se debe trasladar ese resultado de custodia a una máquina diferente.

La cifra de espacio observado se omite por privacidad y era una observación
instantánea. La instantánea de dpkg/status y los nombres/tamaños/mtime
observados en índices y caché coincidieron antes y después del diagnóstico.
La comprobación no afirma vigencia futura ni ausencia de toda escritura ajena.

Pruebas reproducibles sin red ni transacciones reales:

```sh
PYTHONPATH=tests /usr/bin/python3 -B -W error::ResourceWarning -m unittest test_diagnostico_mantenimiento test_ejecucion_apt -q
/usr/bin/python3 -B -W error::ResourceWarning tests/ejecutar_regresion_motor.py
```

Las pruebas nuevas cubren estados y fallos parciales, comparación de planes,
metadatos y archivos, espacio, CLI, autorización separada, revalidación antes de red,
registro e interrupciones y Acquire simulado sin instalador. No acreditan una descarga
real, el cambio de propietarios de APT ni concurrencia efectiva en una transacción.
Se conserva el respaldo previo en almacenamiento privado, con manifiesto SHA-256
adjunto; se omite su ubicación de laboratorio. Durante aquella tarea no se ejecutó sudo, instalación del
helper, descarga, actualización APT ni cambio de configuración del sistema.

Resultado final: 23 pruebas nuevas; 79 en diagnóstico y ejecutor; 716 en la
regresión seleccionada, todas satisfactorias. `git diff --check` sin incidencias.
