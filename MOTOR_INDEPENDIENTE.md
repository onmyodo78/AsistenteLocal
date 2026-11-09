# Motor independiente: auditoría y planificación

La ejecución APT añadida posteriormente se documenta en [EJECUCION_APT.md](EJECUCION_APT.md).
Los contratos de planificación siguen sin otorgar autorización para modificar paquetes.

Las fases 1 y 2 ofrecen adquisición e informes sin iniciar ni importar el cliente
conversacional. No contienen ejecución real, autorización administrativa,
refresco de metadatos, servicios ni instalación de dependencias.

## CLI

Desde el directorio del proyecto, con el Python del sistema y sin sudo:

```sh
python3 -B cli.py capacidades
python3 -B cli.py actualizaciones
python3 -B cli.py plan
python3 -B cli.py auditoria
python3 -B cli.py auditoria --herramienta correlacion_seguridad
python3 -B cli.py --formato json plan
```

`--formato` es una opción global y precede al subcomando. La CLI rechaza su
uso como root. No se puede seleccionar otra distribución mediante argumentos
ni pasar comandos, paquetes, opciones nativas, rutas o autorizaciones libres.

Códigos: 0 completo dentro del alcance declarado, 3 parcial, 1 error o capacidad
no disponible, 2 argumentos inválidos y 130 interrupción. Un error no desencadena
reintentos. `plan` representa una actualización completa propuesta por el gestor;
puede mostrar instalaciones y eliminaciones, pero no las ejecuta.

## Adaptadores y verificación

Se conserva `detectar_distribucion()`: Debian 13 y Fedora con versión numérica,
sin ampliar soporte mediante ID_LIKE. Las capacidades se comprueban aparte.
La presencia de una ruta permite intentar una consulta, no acredita éxito ni
acceso a todos los metadatos. El resultado de cada operación es independiente.

Debian reutiliza el inventario dpkg y las candidatas de `apt_pkg.Policy`; el
binding nativo opcional puede estar ausente sin impedir la auditoría dpkg.
La simulación ejecuta exclusivamente `apt-get --simulate dist-upgrade`, con
configuración fija de estado, cachés y locale, sin descargar ni instalar. La red
está bloqueada por seccomp. No se usa `--no-download`: combinado con simulación
impedía resolver cuando no estaban presentes los archivos de paquetes en caché.
`--simulate` y el aislamiento son las barreras que impiden cambios y conexiones.

El parser APT reconcilia Inst/Remv/Conf, versiones instaladas, arquitecturas,
recuento final y configuración completa. Las anotaciones de dependencias rotas
intermedias solo se admiten si corresponden a paquetes afectados y desaparecen
al finalizar. Los formatos no reconocidos, avisos, salida incompleta o discrepancias
producen `no_verificable`, sin inventar un plan vacío correcto. Los formatos de
versión admitidos inicialmente son APT 2 y 3 y la salida inglesa reconocida.

Fedora consulta RPM y `repoquery --upgrades` mediante el gestor detectado. No se
interpreta una tabla humana como lista de paquetes: se exige el formato fijo.
Se normalizan las versiones EVR con epoch cero explícito.

Para DNF4, si el binding nativo `dnf` está instalado en el intérprete, el trabajador
usa `Base` con caché local y plugins desactivados, `upgrade_all()` y `resolve()`.
No llama a descarga ni ejecución de transacciones. Las acciones admitidas se
reconcilian con el inventario RPM; acciones desconocidas o versiones ambiguas
invalidan la simulación. El binding es una dependencia opcional del gestor para
obtener la transacción estructurada; no se instala ni se añade una dependencia
pip. La falta de caché o una escritura necesaria fuera del temporal causa fallo.

Para DNF5, se hace un sondeo local mediante `--cacheonly --assumeno upgrade`,
si existe el gestor. No hay todavía un lector de transacciones estructuradas DNF5.
Ni su código de salida ni «Nothing to do» prueban una simulación válida: el estado
es siempre `no_verificable` y la capacidad de simulación verificable es falsa.
La presencia de DNF5 no habilita silenciosamente una simulación DNF4 con semántica
diferente. Las retenciones/exclusiones Fedora figuran como `no_comprobada`.
**La resolución DNF4 tiene pruebas simuladas; DNF5 y Fedora real quedan pendientes.**

Auditoría Fedora conserva los parsers actuales y su limitación del diagnóstico de
kernel a Fedora 44. Correlación Debian conserva `no_implementado`. KEV y otras
consultas externas se mantienen desactivadas.

## Contrato versión 1

`contratos_mantenimiento.py` valida el mismo esquema para Debian y Fedora:

- `distribucion`, `gestor`, `operacion`, `capacidades` y `estado`.
- `candidatas`: estado, paquetes con versión anterior/propuesta y errores cerrados.
- `simulacion`: estado, actualizaciones, instalaciones, eliminaciones, retenciones,
  estado de comprobación de retenciones y total no actualizado, cuando se conoce.
- `comparacion`: candidatas cuya versión propuesta no aparece en el plan del
  resolvedor. No equivale a una retención administrativa.
- `limitaciones`, `ejecucion_habilitada=false` y huella SHA-256 del documento.

Las filas y claves se ordenan para una representación determinista. La huella
valida contenido, no autoriza acciones ni acredita frescura. Las versiones previas
o propuestas desconocidas son null; no se sustituyen por cero. Una simulación
completa exige identidades y versiones suficientes para las acciones declaradas.
Un plan global completo exige tanto consulta de candidatas como simulación completas;
si una falla se conservan los resultados del otro componente.

`no_actualizados_total` no es un listado de retenciones. En Debian, la lista de
retenciones se limita a selecciones hold explícitas dpkg. Pinning, exclusiones,
despliegues graduales y decisiones del resolvedor no se convierten en holds.

El contrato es JSON serializable; esta fase no guarda automáticamente planes ni
crea bases SQLite. La persistencia de autorizaciones/ejecuciones corresponde a
la siguiente fase y no reutilizará los tokens del historial como autenticación.

## Seguridad y límites

El trabajador solo acepta identificadores de una lista blanca independiente.
No utiliza shell ni ejecutables proporcionados por el modelo. El entorno se
reconstruye, sin APT_CONFIG, PYTHONPATH ni variables de carga heredadas.

El único cambio al aislamiento existente es un parámetro opcional `temporal_fd`.
Sin él, auditorías conservan cero rutas escribibles y RLIMIT_FSIZE=0. Con él se
permite crear, escribir, truncar y eliminar archivos exclusivamente dentro de un
directorio nuevo 0700 bajo /tmp, creado por el supervisor y eliminado al terminar.
Se comprueba descriptor, propietario y permisos antes de instalar Landlock.
No se permiten sockets ni cambios de permisos, propietarios, metadatos de paquetes
o configuración. No se añade permiso para crear subdirectorios. El hijo no puede
obtener privilegios nuevos.

APT necesita temporales para leer/verificar índices locales: por ello, solo para
este trabajador, el tamaño máximo por archivo temporal es 64 MiB. No es una cuota
agregada del directorio. El aislamiento actual se limita a Linux x86_64 y Landlock
ABI suficiente; si falta, la consulta falla cerrada. CPU y memoria conservan los
límites del aislamiento original.

Se mantienen 120 segundos globales. El transporte nuevo permite hasta 30 segundos
por operación y 4 MiB de stdout+stderr, adecuados para la resolución y los listados
nativos. No cambia los límites de conversación, HTTP ni adquisiciones existentes.
La captura y limpieza comparten plazo. Son operaciones de lectura/simulación:
esta política de terminación no debe reutilizarse para futuras instalaciones.

## Validación reproducible

Regresión revisada sin adquisiciones reales ni LM Studio:

```sh
python3 -B -W error::ResourceWarning tests/ejecutar_regresion_motor.py
```

Pruebas locales optativas nuevas, sin red ni cambios de paquetes:

```sh
PYTHONPATH=tests ASISTENTE_MANTENIMIENTO_REAL=1 python3 -B -W error::ResourceWarning -m unittest test_motor_independiente_real -v
```

Comprueban importación sin módulos LM Studio, una simulación APT real bajo
restricciones y que dpkg/status e índices locales no cambian; verifican también
que scratch es escribible, el exterior no lo es y los sockets se deniegan.
No activan `ASISTENTE_PRUEBAS_REALES=1`, que habilitaría integraciones antiguas.
No usar descubrimiento general como sustituto de estas selecciones.

La prueba antigua de presentación genérica de interfaces se actualizó para
reconocer la separación factual/modelo ya implantada en la fase anterior.
No se cambió la lógica conversacional para satisfacer esa prueba.

### Resultado observado en aquella fase (histórico)

Regresión revisada: 637 pruebas superadas. Pruebas locales optativas nuevas:
4 superadas. Aislamiento antiguo de auditoría: 3 pruebas superadas, incluida
la denegación de escrituras, cambios de permisos, borrado y sockets.

La auditoría nativa Debian obtuvo inventario y la simulación APT local
produjo candidatas y actualizaciones previstas, sin instalaciones adicionales
ni eliminaciones. Los resultados pertenecen a los índices locales existentes;
no demuestran actualidad, instalabilidad futura ni cobertura CVE. No se detuvo
ni contactó LM Studio: se comprobó que la CLI funciona sin importar sus módulos.

Ejemplo abreviado del informe de planificación de esta prueba; se omiten los
recuentos reales del entorno por privacidad, sin inventar valores sustitutos:

```text
INFORME FACTUAL DE PYTHON — solo lectura
Distribución: debian13; gestor: apt; estado: completo
Actualizaciones candidatas: completo
Simulación del resolvedor: completo
Candidatas (no son una transacción; recuento omitido):
  ...
Actualizaciones previstas (recuento omitido):
  ...
Instalaciones adicionales (0 filas):
Eliminaciones previstas (0 filas):
Ejecución real: no implementada y no autorizada.
```

La salida JSON completa contiene las identidades y versiones verificadas de
cada fila, además de todos los estados, errores y limitaciones del contrato.

## Respaldo y siguiente fase (histórico)

Antes de editar se creó un respaldo persistente privado de los archivos
Python/Markdown con manifiesto SHA-256. Se omiten su ubicación y el recuento
de laboratorio. `.gitignore` tiene una copia previa adicional.
Los respaldos se excluyen de Git; no se modificaron los cambios previos del usuario.

Para ejecutar actualizaciones reales falta implementar autenticación, aprobación
del plan exacto, ejecutor administrativo temporal instalado en una ruta protegida,
revalidación bajo los bloqueos nativos y diario SQLite duradero. Antes de habilitarlo
hay que validar las transacciones de cada gestor en máquinas virtuales desechables,
incluido el soporte estructurado DNF5. No basta añadir un comando upgrade sin simulación.
