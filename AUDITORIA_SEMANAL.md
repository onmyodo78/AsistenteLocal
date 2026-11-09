# Auditoría semanal voluntaria y mantenimiento independiente

## Alcance y reutilización

`auditoria_semanal.py` llama a `auditoria_basica.auditar()`, valida su traza
`autonomia_v1` y genera el mismo informe factual de terminal. No hay un segundo
motor, llamadas a LM Studio, correlación CVE Debian nueva ni política administrativa
programada. Mantiene las siete áreas, ampliaciones, 120 segundos, cuatro rondas y
ocho llamadas existentes. Se adapta a Debian/Fedora según capacidades; Fedora
sigue pendiente de validación real. Los índices son locales y pueden estar obsoletos.

El mantenimiento independiente utiliza `mantenimiento_apt.py` como entrada al
circuito de `cli.py` y al helper ya existente; no es otro ejecutor privilegiado.

## Ejecución no interactiva

Desde la raíz del proyecto, como usuario normal:

```sh
/usr/bin/python3 -B cli.py --formato json auditoria-semanal \
  --directorio "$HOME/.local/state/asistentelocal/auditorias"
```

Este comando sí ejecuta una auditoría local de lectura, nunca una actualización.
No requiere que LM Studio esté abierto. Cada ejecución publica un directorio con
`traza.json` completa e `informe.txt` saneado. El JSON conserva referencias,
limitaciones y desconocidos; el resumen de salida indica estado y ubicación.
No se interpretan los hallazgos mediante IA.

El directorio final debe pertenecer al usuario y tener permisos 0700; los archivos
son 0600. Se rechazan enlaces en la ruta, ancestros sustituibles por otros usuarios y permisos excesivos; no se corrigen
permisos existentes automáticamente. No compartir estos informes ni subirlos a Git.
Para invocaciones concurrentes se mantiene un único inode `.auditoria.lock` con
`flock` no bloqueante: la segunda se omite, sin adquirir datos. Usar el mismo
directorio en todas las invocaciones; directorios distintos no comparten bloqueo.

Los archivos se escriben en un directorio privado de trabajo y se publican juntos
mediante rename. Un resultado parcial conserva la traza parcial válida, nunca se
promociona a completo. Código 0: completo; 3: parcial/cancelado/ejecución concurrente;
1: error. Un fallo previo a disponer de traza válida no produce un informe completo;
el error queda en la salida del proceso o journal. Tras una caída pueden quedar
carpetas `.en-curso-*`: revisarlas manualmente, no son informes publicados.
No hay reintentos de aplicación, borrado automático ni retención: controlar el
espacio y archivar/eliminar informes personalmente cuando proceda.

## Unidades systemd de usuario: desactivadas por defecto

No se incluye ningún servicio administrativo y no se instala ninguna unidad durante
el arranque. El comando siguiente **solo imprime** las dos unidades, sin auditoría:

```sh
/usr/bin/python3 -B cli.py unidades-auditoria-semanal \
  --directorio "$HOME/.local/state/asistentelocal/auditorias"
```

Para instalarlas voluntariamente, revisar antes las plantillas y ejecutar desde
la raíz del proyecto, sin sudo:

```sh
/usr/bin/python3 - <<'PY'
from pathlib import Path
from auditoria_semanal import unidades
raiz = Path.home()/'.config/systemd/user'
raiz.mkdir(parents=True, exist_ok=True)
for nombre, contenido in unidades(Path.home()/'.local/state/asistentelocal/auditorias').items():
    with (raiz/nombre).open('x', encoding='utf-8') as f:
        f.write(contenido)
PY
systemctl --user daemon-reload
systemctl --user cat asistentelocal-auditoria.service asistentelocal-auditoria.timer
```

La creación exclusiva `x` rechaza sobrescrituras. Si una unidad ya existe, revisar
ambas antes de sustituir nada. Las rutas apuntan al checkout actual: no moverlo sin
regenerar las unidades. Leer y modificar ese código concede control a quien ejecuta
la auditoría, **no** privilegios root. No colocar las unidades en `/etc/systemd/system`.

Solo después de revisarlas, activación opcional:

```sh
systemctl --user enable --now asistentelocal-auditoria.timer
systemctl --user list-timers asistentelocal-auditoria.timer
```

`OnCalendar=weekly`, demora aleatoria hasta 30 minutos y `Persistent=true`: puede
recuperar una ejecución vencida al iniciar el gestor de usuario. No activa linger:
no garantiza ejecución con la sesión cerrada ni con el equipo apagado. No hay
reinicio automático del servicio ante fallo; systemd tampoco solapa su propia
unidad oneshot. El bloqueo de archivo cubre invocaciones externas simultáneas.
La unidad limita privilegios y establece 150 segundos como límite exterior, sin
ampliar el presupuesto de auditoría de 120 segundos. La cancelación exterior por
systemd puede dejar un directorio temporal incompleto; no inicia mantenimiento.

Consulta y desactivación:

```sh
systemctl --user status asistentelocal-auditoria.service
journalctl --user -u asistentelocal-auditoria.service
systemctl --user disable --now asistentelocal-auditoria.timer
```

Desactivar el temporizador no cancela una auditoría ya iniciada. No se ha instalado,
activado ni probado una ejecución real mediante systemd en esta fase.

## Mantenimiento APT independiente, siempre interactivo

No necesita LM Studio, Codex ni un temporizador. Debian 13 exclusivamente, con las
mismas capacidades y restricciones de [EJECUCION_APT.md](EJECUCION_APT.md).

```sh
/usr/bin/python3 -B mantenimiento_apt.py diagnostico-mantenimiento
/usr/bin/python3 -B mantenimiento_apt.py --formato json plan
/usr/bin/python3 -B mantenimiento_apt.py plan-descarga-apt
/usr/bin/python3 -B mantenimiento_apt.py comprobar-ejecucion-apt
```

Los tres primeros no modifican paquetes ni refrescan índices. `comprobar-ejecucion-apt`
verifica el helper instalado sin sudo. El despliegue del helper y del diario protegido
requiere el procedimiento existente; copiar el proyecto no los instala.

En una terminal nativa, únicamente cuando se desee ejecutar la operación:

```sh
/usr/bin/python3 -B mantenimiento_apt.py descargar-apt
/usr/bin/python3 -B mantenimiento_apt.py actualizar-apt
/usr/bin/python3 -B mantenimiento_apt.py historial-apt
```

Estos comandos sí pueden iniciar operaciones administrativas: **no ejecutarlos como
prueba de instalación**. La entrada rechaza la ausencia de terminal antes de delegar.
El cliente usa `sudo -k --` sin `-S`: la contraseña va al terminal de sudo, nunca al
JSON ni al chat. El helper solicita después la frase exacta y su digest por `/dev/tty`.
Descarga e instalación tienen peticiones y autorizaciones distintas. No hay `--yes`,
plan por instrucciones libres, reutilización de contraseñas ni autorización por LLM.

La instalación permanece limitada a actualizaciones ya cacheadas: no añade paquetes,
no elimina, no degrada, no repara ni descarga implícitamente. El helper repite la
simulación bajo bloqueos, comprueba coincidencia, custodia e integridad de archivos,
registra fases/resultados en SQLite y verifica el estado final. Cambios del plan o
transacciones incompletas cancelan/bloquean; no se reintenta automáticamente.
El diagnóstico posterior de lectura puede ejecutarse de nuevo para obtener candidatas
restantes, sin reinterpretar un resultado desconocido como éxito.

Ante interrupción consultar el diario y el procedimiento administrativo de recuperación
de EJECUCION_APT.md antes de intentar otra operación. Este desarrollo no instala el
helper, no realiza descargas/actualizaciones y no valida una transacción real suya.

## Validación de desarrollo

Se ejecutan únicamente pruebas simuladas: doce casos nuevos y la regresión pública
completa (883 casos: 871 superados y 12 integraciones optativas omitidas). La
referencia de 786 pruebas sigue incluida sin duplicarla. Las pruebas existentes
del helper cubren autorización, revalidación, verificación, errores y diario SQLite.
Durante el desarrollo inicial no se ejecutaron auditorías reales ni inferencias; la validación posterior de lectura se documenta más abajo.
La programación efectiva, autenticación sudo y una transacción real del helper
requieren validación voluntaria posterior, separada de estas pruebas.

Validación posterior: auditoría manual, sintaxis de unidades y consulta autenticada
del historial realizadas en Debian 13; no se activó el temporizador ni se ejecutaron
transacciones. Véase [VALIDACION_INTEGRACION_DEBIAN.md](VALIDACION_INTEGRACION_DEBIAN.md).
