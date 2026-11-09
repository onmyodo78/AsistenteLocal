# Ejecución APT autorizada en Debian 13

Esta fase implementa ejecución real, pero no la habilita instalando código en el
sistema. No se han ejecutado actualizaciones, descargas, sudo, cambios de permisos
del sistema ni modificaciones de sudoers/polkit/systemd durante el desarrollo.
Las pruebas de instalación usan objetos simulados; no prueban una actualización real.

## Alcance admitido

Solo Debian 13, APT y actualizaciones de paquetes ya instalados. Se rechazan planes
parciales, vacíos, retenciones afectadas, instalaciones adicionales, eliminaciones,
reinstalaciones, degradaciones y cualquier transacción nativa distinta del plan.
Fedora conserva su comportamiento anterior: no existe ejecución DNF en esta fase.

Solo se usan archivos ya cacheados bajo `/var/cache/apt/archives`. Cada archivo
utilizado debe corresponder al tamaño y SHA-256 de una candidata de un índice local
marcado como confiable por APT, con custodia root y sin escritura de grupo/otros.
La ruta de instalación no llama a Acquire.run(), Cache.commit(), apt update ni descargas.
La descarga explícita separada se documenta en DIAGNOSTICO_MANTENIMIENTO_APT.md.
Frescura de índices y verificación en línea de firmas no se añaden en esta fase.
Scripts de paquetes y hooks administrativos existentes pueden ejecutar código
privilegiado y reiniciar servicios: aprobar versiones no limita todos sus efectos.
La política de conffiles es fija: `--force-confdef` y `--force-confold`.
No se ordena un reinicio del equipo ni una reparación automática.

`python3-apt` del Python de sistema es necesario para la ejecución. Se reutiliza
para los bloqueos y para aplicar una única transacción marcada, sin abrir otra
resolución entre la última comprobación y la instalación. No se añade pip ni se
instala automáticamente esa dependencia. Las auditorías conservan sus requisitos
anteriores y su aislamiento sin escrituras.

## Componentes

- `cli.py`: conserva consultas y planes; añade comprobar-ejecucion-apt,
  actualizar-apt e historial-apt.
- `cliente_ejecucion_apt.py`: verifica la protección del helper antes de invocar
  una orden fija mediante `/usr/bin/sudo -k -- /usr/bin/python3 -I -S -B ...`.
- `autorizacion_apt.py`: contrato de petición versión 1, identidad, nonce,
  digest, política fija y vigencia de cinco minutos.
- `ejecutor_apt.py`: bootstrap protegido y autorización dentro del proceso
  administrativo. No ejecuta código del checkout editable.
- `ejecucion_apt.py`: coordina diario, bloqueos, revalidación, ejecución única y
  comprobación posterior. Es comprobable mediante dependencias simuladas.
- `apt_ejecucion_nativa.py`: adaptador de ejecución APT; no usa shell ni acepta
  opciones/comandos libres.
- `apt_simulacion.py`: parser puro compartido con el adaptador Debian existente.
- `registro_mantenimiento.py`: diario SQLite independiente del historial de usuario.

El contrato de planificación existente permanece de solo lectura:
`ejecucion_habilitada=false` no se cambia a true. La petición de ejecución es un
contrato distinto, que referencia el plan exacto. Una huella JSON no es autorización.
La disponibilidad del helper se consulta mediante comprobar-ejecucion-apt.

## Flujo de autorización y ejecución

1. La CLI produce un plan completo con el motor existente y lo muestra.
2. El cliente comprueba que helper y padres no son modificables por usuarios
   no administrativos. Se usa sudo normal, sin reglas nuevas ni contraseñas en stdin.
   `-k` impide reutilizar el timestamp de sudo para esa invocación; la autenticación
   efectiva depende de la política sudo ya instalada. No se crea NOPASSWD.
3. El helper exige `-I -S` antes de importar módulos de aplicación o incluso JSON.
   `-I` excluye PYTHONPATH, el directorio actual y el del script; `-S` impide ejecutar
   `.pth`, `sitecustomize` y `usercustomize`. Reconstruye sys.path con el directorio
   protegido y las rutas fijas de biblioteca estándar y dist-packages de Debian.
   Comprueba propiedad root, ausencia de escritura de grupo/otros y enlaces en
   esas rutas y en el código de apt/apt_pkg/apt_inst antes de importarlo.
   Verifica además su instalación, Debian 13, API nativa, UID del solicitante,
   integridad y vigencia de la petición. El entorno se reconstruye.
4. Muestra todas las actualizaciones concretas en `/dev/tty`. Solo acepta la frase
   completa `AUTORIZAR APT <digest de la petición>`, escrita en ese terminal.
   No admite --yes, confirmación por JSON ni credenciales del modelo.
5. Tras confirmar, abre el diario protegido y persiste el plan autorizado antes
   de modificar paquetes. No crea ese diario al rechazar la confirmación.
6. Adquiere los bloqueos nativos frontend/dpkg, índices y archivos APT. Un bloqueo
   ocupado cancela: no se borran archivos de bloqueo ni se fuerza su liberación.
   Antes de abrirlos, los cuatro locks existentes deben ser regulares, root,
   sin enlaces duros/simbólicos ni escritura de grupo/otros.
7. Comprueba `dpkg --audit`, el inventario y el estado roto de la caché. Repite la
   simulación nativa con el parser compartido. Compara exactamente todas las
   acciones, versiones, retenciones y totales de simulación, y las candidatas.
8. Marca una transacción con python3-apt y compara de nuevo sus acciones con las
   actualizaciones autorizadas. Valida tamaño y SHA-256 de cada destino exacto
   `AcquireItem.destfile` que utilizará PackageManager: otro archivo correcto en
   el almacén no acredita ese destino. Exige destinos directamente en archives,
   regulares, root, sin enlaces ni escritura de grupo/otros. Comprueba la vigencia.
9. Registra duraderamente `ejecutando`. Aplica una sola vez esa transacción con
   PackageManager/InstallArchives, sin descargar ni volver a resolver. La API APT
   cede el bloqueo interior a dpkg y mantiene el frontend durante esa fase.
10. Comprueba de nuevo el inventario completo y `dpkg --audit`. Solo confirma éxito
    si el instalador termina correctamente y el estado coincide exactamente.
    La muerte por señal del hijo instalador se detecta antes de interpretar su
    código de salida; nunca se convierte en código cero y resultado completo.

Ante `plan_modificado` o `candidatas_modificadas`, hay que obtener otro plan y
volver a autorizar. Cada identificador se consume una vez. Una operación pendiente,
incompleta o desconocida bloquea posteriores intentos hasta revisión administrativa.

No se aplica un timeout que mate dpkg. Durante la instalación se ignoran SIGINT y
SIGTERM en el ejecutor; el cliente tampoco mata al hijo ante Ctrl+C. Una caída,
SIGKILL, desconexión o corte eléctrico puede dejar una operación incierta: no hay
rollback automático. Después de empezar no debe interpretarse un error de
comunicación como prueba de que no se actualizó nada.

## Registro SQLite

Ruta fija: `/var/lib/asistentelocal/mantenimiento.sqlite3`, directorio 0700,
base 0600 y propietario root. Padres protegidos y sin enlaces simbólicos. SQLite
usa parámetros, claves foráneas, synchronous=FULL y journal_mode=DELETE.

Se guardan plan, política, identidad, digest, fechas, fases, resultado, errores y
hasta 64 KiB finales de salida nativa, claramente etiquetada como no interpretada.
No se guardan contraseñas. Estados incluyen autorizada, revalidando, preparada,
ejecutando, verificando, completo, cancelado, incompleto y resultado_desconocido.
Los errores de registro antes de instalar impiden iniciar dpkg. Si falla el registro
final se devuelve resultado_desconocido; el estado pendiente conservado impide
un reintento silencioso.

No se modifica el historial SQLite existente. `historial-apt` lee el diario
administrativo en modo de solo lectura y muestra las últimas 20 operaciones.
No hay comando de reparación, borrado de bloqueos, marcado manual de éxito ni
reintento automático. La reconciliación administrativa de operaciones pendientes
queda para una fase posterior; esta versión no las elimina para continuar.

## Comprobaciones seguras que no actualizan

Desde el proyecto:

```sh
python3 -B cli.py --help
python3 -B cli.py comprobar-ejecucion-apt
PYTHONPATH=tests python3 -B -W error::ResourceWarning -m unittest test_ejecucion_apt -v
python3 -B -W error::ResourceWarning tests/ejecutar_regresion_motor.py
```

Antes de instalar el helper, comprobar-ejecucion-apt devuelve código 1 y
`ejecutor_no_instalado`: es el estado esperado, no una solicitud de instalación.
La batería específica bloquea el instalador y los procesos del adaptador;
dos pruebas adicionales arrancan únicamente Python sin privilegios para comprobar
el rechazo de PYTHONPATH y del checkout.
el caso que comprueba InstallArchives también usa una caché simulada.
Los resultados de la revisión final figuran al final de este documento.
No activar integraciones reales para probar la ruta de actualización.

## Primera ejecución manual controlada — no ejecutada por el agente

Realizar primero en una VM Debian 13 desechable con instantánea recuperable,
consola disponible, alimentación estable y sin tareas APT simultáneas. Revisar
el código y el plan. Las pruebas simuladas no acreditan una instalación real.

1. Comprobar la dependencia ya instalada, sin instalar nada:

```sh
/usr/bin/python3 -I -S -B -c 'import sys; sys.path.append("/usr/lib/python3/dist-packages"); import apt, apt_pkg; print(apt_pkg.VERSION)'
```

2. **Despliegue inicial protegido, únicamente tras autorización administrativa.**
   Este procedimiento sustituye los antiguos comandos `install` desde el checkout.
   No ejecutarlo si existe `/usr/local/lib/asistentelocal`: no es un procedimiento
   de reemplazo ni de actualización del helper. No instala paquetes ni crea el diario.

### Aprobar los bytes desde la Konsole nativa (sin privilegios)

Desde el proyecto revisado, generar una sola vez el manifiesto. Comparar los nueve
SHA-256 con los valores previamente revisados en la terminal nativa. Si difieren,
**detenerse y revisar**, sin aprobar automáticamente los nuevos valores.
El desplegador también debe revisarse y aprobarse: no basta con proteger los módulos
si se ejecuta como root un instalador editable sin verificar.

```bash
cd /ruta/al/proyecto/AsistenteLocal
umask 077
manifest_apt="$(mktemp /tmp/asistentelocal-manifiesto.XXXXXXXX)"
/usr/bin/sha256sum ejecutor_apt.py ejecucion_apt.py apt_ejecucion_nativa.py autorizacion_apt.py registro_mantenimiento.py contratos_mantenimiento.py apt_simulacion.py distribucion_linux.py archivos_apt.py > "$manifest_apt"
/usr/bin/cat -- "$manifest_apt"
/usr/bin/sha256sum -- "$manifest_apt" despliegue_helper_apt.py
```

Anotar los dos últimos hashes en la terminal de confianza, después de revisar el
contenido y el desplegador. Introducir **esos valores aprobados**, no una sustitución
`$(sha256sum ...)` dentro del comando privilegiado. Estas variables fijan las
referencias antes de abrir/copiar las fuentes; cualquier cambio posterior se rechaza.
Mantener esta misma sesión de Bash:

```bash
read -r -p 'SHA-256 aprobado del manifiesto: ' manifest_apt_sha
read -r -p 'SHA-256 aprobado del desplegador revisado: ' deploy_apt_sha
readonly manifest_apt manifest_apt_sha deploy_apt_sha
project_apt="$PWD"
readonly project_apt
```

La confianza inicial es la revisión humana y los digests introducidos en esta
terminal. No se protege frente a una terminal ya comprometida ni frente a otro
administrador root hostil. El manifiesto de referencia contiene exactamente los
nueve nombres simples, sin rutas absolutas, duplicados ni módulos adicionales.

### Acción administrativa propuesta (no ejecutada por Codex)

El siguiente comando solicita root temporal mediante sudo, sin reglas sudoers nuevas.
El arranque aislado abre el desplegador sin seguir enlaces en ningún componente de
su ruta, lee una instantánea limitada, verifica su SHA-256 aprobado y ejecuta
**esos mismos bytes en memoria**, sin volver a importar/abrir el código editable.
No ejecutar directamente `sudo python3 despliegue_helper_apt.py`.

```bash
sudo /usr/bin/python3 -I -S -B -c '
import hashlib, os, re, stat, sys
ruta, aprobado = sys.argv[1:3]
if not ruta.startswith("/") or ".." in ruta.split("/") or not re.fullmatch("[0-9a-f]{64}", aprobado):
    raise SystemExit("Ruta o digest del desplegador inválidos")
fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
try:
    partes = ruta.split("/")[1:]
    for parte in partes[:-1]:
        nuevo = os.open(parte, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
        os.close(fd)
        fd = nuevo
    archivo = os.open(partes[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    with os.fdopen(archivo, "rb") as entrada:
        info = os.fstat(entrada.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o7002:
            raise SystemExit("Tipo, enlaces o permisos del desplegador inválidos")
        datos = entrada.read(1048577)
finally:
    os.close(fd)
if len(datos) > 1048576 or hashlib.sha256(datos).hexdigest() != aprobado:
    raise SystemExit("El desplegador no coincide con el aprobado; cancelado")
sys.argv = [ruta] + sys.argv[3:]
exec(compile(datos, ruta, "exec"), {"__name__": "__main__", "__file__": ruta})
' "$project_apt/despliegue_helper_apt.py" "$deploy_apt_sha" \
  --origen "$project_apt" --manifiesto "$manifest_apt" \
  --sha256-manifiesto "$manifest_apt_sha"
```

El desplegador exige root, Python aislado, padres `/`, `/usr`, `/usr/local` y
`/usr/local/lib` root:root 0755 y ausencia de destino (incluso enlaces rotos).
Crea `.asistentelocal-despliegue-*` root:root 0700 bajo `/usr/local/lib`, en el
mismo sistema de archivos que el destino. Captura el manifiesto contrastándolo
con su digest aprobado, guarda esa referencia dentro del área privada con 0600
y copia los nueve módulos mediante descriptores sin seguir enlaces. Rechaza
archivos ausentes, no regulares, con enlaces adicionales, bits especiales,
escritura para otros, cambios detectados durante la lectura o tamaño excesivo.
Las fuentes editables pueden tener permisos 0664; nunca se ejecutan durante la copia.

Verifica **los archivos ya copiados** contra el manifiesto privado: conjunto exacto,
SHA-256, propietario root:root, archivos 0644 y directorio 0755. Después sincroniza
y publica mediante `renameat2(RENAME_NOREPLACE)`: una única operación atómica,
sin sobrescribir un destino aparecido concurrentemente. Si esta capacidad Linux
no está disponible, falla sin usar una alternativa insegura. Repite la verificación
íntegra del destino y solo entonces imprime `PUBLICADO Y VERIFICADO` y sus hashes.
Ni el manifiesto ni el desplegador se incluyen en el directorio definitivo.

Un fallo antes de publicar deja el destino ausente; un destino creado por otro
proceso se conserva. Una interrupción abrupta puede dejar un área temporal privada:
no reutilizarla automáticamente. Un fallo después de publicar conserva el directorio
**completo**, informa de error y exige revisión administrativa; no declara éxito ni
lo elimina a ciegas. Un corte eléctrico requiere comprobar de nuevo el contenido,
no inferir éxito del registro de terminal. La atomicidad evita publicar un subconjunto
de módulos; no constituye una garantía frente a fallos físicos del almacenamiento.

### Verificación posterior, sin privilegios

Solo continuar si el comando anterior termina con código cero y la verificación
explícita de publicación. Los siguientes comandos no descargan ni instalan paquetes:

```bash
/usr/bin/stat -c '%U:%G %a %n' /usr/local/lib/asistentelocal /usr/local/lib/asistentelocal/*.py
/usr/bin/python3 -I -S -B /usr/local/lib/asistentelocal/ejecutor_apt.py comprobar
```

El segundo comando mantiene el arranque protegido existente y debe devolver
`estado: preparado`. No necesita wrapper, punto de entrada adicional, permisos
de ejecución en los `.py`, cambios de sudoers ni acceso al proyecto editable.
El despliegue no autoriza ninguna descarga ni instalación de paquetes. Conservar
la salida verificada y los digests aprobados para la revisión administrativa.

3. Volver como usuario normal y revisar capacidad y plan:

```sh
python3 -B cli.py comprobar-ejecucion-apt
python3 -B cli.py --formato json plan
```

Si faltan archivos cacheados, la ejecución cancelará con paquetes_no_cacheados.
La carga de caché exige una autorización distinta de la instalación: revisar primero
plan-descarga-apt y el procedimiento de descargar-apt. No se cambian repositorios
ni se refrescan índices automáticamente.
Si hay instalaciones adicionales o eliminaciones, esta versión rechaza el plan.

4. **El siguiente comando sí puede modificar paquetes después de autenticar y
   confirmar. Es exclusivamente para esa prueba manual futura:**

```sh
python3 -B cli.py actualizar-apt
```

Leer las versiones mostradas por el helper, escribir la frase exacta solo si se
aprueba y esperar al resultado. No matar procesos ni forzar desbloqueos.

5. Consultar el resultado administrativo y realizar otra auditoría de lectura:

```sh
python3 -B cli.py historial-apt
python3 -B cli.py auditoria
```

Un resultado incompleto/desconocido exige inspección administrativa antes de
otra operación. No ejecutar reparaciones sugeridas por el modelo ni convertir
un registro pendiente en éxito por suposición. Recuperar la instantánea de la VM
es una decisión externa, no una acción automática de AsistenteLocal.

## Respaldo y límites pendientes

Respaldo persistente previo a esta fase:
`respaldos_locales/ejecucion-apt-20261108T002548Z.tar.gz`, 121 archivos y manifiesto
SHA-256. Fedora y el motor conversacional no se modifican funcionalmente.

Pendiente de validación real en VM: comportamiento de python3-apt durante una
transacción, hooks y scripts concretos, conffiles, reinicios de servicios y fallos
de alimentación. No se promete atomicidad, recuperación automática ni ausencia
de efectos fuera de los archivos del paquete. La descarga autorizada se añade en una fase posterior documentada por separado.
No se incluye expansión a nuevas dependencias/eliminaciones, ejecución DNF ni reconciliación automática.


## Recuperación administrativa ante operación incompleta

Procedimiento manual externo a AsistenteLocal; no se ejecuta automáticamente.

1. Detener nuevos intentos desde la aplicación. Conservar la consola de la VM.
   Comprobar procesos activos (`ps -ef`) y titulares de bloqueos con las herramientas
   administrativas ya disponibles. No borrar locks ni matar dpkg para desbloquear.
   Si siguen activos, esperar e investigar antes de tocar estado o recuperar discos.
2. Una vez detenidos los procesos, conservar una instantánea y una copia protegida
   del directorio `/var/lib/asistentelocal` completo (incluido cualquier journal
   SQLite), `/var/log/apt` y `/var/log/dpkg.log`. Mantener permisos administrativos;
   los registros y el plan contienen información del sistema.
3. Desde una sesión administrativa, inspeccionar el diario en modo lectura. Con
   `/usr/bin/python3` y su sqlite3 estándar abrir la URI
   `file:/var/lib/asistentelocal/mantenimiento.sqlite3?mode=ro`; consultar
   `SELECT id,estado,error,plan_json,resultado_json FROM operaciones ORDER BY inicio`
   y `SELECT operacion,fecha,estado,detalle_json FROM eventos ORDER BY id`.
   Si SQLite informa corrupción o journal pendiente, conservar primero la copia
   y tratarlo como incidencia administrativa, sin recrear ni borrar la base.
4. Ejecutar solo comprobaciones de lectura: `/usr/bin/dpkg --audit` y
   `/usr/bin/dpkg-query --show`. Comparar versiones e inventario con el plan
   guardado y revisar los logs APT/dpkg. La ausencia de errores en dpkg no basta
   para declarar completa la operación ni para cambiar el diario a éxito.
5. En la primera prueba desechable, recuperar la instantánea previa con la VM
   detenida es la vía de vuelta prevista. Si se decide reparar en lugar de restaurar,
   un administrador debe diagnosticar y autorizar por separado cada modificación;
   no se ofrece una receta automática `dpkg --configure -a`/`apt --fix-broken`.
   Pueden ejecutar scripts, instalar o eliminar paquetes ajenos al plan aprobado.
6. Esta versión **no reabre la ejecución tras una operación pendiente, incompleta
   o desconocida**: no editar estados ni borrar el diario para sortear el bloqueo.
   Una reparación administrativa no equivale a reconciliación implementada. Para
   repetir la prueba, restaurar íntegramente la instantánea previa o usar otra VM.

## Revisión final del ejecutor

Respaldo previo: `respaldos_locales/revision-final-apt-20261108T005329Z.tar.gz`
y manifiesto SHA-256 adjunto. Corregidos aislamiento de imports, validación de los archivos de bloqueo,
verificación de los archivos exactos seleccionados y reconocimiento de hijos
terminados por señal.
No se han instalado helpers ni ejecutado sudo, descargas o actualizaciones.
La prueba de bloqueos usa el método de la fuente python3-apt instalada con su API
simulada: comprueba cesión y recuperación del bloqueo interior también ante error;
no demuestra todavía el comportamiento concurrente de una transacción real.

Validación de la revisión anterior: 56 pruebas específicas y 693 pruebas de regresión seleccionada,
satisfactorias. La CLI sin helper devuelve `ejecutor_no_instalado`, como corresponde.
En este sandbox los directorios del sistema aparecen con UID nobody; la validación
real de imports exige root y se cierra sin continuar. La prueba positiva conserva
las rutas/tipos reales y simula únicamente el UID root. Debe comprobarse sin esa
simulación tras desplegar el bundle protegido en la VM Debian 13.

## Verificación de la corrección de despliegue (sin instalación)

Respaldo previo: `respaldos_locales/despliegue_20261108/EJECUCION_APT.md`.
Pruebas específicas sobre nueve archivos sintéticos en directorios temporales del
usuario, incluyendo el arranque exacto documentado (sin sudo):

```sh
PYTHONPATH=.:tests /usr/bin/python3 -B -W error::ResourceWarning -m unittest test_despliegue_helper_apt -v
/usr/bin/python3 -B -W error::ResourceWarning tests/ejecutar_regresion_motor.py
```

No se ha instalado el helper, ejecutado sudo ni descargado paquetes al validar
esta corrección. Estas pruebas no certifican un despliegue root real ni reproducen
un corte eléctrico. Los nueve módulos APT y sus políticas permanecen sin cambios.
