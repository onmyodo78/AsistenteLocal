# Mantenimiento Fedora 45 con DNF5 interactivo

**Estado vigente al cierre del 9 de noviembre:** actualización integrada sin
validación completa. La corrección del argumento `downloadonly` está en fuentes;
los avisos de alias persisten. Una actualización directa exitosa comunicada por
el usuario no valida esta ruta ni cambia el diario histórico. Consultar el
[cierre técnico](CIERRE_TECNICO_FEDORA.md) antes de cualquier procedimiento.
Las instrucciones administrativas inferiores son históricas/propuestas: no se
recomienda redesplegar mientras persista el bloqueo ni se autoriza hacerlo aquí.

## Contexto de la implementación inicial

Primera versión funcional, 9 de noviembre de 2026. Implementación y regresión
simuladas; no se ha instalado el helper ni realizado una actualización real.

## Modelo de operación

La consulta local de candidatas y la transacción administrativa tienen alcances
distintos. `mantenimiento` detecta Debian 13 o Fedora 45: en Debian reutiliza el
diagnóstico APT; en Fedora consulta candidatas DNF5 con el transporte de lectura
existente, en caché y sin red. Una adquisición incompleta se indica expresamente.
La lista no incluye necesariamente dependencias, reemplazos o eliminaciones y
no acredita frescura. Incluso una consulta completa no es una transacción.

`actualizar-dnf5` solicita una sesión administrativa para un comando fijo. Sudo
normal autentica en el terminal, con `-k` para no reutilizar su timestamp. Se
requiere una política sudo existente con autenticación; como en APT, la política
efectiva pertenece al administrador. El proyecto no crea NOPASSWD, no modifica
sudoers y no recibe, registra ni transmite contraseñas.

El helper protegido muestra el alcance y exige la frase exacta
`ABRIR DNF5 INTERACTIVO <digest>`. Esa frase autoriza abrir DNF5, **no aprueba una
lista de paquetes congelada**. Después DNF5 calcula y muestra su transacción
definitiva y pregunta al usuario directamente. Todas sus entradas y salidas se
conectan a `/dev/tty`, sin respuestas automáticas, pipes de confirmación ni
grabación del terminal. No se acepta confirmación procedente del JSON o modelo.

El comando no incorpora argumentos del modelo, usuario o petición. Desactiva
plugins, assumeyes, assumeno y defaultyes; no usa `-y`, allowerasing, skip de
dependencias ni downgrade. Restablece tsflags. Las fuentes corregidas no incluyen
`--setopt=downloadonly=False` ni `--downloadonly`; el primero no es una opción de
configuración admitida por DNF5 5.4.7.0.
DNF5 conserva sus bloqueos nativos. Puede refrescar metadatos y descargar RPM,
instalar dependencias, reemplazar paquetes y retirar kernels antiguos: el humano
debe revisar todo ello en la terminal definitiva. No se solicita reboot.

`preparar-dnf5` permanece intacto, con su rechazo de transacciones no verificables
y de módulos opacos. No se lo declara seguro ni se lo usa como autorización de
esta ruta interactiva. No hay wrappers nuevos ni interpretación de punteros.
Los contratos del motor de consulta siguen teniendo ejecución deshabilitada,
como ocurre con el motor APT de lectura. La disponibilidad administrativa se
consulta por separado mediante `comprobar-ejecucion-dnf5`.

## Componentes compartidos y específicos

| Componente | Función |
| --- | --- |
| autorizacion_apt.py | Sobre común: UID, nonce, digest, política, tamaño y vigencia de cinco minutos; validación APT conservada |
| cliente_ejecucion_apt.py | Mismo transporte protegido y sudo, con catálogo fijo de dos ubicaciones de helper |
| ejecutor_apt.py | Mismo bootstrap aislado, comprobación de instalación y despacho según su ubicación protegida |
| ejecucion_apt.py | Misma coordinación y máquina de estados; perfil opcional DNF5, comportamiento APT por defecto |
| registro_mantenimiento.py | Mismo diario duradero y exclusión de sesiones; identificadores consumidos una sola vez |
| despliegue_helper_apt.py | Mismo desplegador verificado, con manifiesto y destino cerrados para cada backend |
| mantenimiento_dnf5.py | Política interactiva, diagnóstico factual, autorización TTY y clasificación de resultados |
| dnf5_interactivo.py | Comando nativo fijo, terminal y comprobación posterior RPM |

No hay dependencia funcional de SSH, virtualizadores o rutas de laboratorio.
La aplicación se ejecuta localmente en una terminal Fedora. SSH se utilizó
únicamente para trasladar fuentes y ejecutar la regresión simulada de desarrollo.
No se añadieron dependencias pip ni paquetes del sistema.

## Registro y comprobación posterior

El diario se crea después de autorizar la sesión y persiste su estado antes de
abrir DNF5. Se usa `/var/lib/asistentelocal/mantenimiento.sqlite3`, protegido por
root. Se guardan petición, consulta informativa, política, UID, identificador,
fechas, fases, código de salida DNF5 y verificación. No se copia el transcript
ni se interpretan tablas humanas como evidencia de acciones completadas.

Antes y después se adquiere inventario RPM estructurado, con NEVRA y soporte
multiversión. Se registran hashes, recuentos y versiones que entran/salen, con
límite de 500 filas por lista e indicador explícito de truncamiento. Una versión
que sale no implica necesariamente eliminación del paquete: puede actualizarse.
Se ejecuta además `dnf5 -q --cacheonly --no-plugins check`. Salida desconocida,
stderr o errores impiden declarar esa comprobación verificada.

`completo` significa código DNF5 cero y comprobación posterior satisfactoria;
no garantiza que no queden actualizaciones, retenciones o vulnerabilidades, ni
equivalencia con la consulta inicial. Código no cero sin cambios se registra
como fallo o posible cancelación no distinguible por el código; no se inventa
una causa a partir de texto. SIGINT sin cambios comprobados se distingue como
cancelación. Código no cero con cambios es incompleto. Fallo de comprobación,
comunicación o registro después de una posible ejecución produce resultado
desconocido. Una operación pendiente/incompleta/desconocida bloquea nuevos
intentos hasta revisión administrativa, también entre backends.

No hay reintento automático ni un timeout que mate DNF5 durante la transacción.
Ante Ctrl-C se espera la salida del proceso que ya se inició; no se vuelve a
arrancar. El bloqueo del diario excluye otras sesiones AsistenteLocal, no se
presenta como un bloqueo RPM: esos bloqueos corresponden al propio DNF5.

## Pruebas realizadas

Regresión completa con integraciones administrativas reales desactivadas:

| Entorno | Pruebas | Fallos | Errores | Omisiones |
| --- | ---: | ---: | ---: | ---: |
| Debian 13 | 962 | 0 | 0 | 12 |
| Fedora 45 | 962 | 0 | 0 | 14 |

Incluye pruebas específicas nuevas de detección, candidatas parciales, confirmación
humana, caducidad/manipulación, permisos, cancelación, errores DNF5, inventario
multiversión, comprobación posterior, diario y despliegue cerrado. También se
conserva la regresión del preparador estricto y del mantenimiento APT existente.
Son pruebas simuladas: el comportamiento de una actualización nativa real queda
pendiente de autorización y validación administrativa separadas.

## Procedimiento futuro, solo después de nueva autorización

### 1. Consultar sin privilegios

En una terminal local Fedora, desde el checkout revisado:

```bash
python3 -B cli.py mantenimiento
python3 -B cli.py --formato json actualizaciones
python3 -B cli.py --formato json comprobar-ejecucion-dnf5
```

Si el helper no está instalado, la última consulta indica `ejecutor_no_instalado`
sin solicitar sudo. El comando `actualizar-dnf5` también falla cerrado en ese caso.
No usar `actualizar-apt` en Fedora; se mantienen las entradas explícitas por backend.

### 2. Revisar y desplegar el helper, acción administrativa independiente

Destino fijo: `/usr/local/lib/asistentelocal-dnf5/ejecutor_apt.py`. El nombre del
archivo se comparte con APT; su directorio determina el perfil. El destino Fedora
no sustituye `/usr/local/lib/asistentelocal`. Si ya existe el destino, el instalador
lo rechaza: detenerse y revisar, sin borrarlo ni reemplazarlo automáticamente.

Desde el proyecto revisado, preparar referencias sin privilegios:

```bash
umask 077
manifest_dnf5="$(mktemp /tmp/asistentelocal-dnf5-manifiesto.XXXXXXXX)"
/usr/bin/sha256sum ejecutor_apt.py ejecucion_apt.py mantenimiento_dnf5.py dnf5_interactivo.py autorizacion_apt.py registro_mantenimiento.py contratos_mantenimiento.py distribucion_linux.py > "$manifest_dnf5"
cat -- "$manifest_dnf5"
sha256sum -- "$manifest_dnf5" despliegue_helper_apt.py
```

Revisar los ocho módulos y el desplegador. Introducir sus dos digests aprobados
desde una terminal de confianza; no recalcular y aprobar automáticamente hashes
dentro del comando privilegiado:

```bash
read -r -p 'SHA-256 aprobado del manifiesto: ' manifest_dnf5_sha
read -r -p 'SHA-256 aprobado del desplegador revisado: ' deploy_dnf5_sha
project_dnf5="$PWD"
readonly manifest_dnf5 manifest_dnf5_sha deploy_dnf5_sha project_dnf5
```

El siguiente paso escribe la instalación protegida: no se ha ejecutado durante
el desarrollo. Reutiliza el arranque verificado de APT, ejecutando los mismos
bytes del desplegador que se contrastaron, con perfil DNF5:

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
' "$project_dnf5/despliegue_helper_apt.py" "$deploy_dnf5_sha" \
  --origen "$project_dnf5" --manifiesto "$manifest_dnf5" \
  --sha256-manifiesto "$manifest_dnf5_sha" --backend dnf5
```

El instalador solo copia el conjunto cerrado, valida permisos/propiedad/hashes
y publica sin reemplazar. No instala paquetes, crea sudoers ni inicia servicios.
No ejecutar directamente un instalador editable con sudo sin este arranque.

### 3. Validar la actualización con el humano presente

Primero comprobar el helper. Con autorización expresa para la operación real,
iniciar desde AsistenteLocal:

```bash
python3 -B cli.py --formato json comprobar-ejecucion-dnf5
python3 -B cli.py actualizar-dnf5
```

Sudo pedirá autenticación según su política normal. Revisar la consulta inicial
y el alcance administrativo; escribir la frase exacta del helper solo si se desea
abrir DNF5. **Revisar después la transacción definitiva que DNF5 muestra y confirmar
manualmente su propia pregunta.** Entrar no o cancelar si no es aceptable. El
programa no debe suministrar la respuesta ni el modelo aprobarla.

Tras terminar, revisar el JSON factual y, si procede, el diario:

```bash
python3 -B cli.py --formato json historial-dnf5
python3 -B cli.py mantenimiento
```

`historial-dnf5` requiere sudo para leer el diario protegido. Si el resultado es
incompleto o desconocido, revisar el estado nativo y los registros con un
administrador; no lanzar automáticamente otra actualización ni editar SQLite
para eliminar el impedimento. Esta primera versión no implementa reconciliación
automática de operaciones pendientes.

## Referencias de DNF5

- [Opciones generales y códigos de salida](https://dnf5.readthedocs.io/en/stable/dnf5.8.html).
- [Configuración de assumeyes, assumeno y defaultyes](https://dnf5.readthedocs.io/en/stable/dnf5.conf.5.html).
- [Upgrade](https://dnf5.readthedocs.io/en/stable/commands/upgrade.8.html).

La prueba nativa posterior debe confirmar las opciones en la versión concreta
de DNF5; un fallo de argumentos no se interpreta como actualización exitosa.
