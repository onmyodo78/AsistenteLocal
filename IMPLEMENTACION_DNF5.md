# DNF5: preparación implementada y ejecución bloqueada

**Nota de estado posterior:** este informe describe la fase inicial del preparador
estricto, que conserva su rechazo de ejecución. Posteriormente se implementó una
ruta interactiva administrativa separada; su actualización integrada todavía no
está completamente validada. El estado vigente y el resultado XDG negativo están
en el [cierre técnico Fedora](CIERRE_TECNICO_FEDORA.md).

Entrega histórica del 9 de noviembre de 2026. Se revisó la propuesta inicial,
conservada únicamente en el entorno local por haber sido sustituida por esta implementación, y
se contrastó con los adaptadores, worker/transporte, contratos, mantenimiento,
motor de auditoría, herramientas locales y circuito administrativo APT actual.

## Resultado y alcance real

Se implementa un backend opcional de **preparación de lectura** con libdnf5,
contrato estricto e integración simulada. No se implementa una ruta que instale
paquetes Fedora: la identidad completa y la continuidad de los bloqueos aún no
están acreditadas en la versión de la VM. El rechazo es incondicional por código,
no una preferencia del modelo ni una confirmación que pueda omitirse.

No se instaló ninguna dependencia, no se ejecutó DNF/RPM ni sudo, ni se modificó
configuración, sudoers, servicios, automatizaciones o LM Studio. No se publicó
en GitHub. Los artefactos de traslado son archivos locales de código y pruebas.

## Cambios

- `dnf5_preparacion.py`: configuración efímera, resolución de Goal e inspección
  de Transaction. Registra acciones tipadas, motivo, NEVRA con epoch y release,
  paquetes reemplazados, inventario multiversión y los ID de repositorios activos.
  No contiene llamadas a download/run/test/serialize/store ni lanza comandos.
- `mantenimiento_worker.py`: nueva operación fija `dnf5-preparar`, ejecutada solo
  después del aislamiento existente y con rechazo de root. El modo antiguo de
  aborto `dnf5-simular` permanece por compatibilidad, sin ser seleccionado por
  el adaptador ni por el nuevo comando.
- `mantenimiento_transporte.py`: incorpora esa operación a la lista blanca;
  reutiliza captura acotada, deadline, limpieza, temporal privado, Landlock y
  seccomp. No se relaja el aislamiento ni el rechazo de stderr desconocido.
- `adaptadores/fedora.py`: prepara mediante el worker si encuentra el binding,
  valida el JSON y contrasta el inventario previo cuando se proporciona.
  Proyecta acciones informativas en el plan v1, siempre no verificable. Una
  salida por reemplazo de la misma actualización no se presenta como eliminación
  independiente. Relaciones más complejas se conservan en el contrato detallado.
- `cli.py`: `preparar-dnf5` expone la evidencia detallada sin modelo ni privilegios;
  devuelve código 3. El plan Debian/APT y sus contratos v1 no cambian.
- Pruebas y corredor: nueva selección `test_dnf5_preparacion` y corrección del
  reloj de la prueba de frase exacta.

Libdnf5 es una dependencia nativa opcional del sistema, no una nueva dependencia
pip. Si no está instalada o su API difiere de la usada, se devuelve
`binding_no_disponible` o `api_dnf5_no_admitida`. No se instala para resolverlo.
Un fallo de carga de repositorios, permisos o aislamiento también bloquea la
preparación; no se ignora para obtener una lista aparentemente completa.

## Evidencia y garantías

El contrato `preparacion_dnf5` v1 está separado del plan de mantenimiento v1.
Reutiliza serialización canónica, lector JSON con rechazo de claves duplicadas,
límites y vigencia del circuito existente. Valida tipos, identidades, duplicados,
acciones desconocidas, repositorios y reemplazos contra inventario. Los errores
son códigos cerrados: no se vuelcan excepciones, URL, contraseñas o logs nativos.

`acciones_estado=completo` significa que se obtuvo y validó la enumeración de
acciones del objeto resuelto; **no significa simulación administrativa completa**.
El estado global permanece `no_verificable`, `ejecucion_habilitada=false`, con
seis pendientes explícitos: retenciones, avisos correlacionados con el plan,
identidad de metadatos, configuración efectiva, RPM verificados y continuidad
del bloqueo. La resolución exige ausencia de problemas y logs sin interpretar;
grupos, entornos o módulos no admitidos no se omiten silenciosamente.

`comprobar_identidad` rechaza evidencia vencida o modificada en acciones,
inventario o repositorios. Su éxito solo compara la evidencia disponible;
no acredita los seis pendientes. La huella identifica el informe, no es una
firma ni un token administrativo. `comprobar_ejecutable` rechaza incluso evidencia
idéntica y reciente. El comprobador administrativo APT sigue rechazando Fedora.
No existe llamada a un `dnf upgrade` posterior ni una segunda resolución ejecutora.

La configuración de lectura desactiva plugins y construcción de cachés, exige
caché local, desactiva skips/downgrades y usa logdir/persistdir efímeros. Red y
escrituras persistentes están prohibidas por el aislamiento, aunque una biblioteca
intentase hacerlas. Si DNF5 necesita un bloqueo escribible o un caché no disponible,
puede no prepararse en esta modalidad: conservar no_verificable y el motivo.

## Circuito administrativo pendiente

No se ha duplicado ni extraído prematuramente el ejecutor APT. Su autorización
TTY, sudo normal, diario duradero y coordinación permanecen operativos y se
validan en la regresión. La preparación nueva reutiliza el transporte de lectura;
la conexión privilegiada al diario y al coordinador **queda pendiente**, no se
presenta como implementada o probada mediante un backend ficticio ejecutable.

La documentación de libdnf5 permite inspeccionar y ejecutar el mismo objeto
Transaction en una sesión. El diseño previsto conserva ese objeto dentro del
helper protegido: autenticar por sudo, mostrar todas las acciones y confirmar
la petición exacta en TTY, registrar autorización, adquirir bloqueos nativos,
resolver y comparar bajo bloqueo, verificar firmas/hashes/configuración/metadatos,
recomprobar vigencia y ejecutar ese objeto sin resolver otra transacción. Rechazar
eliminaciones, instalaciones inesperadas y cualquier variación relevante. No
reintentar tras comenzar; registrar resultado y contrastar inventario posterior.

Antes de habilitarlo se debe comprobar en la API instalada la cooperación del
bloqueo libdnf5 con operaciones externas RPM y el comportamiento interno de run
ante cambios del sistema. Base.lock() no es un bloqueo de rpmdb. Los imports
privilegiados Fedora, su instalación protegida y el manifiesto cerrado del helper
también requieren adaptación específica. No se sustituye esta evidencia por un
lock del diario, por JSON de serialize (experimental) o por replay. Hasta entonces
no se ofrece un comando de actualización Fedora ni se solicita sudo para Fedora.

## Regresiones y pruebas

La frase exacta mantiene todas las expectativas anteriores y usa el mismo reloj
en la entrada conversacional y el coordinador, con orígenes 10 y 10000 segundos.
Una prueba adicional avanza el reloj y confirma agotamiento a los 120 segundos,
sin interpretación del modelo tras vencer el plazo. No cambian límites productivos.

La prueba de aborto conserva `no_verificable` y la prohibición de sondear comandos
cuando no hay binding. Ahora fija explícitamente esa ausencia, para que el resultado
no dependa de tener libdnf5 en el anfitrión. Otra prueba simula binding presente y
una respuesta textual de aborto: también se rechaza. No se aceptan tablas humanas.

No se dispone de la copia ni del traceback de Fedora. No se pueden afirmar
diferencias reales entre sus archivos y Debian; una copia antigua sigue siendo
solo una hipótesis. El paquete y manifiesto permiten identificar esas diferencias
sin sustituir ni sobrescribir la copia anterior.

Regresión final Debian 13, Python 3.13: **916 pruebas, 12 omitidas, sin fallos**.
Incluye 20 pruebas nuevas DNF5 y una nueva de agotamiento conversacional, además
de la prueba de frase exacta ampliada. Verifica permisos, API incompatible,
repositorios ausentes/cambiados, conflictos sin excepción, acciones desconocidas,
eliminación/instalación/downgrade, kernels multiversión, inventario cambiado,
caducidad, manipulación, JSON inválido, cancelación, deadline, errores de transporte,
worker aislado y ausencia de vías ejecutoras. El corredor conserva las pruebas
administrativas APT simuladas; no acredita ejecución nativa DNF5 ni actualizaciones.

## Traslado y validación Fedora 45

Se prepara `dist/asistentelocal-validacion-fedora-dnf5-20261109.tar.gz` con fuentes,
documentación y pruebas/fixtures; sin .git, cachés, datos privados, historiales,
respaldos, dist anterior ni prototipos locales. Incluye `MANIFIESTO_FEDORA.sha256`.
El archivo adyacente `.tar.gz.sha256` identifica el paquete. Extraer en una carpeta
nueva de trabajo de la VM, sin sobrescribir la copia anterior y sin instalar nada.

Desde el directorio padre del paquete recibido:

```bash
sha256sum -c asistentelocal-validacion-fedora-dnf5-20261109.tar.gz.sha256
tar -xzf asistentelocal-validacion-fedora-dnf5-20261109.tar.gz
cd asistentelocal-validacion-fedora-dnf5-20261109
sha256sum -c MANIFIESTO_FEDORA.sha256
python3 --version
dnf5 --version
python3 -B -W error::ResourceWarning tests/ejecutar_regresion_completa.py
python3 -B cli.py --formato json capacidades
python3 -B cli.py --formato json actualizaciones
python3 -B cli.py --formato json preparar-dnf5
python3 -B cli.py --formato json plan
```

Usar usuario normal en terminal nativa Fedora. El número de omisiones puede variar
por plataforma. Registrar versiones exactas, resultados, motivo de no verificable y
traceback completo si hay fallos. Las consultas no necesitan LM Studio. No usar
sudo, refresh, download, store, replay ni activar variables de integración real.

Para comparar archivos, ejecutar `sha256sum -c` con el manifiesto nuevo desde
la raíz de la copia Fedora anterior: informará faltantes y diferencias; no escribe
archivos. Conservar esa salida antes de migrar. No confundir diferencias con prueba
automática de cuál archivo causó una regresión. Los imports de los tests se resuelven
desde la carpeta del corredor y la raíz de esa misma copia, sin mezclar checkouts.

Resultados esperados: ejecución siempre deshabilitada; estado global DNF5 no
verificable. Si la API/caché/aislamiento permiten preparar, inspeccionar acciones,
reemplazos, repositorios y huella, sin asumir ausencia de conflictos/retenciones
cuando no se comprobaron. Si no, conservar el error y no instalar dependencias.
La regresión final también se ejecuta en una extracción local del paquete para
comprobar que contiene las dependencias de código y fixtures necesarias.

Ninguna actualización real forma parte de este procedimiento. Esa validación
requiere completar primero los pendientes administrativos, revisar el plan
concreto y una nueva autorización expresa del usuario.

## Fuentes primarias

- [Sesión y configuración](https://dnf5.readthedocs.io/en/latest/tutorial/bindings/python3/session.html).
- [Carga de repositorios](https://dnf5.readthedocs.io/en/latest/tutorial/bindings/python3/repos.html).
- [API Base y Transaction](https://dnf5.readthedocs.io/en/latest/api/python/libdnf5_base.html).
- [Acciones tipadas upstream](https://github.com/rpm-software-management/dnf5/blob/main/include/libdnf5/transaction/transaction_item_action.hpp).

Son referencias de diseño; los dobles de prueba no certifican la compatibilidad
con el binding instalado en la VM. No se ha accedido a esa VM desde esta sesión.
