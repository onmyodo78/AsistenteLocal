# Cierre técnico de la integración Fedora — 9 de noviembre de 2026

## Decisión propuesta

Cerrar la investigación XDG con resultado negativo. La corrección de compatibilidad
del argumento DNF5 puede incorporarse a las fuentes junto con sus pruebas y esta
documentación, como corrección parcial. **La actualización integrada de
AsistenteLocal todavía no está validada completamente ni lista para redespliegue.**
Este cierre no crea una versión, commit, publicación ni autorización administrativa.

## Evidencia y alcance

| Evidencia | Procedencia | Qué permite afirmar |
| --- | --- | --- |
| La actualización directa mediante DNF5 funcionó | Resultado comunicado por el usuario; no repetido en este cierre | DNF5 pudo actualizar fuera del circuito integrado; no valida el helper, la autorización, el diario ni la comprobación posterior de AsistenteLocal |
| Fedora 45, DNF5 y libdnf5 5.4.7.0 | Consultas SSH de la investigación previa | Identifica el entorno de la comparación XDG |
| Lecturas nativas `--help` y `check` | Matriz XDG de la investigación previa, sin privilegios ni transacciones | Los avisos persisten con ambos controles de plugins activos |
| Regresión local de cierre | Debian 13.7, Python 3.13.5; 982 casos, 970 superados y 12 omitidos, sin fallos ni errores | Compatibilidad de las fuentes bajo las pruebas seleccionadas; no acredita una actualización real |
| Regresión Fedora anterior | Informe previo de compatibilidad: 982 casos, sin fallos ni errores y 14 omisiones | Evidencia histórica de pruebas; no se ha repetido en este cierre |

No se ha consultado ni alterado el diario administrativo histórico en este cierre.
No se reconstruye una transacción a partir de una actualización manual posterior.

## Primera incompatibilidad: argumento corregido en las fuentes

DNF5 5.4.7.0 no admite `downloadonly` como opción de configuración de `--setopt`.
La fuente `dnf5_interactivo.py` ya elimina `--setopt=downloadonly=False` del
comando fijo. No lo sustituye por `--downloadonly`, no añade argumentos externos
ni cambia el modo de confirmación. El informe previo registró código 0 con el
comando corregido y `--help`; esa lectura no ejecutó `upgrade`.

Se conservan en la fuente revisada:

- `--no-plugins` y `DNF5_PLUGINS_DIR=''`, para biblioteca y aplicación.
- `assumeyes=False`, `assumeno=False`, `defaultyes=False` y confirmación humana TTY.
- `skip_broken=False`, `skip_unavailable=False`, `skip_system_repo_lock=False`,
  `tsflags=` y `--no-allow-downgrade`; sin `-y` ni `--allowerasing`.
- Comando cerrado, autorización con UID/digest/vigencia, consumo único, bloqueo
  de sesiones y ausencia de reintentos automáticos.
- Verificación posterior conservadora: `check` exige código 0 y ambas salidas
  vacías; no se introduce una excepción de stderr para los alias.

Las fuentes candidatas no equivalen al helper instalado. En este cierre,
`sha256sum -c MANIFIESTO_DNF5_COMPAT_547.sha256` confirmó los ocho módulos locales.
No se modificó el manifiesto ni se verificó de nuevo la instalación protegida.

## Segunda incompatibilidad: cuatro avisos de alias

Con `LC_ALL=C`, `LANG=C`, `DNF5_PLUGINS_DIR=''` y `--no-plugins`, la lectura
`/usr/bin/dnf5 -q --cacheonly --no-plugins check` devolvió código 0, stdout de
0 bytes y stderr de **765 bytes**. Son cuatro mensajes:

1. `Attached command "builddep" not found`: el alias solicita un comando ausente.
2. `Missing attribute "attached_command" for command "build-dep"`.
3. `Parent command "reposync" not found`: alias `reposync.downloadpath`.
4. `Parent command "reposync" not found`: alias `reposync.source`.

Proceden de `/usr/share/dnf5/aliases.d/compatibility-plugins.conf` y
`/usr/share/dnf5/aliases.d/compatibility-reposync.conf`.
SHA-256 de los 765 bytes exactos, incluidos sus saltos de línea:

```text
b85816b15c3fa4c6bacb8fc76f29b207b5038c30c5feb0af5a3f2b628ff51b44
```

No se usa este hash como excepción de aceptación. Código 0 con esos mensajes
sigue sin satisfacer la comprobación posterior.

## Comparación XDG finalizada

Se ejecutó como usuario normal, con HOME del usuario, entorno explícito sin
heredar XDG, PATH fijo, idioma C y `DNF5_FORCE_INTERACTIVE=1`. Todos los comandos
comparativos mantuvieron `DNF5_PLUGINS_DIR=''`, `-q`, `--cacheonly` y
`--no-plugins`. Las variables controladas apuntaron a `/proc/self/fd`, sin crear
directorios ni cambiar configuraciones. No es una prueba de un directorio de
estado escribible ni una validación del entorno administrativo con HOME=/root.

| Variante respecto de la base | `check`: código / stdout bytes / stderr bytes | `--help`: código / stdout bytes / stderr bytes |
| --- | --- | --- |
| Sin XDG | 0 / 0 / 765 | 0 / 10969 / 765 |
| Solo `XDG_CONFIG_HOME` | 0 / 0 / 765 | 0 / 10969 / 765 |
| Solo `XDG_CONFIG_DIRS` | 0 / 0 / 765 | 0 / 10969 / 765 |
| Solo `XDG_DATA_HOME` | 0 / 0 / 765 | 0 / 10969 / 765 |
| Solo `XDG_DATA_DIRS` | 0 / 0 / 765 | 0 / 10969 / 765 |
| Las cuatro variables anteriores juntas | 0 / 0 / 765 | No ejecutado |
| Las cuatro más `XDG_CACHE_HOME` y `XDG_STATE_HOME` | 0 / 0 / 937 | 0 / 10969 / 765 |
| Solo `XDG_STATE_HOME` | 0 / 0 / 937 | No ejecutado |

Todos los resultados de 765 bytes comparten el hash anterior. Los de 937 bytes
añaden 172 bytes por no poder abrir `/proc/self/fd/dnf5.log`; mantienen los cuatro
mensajes originales. Su SHA-256 es:

```text
87141ac96622e577dd944c108481b2cf3c90ce3526ddd25c22b891b1994dd835
```

El código oficial 5.4.7.0 carga los alias de `/usr/share/dnf5/aliases.d` y
`/etc/dnf/dnf5-aliases.d` desde rutas fijas, además de la ruta de usuario que
depende de `XDG_CONFIG_HOME`. Por ello estas variantes no eliminan los alias de
plugins ausentes. No se demuestra una imposibilidad general de cualquier solución.

Incidencia de procedimiento: el sondeo inicial `--version` omitió los controles
de plugins y cargó plugins. Se repitió con ambos controles: misma versión, sin
listar plugins cargados y con 765 bytes de stderr. Las pruebas comparativas
estuvieron aisladas. El sondeo inicial no se presenta como prueba de aislamiento.

## Cobertura y estados conservados

`tests/test_dnf5_interactivo.py` contiene 39 casos, incluidos:

- `test_comando_no_utiliza_downloadonly_como_opcion_configuracion`: excluye
  ambos modos downloadonly y conserva opciones de confirmación y downgrade.
- `test_aislamiento_conserva_plugins_aplicacion_y_biblioteca_desactivados`:
  exige ambos controles en las fuentes.
- `test_aviso_alias_con_codigo_cero_no_se_silencia_ni_declara_verificado`:
  aviso sintético de alias, código 0, estado `no_verificable` y conteo de bytes;
  no guarda texto crudo. No reproduce el bloque completo de 765 bytes.
- Casos de TTY, autorización alterada/caducada/reutilizada, inventario y fallo
  posterior. `test_fallo_verificacion_no_se_declara_exito_y_bloquea_reintento`
  exige `resultado_desconocido` y rechazo de un nuevo intento.

La regresión completa incluye este módulo y desactiva integraciones reales.
Los diarios de prueba son temporales; no son el diario histórico protegido.
Comando ejecutado en Debian durante este cierre:

```bash
python3 -B -W error::ResourceWarning tests/ejecutar_regresion_completa.py
```

La revisión de restricciones combina inspección de la fuente y pruebas existentes;
no es una prueba exhaustiva de seguridad ni de ejecución nativa administrativa.
La operación histórica `resultado_desconocido` conserva su estado y su bloqueo.
La verificación `no_verificable` no se convierte en `comprobado` por una
actualización directa exitosa, por código 0 ni por reconocer estos avisos.

## Incorporación y pendientes

| Cambio o decisión | Recomendación |
| --- | --- |
| Retirada del setopt incompatible y sus pruebas existentes | Incorporable a las fuentes como corrección parcial, tras revisión del conjunto exacto; sin desplegar |
| Documentación de resultados y límites | Incorporable; este cierre solo modifica documentación |
| Corrección por variables XDG | No incorporar: resultado negativo |
| Retirar aislamiento o ignorar stderr por texto/hash | No incorporar: debilita controles o cambia el criterio de verificación |
| Helper protegido y diario histórico | Conservar intactos; no reconciliar ni desbloquear desde este cierre |
| Nueva versión con actualización integrada validada | Pendiente de solución de alias y validación administrativa separada |

Para una futura versión: investigar una corrección upstream o un mecanismo
documentado que evite los avisos en origen manteniendo ambos aislamientos;
validarlo primero en lectura en un entorno controlado. No se propone editar
alias del sistema ni activar plugins como solución mínima. Cualquier alternativa
basada en cambiar el entorno de ejecución necesita diseño y validación propios.

La revisión/reconciliación de la operación histórica, un eventual redespliegue y
una futura prueba de actualización integrada necesitan procedimientos y
autorizaciones separados. Ninguna queda autorizada por este informe.

No se ejecutó DNF5, RPM, SSH, sudo ni despliegues durante este cierre documental.
No se modificaron fuentes Python, helper, servicios, permisos, configuración ni
diario histórico. La evidencia XDG procede de la investigación ya finalizada.

## Referencias

- [Corrección parcial y manifiesto candidato](CORRECCION_DNF5_547.md).
- [Modelo interactivo y restricciones](MANTENIMIENTO_FEDORA_INTERACTIVO.md).
- [DNF5 5.4.7.0: plugins y carga de alias, líneas 874–900](https://github.com/rpm-software-management/dnf5/blob/5.4.7.0/dnf5/main.cpp#L874-L900).
- [DNF5 5.4.7.0: resolución de rutas XDG](https://github.com/rpm-software-management/dnf5/blob/5.4.7.0/libdnf5/common/xdg.cpp).
