# Compatibilidad DNF5 5.4.7.0 — 9 de noviembre de 2026

## Cierre de la investigación XDG

La comparación XDG ha finalizado con resultado negativo: los cuatro avisos de
alias persisten, con 765 bytes de stderr y SHA-256
`b85816b15c3fa4c6bacb8fc76f29b207b5038c30c5feb0af5a3f2b628ff51b44`.
El [cierre técnico Fedora](CIERRE_TECNICO_FEDORA.md) contiene la matriz completa,
la incidencia del sondeo de versión, la cobertura y los límites de incorporación.
La actualización directa mediante DNF5 funcionó según el usuario; la actualización
integrada de AsistenteLocal sigue sin validación completa. No se reclasifica la
operación histórica `resultado_desconocido` ni la comprobación `no_verificable`.
Regresión de este cierre en Debian: 982 casos, sin fallos ni errores, 12 omitidos.
No se redespliega el helper. El procedimiento inferior es una propuesta anterior,
no una autorización ni una recomendación de ejecutar un despliegue ahora.

## Resultado: corrección parcial; no redesplegar todavía

Se retiró únicamente --setopt=downloadonly=False del comando fijo.
No es una opción de configuración en DNF5 5.4.7.0. No se añade --downloadonly.
Las confirmaciones, restricciones, tiempos y verificaciones no cambian.
Se añadieron tres pruebas al módulo test_dnf5_interactivo.py.

Regresión completa: Debian 982 pruebas, 0 fallos, 0 errores, 12 omisiones;
Fedora 982 pruebas, 0 fallos, 0 errores, 14 omisiones.
El comando corregido con --help termina con código 0; no se ejecutó upgrade.

## Plugins: bloqueo conservador mantenido

La documentación oficial distingue --no-plugins (biblioteca libdnf5) de
DNF5_PLUGINS_DIR vacío (plugins de aplicación). Quitar la variable cargaría
plugins de aplicación y NO es una corrección aceptable del aislamiento.
El código oficial 5.4.7.0 carga aliases desde rutas fijas tras cargar plugins.
No se encontró una alternativa pública documentada que desactive los plugins
de aplicación y evite los avisos de esos aliases sin configuración adicional.
No se ha demostrado que tal alternativa exista: no afirmar imposibilidad general.
Se conserva DNF5_PLUGINS_DIR vacío y se documenta su finalidad en el código.
No se ignora, filtra ni admite stderr por coincidencias textuales.

Validación de lectura en Fedora, sin privilegios, con HOME del usuario:
- Comando corregido + --help: código 0, stderr 765 bytes.
- Check en caché con aislamiento de aplicación: código 0, stdout 0, stderr 765.
- Las pruebas verifican que ese aviso produce no_verificable y no se guarda crudo.
No se declara la ruta administrativa validada ni lista para una actualización.

Referencias primarias:
https://dnf5.readthedocs.io/en/latest/dnf5.8.html#environment
https://dnf5.readthedocs.io/en/latest/dnf5.8.html#options
https://dnf5.readthedocs.io/en/latest/misc/aliases.7.html
https://github.com/rpm-software-management/dnf5/blob/5.4.7.0/dnf5/main.cpp

## Integridad y alcance

No se modificaron APT, preparador estricto, cliente, autorizaciones o diario.
Solo cambian dnf5_interactivo.py y tests/test_dnf5_interactivo.py, además de
este informe y un manifiesto nuevo. Los dos archivos de código/pruebas fueron
sincronizados con hashes y respaldo en el proyecto Fedora.
Referencia del manifiesto de la instalación comunicada en aquella fase:
ba12ac0f31399bae2c2778a47e21016d9409ef999545bcd8aeca63fe8db8ea8c.
Es el hash de un manifiesto histórico, no el hash de un binario ni una nueva
comprobación del helper durante la preparación para publicación.
La operación histórica resultado_desconocido no se leyó ni modificó en esta fase.
No hubo sudo, actualizaciones, RPM modificados, servicios cambiados o despliegues.

## Manifiesto candidato, NO aprobado ni instalado

MANIFIESTO_DNF5_COMPAT_547.sha256: f2ccea95b461b9e5f8e92eadfbe1f7f91e19f1e5071314073db5c042f5ecd496
Desplegador sin cambios:
5e29c81d6eaf883225f6512603d20e3d8e5756afe428a623ba2c16494eb13fb6
El manifiesto candidato cambia solo dnf5_interactivo.py de los ocho módulos.
No sustituye ni invalida el manifiesto autorizado de la instalación actual.

## Procedimiento de redespliegue para revisión posterior

No se recomienda desplegar mientras persista el bloqueo de plugins.
Si se decide instalar esta corrección parcial, solicitar autorización explícita:
1. En Konsole y con contraseña personal, verificar el desplegador por los bytes
   aprobados mediante el arranque aislado -I -S -B del procedimiento existente.
2. Verificar manifiesto candidato, fuentes y helper instalado: conjunto exacto,
   hashes, root:root, directorio 0755 y ocho módulos regulares 0644 con nlink 1.
3. Rechazar si ya existe /usr/local/lib/asistentelocal-dnf5-respaldo-compat547-20261109.
   Conservar allí íntegro el helper actual mediante renameat2 RENAME_NOREPLACE.
   No tocar el respaldo TTY existente ni el directorio APT.
4. Publicar los ocho módulos con el desplegador cerrado existente en
   /usr/local/lib/asistentelocal-dnf5, root:root 0755 y archivos root:root 0644.
   Usar los temporales originales: manifiesto /tmp/asistentelocal-dnf5-manifiesto.*
   0600 y staging /usr/local/lib/.asistentelocal-despliegue-* 0700.
5. Verificar hashes, propiedades, ausencia de archivos adicionales y temporales,
   respaldo intacto y solo la operación comprobar. Detenerse ante discrepancias,
   conservando respaldo, sin restauración ni actualización automáticas.

Ningún despliegue autoriza una transacción real ni reconcilia el diario.
El estado histórico desconocido sigue bloqueando nuevos intentos; su revisión y
cualquier eventual reconciliación requieren un procedimiento y autorización
separados. No editar SQLite para permitir otro intento.
