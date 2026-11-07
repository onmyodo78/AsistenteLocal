# Escritor de exportación, fase 4

Módulo independiente `exportacion_escritor.py`; sin integración con AsistenteLocal,
SQLite, diagnósticos ni guardado automático. Única API de escritura:

`publicar(controlador, identificador, autorizacion)`

Solo admite una instancia exacta de `ControladorExportacion`. Consume el token
mediante la implementación real de `consumir()`, manteniendo su bloqueo. No acepta
entregas reconstruidas, bytes ni rutas como autorización. Valida el plazo de ese
mismo permiso al comenzar, durante la escritura y justo antes de publicar. Un
fallo consume el permiso. No cambia el contrato del controlador ni generadores.

La entrega es una instantánea inmutable de formato, destino y bytes. Se vuelve
a comprobar la correspondencia md/.md o csv/.csv y el límite de 4 MiB. No se
regeneran informes ni se hacen nuevas adquisiciones. La API depende del bloqueo
y registro privado actuales del controlador; una revisión de esa API exige
revisar también el escritor.

## Archivos y publicación

- Solo Linux con operaciones relativas a descriptores. Todos los directorios deben
  existir; se recorren desde `/` con `O_DIRECTORY|O_NOFOLLOW` sin resolver enlaces.
- Se rechazan ancestros escribibles por otros sin sticky y padres finales ajenos
  o escribibles por grupo/otros. Un `/tmp` con sticky es admisible como ancestro
  de un directorio privado de prueba. No se modifican permisos de directorios.
- Se crea un temporal aleatorio en el mismo padre con `O_EXCL|O_NOFOLLOW`, modo
  0600. `fchmod` solo actúa sobre ese archivo recién creado, incluso con umask
  más restrictiva. Nunca se abre el destino para escribir o truncar.
- Se completan las escrituras, se hace `fsync` del temporal y se releen sus bytes
  para compararlos exactamente con la entrega. Se verifica su identidad y se
  reabre la cadena del padre antes de publicar para detectar sustituciones.
- `os.link` con ambos directorios anclados al descriptor publica el inode completo
  en un nombre nuevo. La operación falla si el destino ya existe, sea archivo,
  directorio o enlace: no existe ventana de comprobación seguida de sobrescritura.
- Se elimina el nombre temporal y se sincroniza el directorio. Si el sistema de
  archivos no admite enlaces duros o estas operaciones, se falla sin fallback.

La atomicidad de aparición del nombre se apoya en la semántica de `link` del
sistema de archivos; no es una transacción entre varios archivos. Los lectores
ven un archivo completo desde su publicación. No se garantiza durabilidad ante
fallos de hardware ni semántica equivalente en sistemas de archivos remotos o
implementaciones no conformes. No se han validado todos los sistemas de archivos
usados por Fedora o Debian. La disponibilidad de las primitivas no certifica por
sí sola un montaje remoto: esta versión se destina a sistemas locales con las
semánticas POSIX descritas.

## Fallos y límites

Antes del enlace, un fallo elimina el temporal cuando el SO lo permite y no
publica un informe parcial. Si el SO impide la limpieza, se devuelve
`limpieza_no_confirmada`; puede quedar un temporal 0600. Una terminación abrupta
del proceso puede dejar también ese temporal. No se implementa limpieza posterior.

Después del enlace, el informe ya está publicado y completo. Un fallo al eliminar
el temporal o sincronizar el directorio se comunica como
`publicado_finalizacion_no_confirmada` o `publicado_limpieza_no_confirmada`; no se
borra el informe ni se afirma rollback. El token permanece consumido y no se
reintenta. Los mensajes son códigos cerrados y suprimen el contexto de errores
nativos para no mostrar rutas ni contenido.

La vigencia se comprueba inmediatamente antes de `link`; el reloj puede avanzar
mientras el kernel ejecuta esa llamada. No se promete una caducidad atómica con
el reloj y el sistema de archivos. La cancelación posterior al consumo no es una
revocación de una operación que ya ha comenzado.

El límite de confianza excluye código malicioso con el mismo UID y administradores:
pueden manipular memoria de Python, renombrar padres entre la última comprobación
y la publicación o modificar archivos del usuario. Los descriptores evitan seguir
rutas sustituidas; la comprobación adicional detecta cambios previos, pero no
puede garantizar que un directorio no sea renombrado inmediatamente después.
No es una barrera de seguridad frente a esos actores. No se modifica el aislamiento
existente para realizar exportaciones.

Las pruebas escriben solo dentro de `TemporaryDirectory`. No se autoriza una
exportación real ni conexión con la aplicación por la existencia de este módulo.
