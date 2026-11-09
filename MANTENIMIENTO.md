# Revisión semanal recomendada

Procedimiento manual para quien mantiene el proyecto. Se recomienda realizarlo
una vez por semana; no configura cron, temporizadores ni otras automatizaciones.
No utiliza GitHub Actions, Dependabot ni servicios externos de mantenimiento.
GitHub sirve únicamente como medio de distribución del proyecto.

La revisión no instala dependencias ni actualiza el sistema. Los hallazgos se
convierten en propuestas separadas que el usuario puede autorizar después.

## 1. Revisar el estado local

Desde la raíz del repositorio, revisar `git status --short` y `git diff`, sin
hacer fetch, pull, commit ni push. Examinar también el contenido de los archivos
nuevos que se pretenda publicar: el diff normal no los incluye.

Inventariar las dependencias a partir del código y del README: biblioteca
estándar, ejecutables de cada herramienta, LM Studio para conversación y bindings
opcionales como `apt_pkg` o RPM. Contrastar con la información instalada que ya
esté disponible localmente, sin instalar ni importar bindings solo para probarlos.
Registrar ausencias e incompatibilidades sin corregirlas automáticamente.

Consultar versiones y documentación ya instaladas cuando sea necesario. La
información APT local puede estar desactualizada; no ejecutar `apt update`,
adquisiciones APT reales, simulaciones ni prototipos como parte de esta revisión.
La fecha de un archivo de caché no acredita por sí sola su frescura ni seguridad.

## 2. Revisar compatibilidad y regresiones

Comprobar que los requisitos publicados siguen coincidiendo con el código y la
información local: intérprete, distribución, herramientas opcionales y límites
de aislamiento. Distinguir compatibilidad revisada de compatibilidad demostrada
mediante ejecución real. No modificar el entorno para completar una comprobación.

Tras revisar su alcance, ejecutar la regresión pública desde la raíz:

```sh
/usr/bin/python3 -B -W error::ResourceWarning tests/ejecutar_regresion_completa.py
```

El corredor enumera pruebas concretas y desactiva las integraciones optativas.
No sustituirlo por descubrimiento general de prototipos locales. Registrar casos
superados, omitidos y fallidos; las comprobaciones reales requieren revisión
separada. El corredor de referencia sigue disponible en
`tests/ejecutar_regresion_motor.py`.

## 3. Revisar seguridad y privacidad

Inspeccionar cambios en listas de operaciones permitidas, argumentos, uso de
subprocesos, límites de tiempo y salida, aislamiento y comportamiento ante
fallos. Comprobar que no aparecen shell libre, elevación de privilegios para el
modelo, persistencia de credenciales ni consultas externas implícitas.

Revisar los archivos concretos destinados a publicación para detectar secretos,
datos personales, rutas de usuario, informes reales o conversaciones. Verificar
las exclusiones de Git y los archivos ya rastreados: `.gitignore` no elimina
archivos rastreados ni constituye un detector de secretos. `privado/` se reserva
exclusivamente para documentación técnica de desarrollo, sin contraseñas,
tokens, credenciales ni información personal, y debe permanecer sin rastrear.

Los avisos y la documentación disponibles localmente pueden orientar la revisión,
pero su ausencia no acredita que las dependencias estén libres de vulnerabilidades.

## 4. Consultar fuentes externas solo con autorización

Si se necesita información reciente, presentar al usuario las fuentes oficiales,
el propósito y los datos que se enviarían. Esperar autorización antes de acceder.
Consultar únicamente las fuentes autorizadas, por ejemplo documentación oficial
de Python, Debian, Fedora o del proveedor de una dependencia, según el alcance.
No enviar inventarios, versiones locales, conversaciones ni informes privados
sin autorización específica para esos datos.

Sin autorización, completar las comprobaciones locales y registrar
«información externa no consultada; vigencia de avisos no verificada». No activar
servicios de mantenimiento ni crear configuraciones para ellos. No descargar o
instalar actualizaciones como consecuencia de encontrar un aviso.

## 5. Registrar y proponer acciones

Anotar fecha real de revisión, alcance, evidencia saneada, pruebas ejecutadas,
limitaciones y acciones propuestas en documentación técnica local. Evitar copiar
salidas nativas que contengan datos privados. Si hay un hallazgo sensible, no
incluirlo en documentos públicos ni en `privado/`; limitar el registro a una
descripción técnica sin secretos ni información personal.

Priorizar las propuestas según impacto y evidencia, separando correcciones del
proyecto, comprobaciones pendientes y posibles cambios del sistema. Cada cambio
requiere su revisión y autorización correspondiente. Actualizar `CHANGELOG.md`
solo con cambios realmente realizados; no inventar versiones o publicaciones.
Finalizar revisando el diff y los archivos nuevos, sin commit ni publicación
automáticos.
