# Registro de cambios

## Preparación para revisión GitHub — sin publicar, 9 de noviembre de 2026

- Completado el manifiesto público de 169 archivos y documentada la selección de
  históricos útiles; tres documentos/artefactos anteriores permanecen solo locales.
- Corregidos README, hoja de ruta y estado para separar capacidades comprobadas,
  experimentales y pendientes, sin cambios de fuentes Python ni pruebas.
- Minimizados datos del laboratorio y reforzadas exclusiones de claves locales;
  registros y respaldos preservados. Validación exacta: [inventario](INVENTARIO_PUBLICACION.md).
- Copia exacta: 874 casos en referencia y 982 en el completo, con 12 omisiones
  en este último, sin fallos ni errores; fuentes y pruebas intactas.
- Sin despliegues, transacciones, selección Git ni autorización de publicación.

## Cierre técnico Fedora — sin publicar, 9 de noviembre de 2026

- Consolidada la corrección parcial existente de `--setopt=downloadonly=False`,
  sus pruebas y las restricciones conservadas; sin cambios de fuentes en este cierre.
- Documentados los cuatro avisos de alias, sus 765 bytes y SHA-256, y la comparación
  XDG negativa manteniendo ambos aislamientos de plugins.
- Diferenciada la actualización directa exitosa comunicada por el usuario de la
  actualización integrada aún sin validación completa; conservados los estados
  `resultado_desconocido` y `no_verificable` y el bloqueo histórico.
- Regresión Debian: 982 casos, sin fallos ni errores, 12 omisiones. Ocho módulos
  locales coinciden con el manifiesto candidato; sin redespliegue, transacciones,
  cambios de configuración, helper ni diario. Detalle: [cierre Fedora](CIERRE_TECNICO_FEDORA.md).

## Ampliación local — sin publicar

- Auditoría semanal no interactiva reutilizando el coordinador, con informes privados
  y bloqueo compartido; plantillas systemd de usuario sin instalación/activación implícita.
- Entrada mantenimiento_apt.py al circuito existente de CLI y helper protegido,
  exigiendo terminal para operaciones autenticadas, sin duplicar lógica APT.
- Pruebas simuladas de programación, persistencia, permisos y delegación.
- No se ejecutan transacciones ni se modifica el helper o la configuración de LM Studio.

## Cierre local — sin publicar, 8 de noviembre de 2026

- Actualizada la documentación de capacidades implementadas, verificadas y pendientes;
  Debian 13 validado, Fedora pendiente de prueba real.
- Conservada la regresión de referencia de 786 casos e incorporado un corredor
  completo de pruebas existentes, sin añadir casos para aumentar el contador.
- Revisadas exclusiones, dependencias locales e inventario de publicación.
- Conservados fuera de la entrega los registros reales y respaldos privados.
- Sin cambios funcionales del motor ni del ejecutor APT en este cierre.

## Notas documentales anteriores (históricas)


- Documentado el objetivo de una única aplicación local, auditable y adaptable,
  con herramientas y permisos explícitos; otros proveedores de modelos locales
  compatibles se describen como extensibilidad futura, todavía no implementada.
- Aclarada la independencia de la CLI respecto de VS Code y Codex, el papel del
  servidor local de LM Studio y la posibilidad de arrancar sin él.
- Aclarado el papel de GitHub como medio de distribución y el control del usuario
  sobre consultas externas y modificaciones del sistema.
- Añadida una hoja de ruta que distingue APT experimental de la futura
  actualización supervisada, todavía no disponible.
- Añadido un procedimiento semanal recomendado, manual y prioritariamente local
  para revisar dependencias, compatibilidad y seguridad, sin actualizaciones
  automáticas ni servicios externos de mantenimiento.
- Reservado un directorio excluido de Git para documentación técnica local de
  desarrollo, sin credenciales ni información personal.

Estos cambios son documentales y de exclusión de archivos; no modifican la lógica
de ejecución, los módulos Python ni las pruebas. No se reconstruye el historial
anterior ni se asignan versiones o fechas de publicación sin evidencia.
