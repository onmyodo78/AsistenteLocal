# Hoja de ruta

Este documento recoge propuestas futuras, sin calendario ni compromiso de
versión. No habilita operaciones ni autoriza su ejecución.

## Estado actual

AsistenteLocal mantiene su alcance de consultas de solo lectura. En Debian 13
existe inventario dpkg y una adquisición experimental de candidatas APT desde
información local. La adquisición APT no tiene validación real satisfactoria bajo
las protecciones actuales y puede fallar o ser parcial. No implementa simulación,
selección para instalación ni ejecución de actualizaciones. Tampoco implementa
correlación CVE Debian. Un resultado desconocido no significa ausencia de
actualizaciones o vulnerabilidades. El [README](README.md) detalla estos límites.

## Objetivos generales de extensibilidad

Se propone mantener una única aplicación local, auditable y adaptable, con
herramientas y permisos definidos de forma explícita. La selección configurable
de proveedores de modelos locales compatibles, como Ollama además de LM Studio,
es un objetivo futuro: actualmente la conversación utiliza LM Studio y no hay
integración con Ollama. Cada integración necesitará verificación propia y deberá
conservar los controles de privacidad y autorización, sin depender de VS Code o
Codex para el uso cotidiano. Las conexiones externas serán opcionales y estarán
bajo control del usuario.

## Capacidades futuras: actualización supervisada

Todas las capacidades siguientes están pendientes y no disponibles actualmente:

- Consulta y clasificación de actualizaciones APT con evidencia de la fuente,
  antigüedad de los índices, estados parciales y limitaciones. No atribuir
  correcciones de seguridad sin evidencia suficiente.
- Selección de paquetes y exclusión temporal para una operación concreta, sin
  convertirla automáticamente en una retención persistente del sistema.
- Simulación obligatoria antes de cualquier actualización, mostrando también
  dependencias, eliminaciones y otros cambios propuestos. Simular no garantiza
  que una ejecución posterior termine correctamente.
- Ejecución únicamente con autorización explícita del usuario sobre el plan
  concreto. Los cambios del plan exigirán nueva revisión y autorización.
- Autenticación administrativa mediante mecanismos nativos del sistema, sin
  almacenar contraseñas ni conceder privilegios al modelo.
- Verificación posterior de cada operación, incluidas las fallidas o
  interrumpidas, diferenciando resultado confirmado, parcial y desconocido.
- Posible interfaz gráfica opcional, conservando la CLI y los mismos controles
  de autorización, seguridad y privacidad.
- Revisión periódica de dependencias, compatibilidad y seguridad siguiendo el
  [procedimiento manual recomendado](MANTENIMIENTO.md).

## Condiciones para avanzar

La lectura seguirá siendo el modo predeterminado. El modelo y el ejecutor
permanecerán separados; la IA no podrá suministrar comandos arbitrarios. Las
protecciones actuales no se relajarán como alternativa silenciosa ante un fallo.
Las nuevas capacidades requerirán diseño, pruebas y validación independientes
antes de documentarse como disponibles. Se minimizarán dependencias adicionales.

Las consultas externas y las modificaciones del sistema seguirán bajo control
del usuario. Esta hoja de ruta no configura automatizaciones, servicios externos
de mantenimiento ni actualizaciones automáticas.
