# Estado de la entrega pública

Fecha de revisión: 9 de noviembre de 2026.

La entrega de AsistenteLocal Python se ha incorporado a la rama `main` del repositorio público [onmyodo78/AsistenteLocal](https://github.com/onmyodo78/AsistenteLocal) mediante el commit `9070eae7040be3a961d0852d5ee25d55775738f1`.

La publicación se realizó mediante un avance rápido (*fast-forward*), sin sobrescribir el historial anterior. No se han creado etiquetas de versión ni GitHub Releases.

Este documento describe las capacidades, pruebas y limitaciones técnicas de la entrega publicada. La validación de lectura corresponde a Debian 13, con comprobaciones nativas adicionales en Fedora 45. Las operaciones administrativas APT y DNF5 mantienen las restricciones y los límites de validación indicados a continuación.

## Estado Fedora vigente

El [cierre técnico Fedora](CIERRE_TECNICO_FEDORA.md) distingue las lecturas nativas
ya comprobadas de la actualización integrada pendiente. Se corrigió en fuentes
el setopt `downloadonly` incompatible con DNF5 5.4.7.0. La comparación XDG no
elimina los cuatro avisos de alias (765 bytes de stderr); se conserva el aislamiento
y el rechazo conservador. La actualización directa funcionó según el usuario,
pero no valida el circuito de AsistenteLocal ni reconcilia su diario histórico.
`resultado_desconocido` y `no_verificable` se mantienen cuando corresponden.
Regresión Debian repetida en este cierre: 982 casos, 970 superados y 12 omitidos,
sin fallos ni errores. Sin cambios de código, configuración, helper o diario,
sin transacciones ni despliegues. Las cifras inferiores de noviembre 8 son históricas.

## Capacidades y evidencia

| Componente | Implementado | Validación de esta entrega |
| --- | --- | --- |
| Núcleo CLI independiente | Auditoría, candidatas y planificación sin modelo | Debian 13, Python 3.13; auditoría real de lectura con las siete áreas completas |
| Auditoría autónoma básica | Coordinador determinista, ampliaciones limitadas y traza autonomia_v1 | Regresión simulada y ejecución local; sin acciones administrativas |
| Presentación factual | Python conserva hechos, prioridades y desconocidos | Pruebas de independencia y conservación ante fallos del modelo |
| Conversación LM Studio | Herramientas controladas e interpretación opcional | Una interpretación real sintética, HTTP 200; LM Studio 0.4.28+2, GPT-OSS 20B |
| Proyección compacta | explicacion_compacta_v1, optativa | Validación contra traza y prueba sintética integrada; sigue desactivada por defecto |
| APT Debian | Consulta local, simulación, diagnóstico y manifiesto de descarga | Consulta y planificación de lectura reales; transacciones del helper solo simuladas |
| Ejecutor privilegiado APT | Separado, plan autorizado, verificaciones y diario | Instalación preexistente verificada en lectura; historial autenticado correcto. Sin transacciones reales |
| Fedora | Adaptadores de lectura, preparación estricta y ruta administrativa interactiva separada | Lecturas nativas y regresión previa en Fedora 45; actualización directa comunicada como exitosa. Actualización integrada sin validación completa; véase el cierre Fedora |
| Correlación CVE Debian | No implementada | No se atribuyen automáticamente CVE ni clasificación de seguridad a candidatas |
| Auditoría semanal de usuario | Informes privados y plantillas systemd optativas | Auditoría manual y verificación de sintaxis reales; ninguna unidad instalada/activada ni ejecución systemd real |
| Entrada APT independiente | mantenimiento_apt.py reutiliza CLI y helper | Lectura e historial con sudo interactivo verificados; sin transacciones reales |
| Otros proveedores y delegación general | Previstos | No implementados |

La auditoría de lectura se ejecutó sin importar el cliente conversacional. Se
bloquearon las conexiones del proceso CLI y se comprobó que dpkg y los índices
APT permanecían intactos. Esto no es una certificación de aislamiento de todos
los procesos ni de todas las configuraciones posibles.

## Pruebas reproducibles

Desde la raíz del proyecto:

```sh
TMPDIR=/tmp /usr/bin/python3 -B -W error::ResourceWarning tests/ejecutar_regresion_motor.py
TMPDIR=/tmp /usr/bin/python3 -B -W error::ResourceWarning tests/ejecutar_regresion_completa.py
```

La validación de la copia exacta para publicación obtuvo 874 casos superados en
el corredor de referencia y **982 casos, 970 superados y 12
omitidos** en el completo, sin fallos ni errores. Ambos corredores desactivan integraciones
reales; no se activan pruebas administrativas, LM Studio ni consultas externas.
Las cifras de 786/787 y 883 pertenecen a fases anteriores, no al corredor actual.
La validación del conjunto exacto para publicación se detalla en
[INVENTARIO_PUBLICACION.md](INVENTARIO_PUBLICACION.md).

La comprobación real adicional usó una única solicitud sintética: HTTP 200 en
19,907 segundos, con hechos originales intactos y presentación factual anterior
a la explicación. No se enviaron inventarios ni la traza real del equipo al modelo.
No constituye una garantía de latencia: el contexto y la carga pueden provocar timeout.

## Límites pendientes

- La explicación es texto del modelo, no evidencia; las validaciones no prueban
  exhaustivamente su exactitud semántica. Las recomendaciones no autorizan operaciones.
- La proyección anterior sigue siendo predeterminada; existe un caso parcial
  conocido con memoria nula que requiere corrección separada. El informe factual
  ya presentado no depende del éxito de esa continuación.
- Llamadas ordinarias: 45 s; continuaciones explicativas explícitas sin herramientas:
  90 s, recortados por el deadline global de 120 s. Sin reintentos automáticos.
  Cerrar la conexión no garantiza detener la generación en LM Studio.
- Los índices locales no acreditan frescura ni ausencia de vulnerabilidades.
  Los recuentos de índices necesarios/opcionales/no aplicables no clasifican paquetes.
- La simulación no garantiza éxito de instalación. No se valida el helper por
  haber realizado mantenimiento manual del sistema fuera de él.
- La actualización integrada Fedora, otras versiones de Python, otros modelos y
  otros motores necesitan validación propia. No hay soporte Ollama verificado.

## Publicación y privacidad

El manifiesto [PUBLICACION_ARCHIVOS.txt](PUBLICACION_ARCHIVOS.txt) identifica los archivos seleccionados para la entrega pública. La revisión de privacidad y la validación del conjunto publicado se documentan en [INVENTARIO_PUBLICACION.md](INVENTARIO_PUBLICACION.md).

Los registros reales, los respaldos y la documentación privada de mantenimiento permanecen excluidos del repositorio. Los informes factuales pueden contener información sensible del sistema y no deben publicarse sin revisión específica.

Comprobaciones reales posteriores y limitaciones: [VALIDACION_INTEGRACION_DEBIAN.md](VALIDACION_INTEGRACION_DEBIAN.md).

## Cierre documental previo al reinicio (histórico, 8 de noviembre)

Validación cerrada el 8 de noviembre de 2026: **871 pruebas superadas, 12 omitidas**
(883 casos). Auditoría semanal manual completa en siete áreas, JSON validado,
informes privados y unidades verificadas sin advertencias. Helper preexistente
comprobado e historial consultado con autenticación sudo interactiva, sin transacciones.

Se conserva una selección de los informes en almacenamiento privado persistente
fuera del repositorio y de /tmp, con hashes verificados, directorios 0700 y archivos
0600. Se omiten las unidades con rutas personales y otros artefactos reproducibles.
Los informes factuales completos siguen siendo privados, no anónimos. No se incluyen
en Git, en el manifiesto ni en los paquetes públicos.

Límites conservados: systemd sin activación ni ejecución real del temporizador;
transacción APT y persistencia SQLite administrativa sin probar realmente;
correlación CVE Debian pendiente y Fedora sin validación real. La consulta de
historial no creó un diario ni autoriza futuras operaciones.
