# Colección temporal de resultados saneados — fase 5B

`sesion_resultados.ColeccionSesion` es independiente. No importa SQLite,
controladores de persistencia, escritor de exportación ni la aplicación principal.
No conserva resultados originales, comandos, conversaciones o mensajes del modelo.

API: `insertar_verificado`, `insertar_saneado`, `consultar`, `seleccionar`,
`estado`, `vaciar` y `cerrar`. Las consultas y selecciones devuelven copias con
id interno, registro histórico validado y observación opcional verificada por el
llamador. Los ids no son identificadores del sistema. No se reutilizan al vaciar.

Límites: 100 registros, 1 MiB de instantáneas serializadas UTF-8 en total, más los
límites del contrato histórico por registro. Estos son límites de carga útil,
no una cota exacta de RSS: hay sobrecarga de Python y copias temporales acotadas.
Las inserciones que superan el límite se rechazan sin expulsar datos anteriores.

Vida máxima fija: 1.800 segundos desde crear la colección, medida con reloj
monotónico. Consultar o vaciar no renueva su vida. Al acceder después del plazo,
retroceder el reloj o detectar un valor inválido, se eliminan las referencias y
la colección se cierra. No hay limpieza en segundo plano: una colección inactiva
puede conservar referencias hasta el siguiente acceso o su destrucción. No se
promete borrado forense de memoria.

Las fechas de observación no se inventan. Por defecto son ausentes. Solo se
acepta la declaración explícita `fecha_utc`/`verificada=True`, comprobada con las
reglas del contrato de exportación; no certifica un reloj ni la verdad de la
procedencia. La inserción no se presenta como fecha de observación.

## Punto de integración pendiente

Actualmente `control_verificado.ejecutar_verificada()` hace:

1. `resultado = adquirir(deadline)`;
2. `comprobar_plazo(deadline)`;
3. `texto, presentado = presentar(resultado)`;
4. calcula el código, imprime y devuelve ese código.

La captura futura debe situarse entre 2 y 3 y usar `insertar_verificado()` sobre
ese mismo resultado, sin invocar de nuevo `adquirir()`. Solo se retendría su copia
saneada; una incidencia de colección no debe alterar los hechos del diagnóstico.

Los cinco modos verificados son interfaces, memoria, conexiones, puertos y
servicios. Producen un `ResultadoVerificado` antes de presentar. `main()` retorna
el código de esos modos y `sys.exit(main())` termina el proceso. No hay sesión
reutilizable al terminar. Para permitir una exportación posterior debe autorizarse
un ciclo de vida explícito dentro del mismo proceso o una interacción anterior a
su terminación. No se cambia ese comportamiento en esta fase.

`insertar_saneado()` también conserva contratos históricos ya validados, incluida
la separación dpkg/APT, pero no conecta auditorías conversacionales ni añade un
modo verificado de seguridad. No se reconstruyen métricas de textos ni se hacen
adquisiciones para completar registros. SQLite, exportación y escritor permanecen
sin conexión. No se incorpora ningún comando de terminal.

## Captura conversacional — fase 5C

El modo conversacional crea ahora una `ColeccionSesion` en `main()` después de
las salidas anticipadas de los modos verificados. La asocia mediante ContextVar
al ciclo interactivo y la cierra y retira del contexto en un bloque `finally`.
La llamada existente `preguntar(texto)` se conserva; las pruebas y otros llamadores
pueden inyectar opcionalmente `coleccion` sin crear una sesión global persistente.

Dentro de `preguntar()`, inmediatamente después de una ejecución autorizada de
`ejecutar_consulta()` y antes de `ajustar()`, presentar o enviar texto a LM Studio,
`capturar_resultado_saneado()` adapta exclusivamente `ResultadoAuditoria`,
`ResultadoDebian` e interfaces `ResultadoInterfaces` con distribución admitida.
La colección vuelve a validar el registro saneado. No hay fecha de observación
inventada ni extracción desde texto. No se retienen los originales en la colección.

Fallos de contrato, colección llena o cerrada/caducada omiten únicamente la
captura, sin variar herramientas, mensajes del modelo ni adquisiciones. Una vez
caducada, no se crea automáticamente otra colección. Las interfaces requieren
identificación Fedora o Debian 13 mediante el detector existente; distribuciones
no admitidas o estructuras no reconocidas no se almacenan. No se añade acceso a
la colección al registro de herramientas ni al prompt. Los registros capturados
permanecen aunque falle una interpretación posterior, hasta cierre o caducidad.

El punto de integración de los modos verificados descrito arriba continúa
pendiente: no se ha cambiado su terminación. Tampoco se añaden comandos de
sesión, controlador de exportación, escritor, SQLite ni publicación de informes.
