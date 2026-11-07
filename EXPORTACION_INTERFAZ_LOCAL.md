# Preparación local de exportaciones — fase 5D

El bucle de entrada humana del modo conversacional reconoce exactamente
`:exportar` después de quitar espacios exteriores. Lo intercepta antes de llamar
a `preguntar()`. No es una herramienta ni se envía al modelo. Texto del modelo,
resultados y nombres de funciones nunca se despachan como comandos locales.

`exportacion_interfaz.InterfazExportacion(coleccion)` mantiene un controlador de
exportación inicialmente desactivado. `preparar_interactiva()`:

1. Revoca una preparación anterior y exige stdin interactivo (`isatty`).
2. Consulta registros saneados existentes; no ejecuta diagnósticos.
3. Solicita ids separados por comas, formato `md` o `csv` y ruta absoluta explícita.
4. Genera el contenido en memoria y muestra vista previa saneada y el destino
   introducido por el humano, escapado para terminal. La ruta no forma parte del
   informe, la vista estructurada, el prompt ni los errores.
5. Exige escribir exactamente `AUTORIZAR`; no acepta sí, manual, valores vacíos
   ni respuestas ambiguas. La selección no equivale a consentimiento.
6. Conserva privadamente el identificador y token del controlador. Informa
   «Exportación autorizada temporalmente en memoria. Archivo no publicado».

`cancelar`, vacío, EOF o interrupción cancelan el flujo sin consumir permisos ni
escribir. Entrada no interactiva se rechaza. Una selección inválida o contrato no
admitido termina la preparación con mensaje fijo, sin trazas ni rutas privadas.
No hay reintentos automáticos. Para cambiar registros, formato o destino se inicia
otra preparación: todos los permisos anteriores se revocan y se exige confirmar
la nueva vista. La interfaz no llama a `consumir()` ni importa el escritor.

`cerrar()` revoca autorizaciones y elimina preparaciones de memoria; `main()` lo
llama al terminar, junto con el cierre de la colección. Las autorizaciones siguen
las reglas del controlador (cinco minutos, contenido/formato/destino específicos,
un solo uso). No se muestran tokens. La interfaz no autentica personas: la futura
capa de publicación deberá seguir consumiendo el permiso en el controlador.

La fecha de preparación se obtiene del reloj UTC local. Las fechas de observación
solo proceden de los registros seleccionados, y no se inventan. Una colección
vacía o caducada no se completa con nuevas adquisiciones.

No se comprueban existencia, enlaces o permisos del destino durante esta fase:
solo las reglas léxicas del controlador. No se crean archivos ni directorios.
La revisión del destino es una interacción local explícita; no se registran rutas
en logs. JSON y SQLite quedan fuera de esta interfaz. Los modos verificados y
sus códigos, las 14 herramientas y sus restricciones permanecen sin cambios.
La integración del escritor sigue pendiente de autorización independiente.
