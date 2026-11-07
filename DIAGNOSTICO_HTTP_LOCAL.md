# Diagnóstico de HTTP local — segunda fase

Se activa un HTTPHandler privado por petición con una subclase de
http.client.HTTPConnection (lmstudio_http.py). Se conserva urllib para construir
la petición, procesar la respuesta y producir HTTPError/URLError. No hay parches
globales, dependencias nuevas, sondeos ni reintentos. No se han realizado
peticiones reales a LM Studio.

## Seguridad y compatibilidad

Solo se acepta POST a http://127.0.0.1:1234/v1/chat/completions, con comprobación
adicional del host y puerto antes de conectar. El socket IPv4 conecta directamente
a esa dirección numérica, sin DNS ni túneles. El opener privado desactiva proxies
y rechaza redirecciones, conservando su HTTPError sin leer el cuerpo. Es una
restricción deliberada frente a los manejadores ambientales de urlopen: un proxy
o una redirección no forman parte del endpoint autorizado. Se mantiene HTTP/1.1,
Connection: close, Content-Type y el JSON existente, así como las validaciones,
el límite de 1 MiB, tratamiento de errores y cierre de recursos de urllib.
No se cambia Debian, LM Studio, Landlock ni seccomp.

## Fases observables

- preparacion: construcción del JSON y petición.
- conexion_y_cabeceras: campo anterior conservado; ahora solo mide la entrada
  al manejador antes de iniciar TCP, no es un agregado de las fases nuevas.
- conexion_tcp: connect(); retornar confirma conexión TCP establecida.
- envio_peticion: request() después de conectar explícitamente; retornar confirma
  que el transporte local aceptó el envío, no que LM Studio lo haya procesado.
- espera_cabeceras: getresponse(), incluida recepción y análisis de estado y
  cabeceras. Retornar confirma que se procesaron; no distingue cola y generación.
- lectura_cuerpo, cierre y validacion conservan su significado.

fase_error identifica la operación activa. Un valor null en duración significa
que la fase no llegó a iniciarse. Una duración registrada de una fase fallida
no implica que se completara. Un TimeoutError nunca demuestra un fallo del modelo.
No se conocen los bytes parciales internos de cabeceras; bytes_cuerpo solo cuenta
el cuerpo leído y bytes_peticion solo el JSON preparado.

## Plazos y privacidad

El vencimiento se fija antes de abrir: mínimo entre plazo global y reloj actual
más MAX_MODEL_SECONDS (45). Conexión, cada sendall y cada recv_into descuentan
ese mismo vencimiento. SocketIO de CPython usa recv_into también para leer las
cabeceras: recibirlas lentamente no renueva el presupuesto. El cuerpo usa el
mismo vencimiento, comprobado antes y después de cada read1. No hay un segundo
presupuesto de 45 segundos al comenzar el cuerpo. El plazo global también se
comprueba durante la validación, como antes. Los límites de socket no constituyen
una garantía de planificación de tiempo real del sistema operativo.

Se conservan tipo_error y tipo_error_sistema y la lista blanca doble del emisor.
No se registra texto de excepciones, URLs, cabeceras, mensajes, auditorías ni
contenido HTTP. Los campos permitidos de tokens y finish_reason no se amplían.
PermissionError no identifica por sí solo a Landlock o seccomp.

## Validación

```sh
PYTHONPATH=tests ASISTENTE_PRUEBAS_REALES=0 python3 -B -W error::ResourceWarning -m unittest test_lmstudio_http test_lmstudio_diagnostico_http test_continuacion_auditoria test_lmstudio_comunicacion test_entorno test_infraestructura_integracion test_finalizacion_general test_estabilizacion_debian test_auditoria_debian test_auditoria_seguridad.Auditoria test_interfaces_red test_memoria_verificada test_backend_seguridad test_errores test_resultado_verificado test_finalizacion_debian test_captura_conversacional -q
```

255 pruebas simuladas superadas, sin fallos, errores ni omisiones. Incluyen
éxito, timeout y errores de sistema en TCP/envío/cabeceras, errores y límites de
lectura, cierre, validación, privacidad, presupuesto compartido, recepción con
plazo agotado, HTTPError, proxies ambientales y rechazo de destinos y redirecciones.
Los puntos de simulación anteriores pasan de urlopen a abrir_http_local; las
pruebas nuevas ejercitan el manejador real con socket simulado. No se ejecutan
integraciones reales. La causa concreta del timeout queda pendiente de reproducir:

```sh
python3 -B AsistenteLocal.py
```

Los registros LMSTUDIO_METRICAS de stderr permitirán localizar la fase de la
segunda petición de auditoria_seguridad, sin atribuir su causa al modelo.
