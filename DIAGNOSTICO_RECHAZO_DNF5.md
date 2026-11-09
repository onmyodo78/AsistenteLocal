# Diagnóstico del rechazo de operaciones DNF5

Informe histórico conservado porque explica el contenedor modular opaco que
mantiene bloqueada la preparación estricta. No describe por sí solo la ruta
interactiva posterior. Estado vigente: [cierre Fedora](CIERRE_TECNICO_FEDORA.md).
Se omiten rutas y huellas del inventario de laboratorio por privacidad; no se
han sustituido por observaciones inventadas ni se han alterado los registros originales.

Validación del 9 de noviembre de 2026 en Debian 13 y Fedora 45, con Python
3.15.0 y python3-libdnf5/libdnf5/dnf5 5.4.6.0-3.fc45 en Fedora.

## Resultado observado

La consulta real mediante `python3 -B cli.py --formato json preparar-dnf5`
identificó el contenedor de **módulos**, no una acción RPM desconocida:

```json
{
  "estado": "no_verificable",
  "acciones_estado": "no_comprobada",
  "errores": ["acciones_dnf5_no_admitidas"],
  "diagnostico": [{
    "motivo": "modulo",
    "representacion": "no_iterable",
    "cantidad": null,
    "codigos": [],
    "verdad_contenedor": true,
    "truncado": false,
    "codigos_truncados": false
  }],
  "ejecucion_habilitada": false
}
```

El contrato y su huella se validaron. Código CLI 3; stderr vacío; duración
1,140 s. `comprobar_ejecutable` rechazó con `plan_no_verificable`.

Esto **no demuestra que la transacción contenga módulos**: no se pudo recorrer
el objeto devuelto por `get_transaction_modules()`. Su valor booleano verdadero
activaba el rechazo anterior, pero no acredita que tenga elementos. Cantidad
desconocida no se convierte en cero. Tampoco se ha enumerado aquí una transacción
RPM completa: la inspección se detiene en el contenedor rechazado.

La revisión de wrappers instalados mostró `VectorBaseTransactionGroup`,
`VectorBaseTransactionEnvironment` y `VectorBaseTransactionPackage`, pero no
`VectorBaseTransactionModule` ni `TransactionModule`. El getter de módulos existe
y delega al binding nativo; la existencia del método no garantiza un resultado
iterable desde Python. Esto concuerda con la incompatibilidad observada.

## Cambios implementados

Solo cambian `dnf5_preparacion.py` y `tests/test_dnf5_preparacion.py` en ambos
sistemas. La evidencia nueva usa el contrato de preparación v2 con diagnóstico
cerrado; se conserva lectura compatible de v1 y no cambia el contrato APT.

Se revisaron todas las condiciones anteriores de `acciones_dnf5_no_admitidas`:

- Colecciones de grupos, entornos y módulos: motivos separados, conteos acotados
  y muestra limitada de códigos numéricos cuando la API los proporciona.
- Código de acción RPM sin correspondencia en la lista admitida: rechazo separado.
- Validación de acción RPM o motivo no representable: motivos distintos mediante
  una excepción interna que transporta solo diagnóstico validable.
- Cualquier rechazo residual con ese código: `operacion_no_representable`, sin
  inventar una categoría o copiar el texto de una excepción nativa.

El diagnóstico admite como máximo ocho entradas y ocho códigos distintos por
entrada, con conteos limitados por MAX_FILAS y marcas de truncamiento. Nunca
incluye nombres, ID, URL, mensajes nativos, repr de objetos o direcciones de
punteros. Los fallos de iteración se representan con cantidad desconocida,
`no_iterable` o `lectura_no_disponible`, conservando el rechazo original.

No se amplían acciones permitidas. La decisión booleana original se conserva
para diagnosticar su efecto sin aceptar contenedores antes rechazados. Todos
los resultados siguen globalmente no verificables y no ejecutables. El helper
administrativo, autorización, aislamiento, transporte y configuración no cambian.

## Pruebas y traslado

Se añadieron diez pruebas, incluyendo categorías individuales y simultáneas,
acción desconocida, motivo RPM inválido, rechazo residual, límites, datos sensibles,
vector vacío con booleano verdadero, contenedor opaco, fallo durante iteración y
compatibilidad del contrato. Las pruebas específicas DNF5 son ahora 30.

Regresión final:

| Entorno | Pruebas | Fallos | Errores | Omisiones |
| --- | ---: | ---: | ---: | ---: |
| Debian 13 | 926 | 0 | 0 | 12 |
| Fedora 45 | 926 | 0 | 0 | 14 |

Los dos archivos fueron respaldados antes de cada traslado. El respaldo previo
a la versión final permanece en almacenamiento local excluido de la publicación;
se omite su ruta privada.

SHA-256 finales, verificados al transferir y antes de la consulta real:

```text
17517e1436b6dac8458a097e4a6058f873b77a963e61f979bfa22d4715f526c9  dnf5_preparacion.py
6cde75380e3368999aa70babe9ac6acde069569a83b409f18861a3c412ded35d  tests/test_dnf5_preparacion.py
```

El primer intento real de esta fase expuso un defecto del diagnóstico inicial:
intentar recorrer un contenedor opaco produjo `api_dnf5_no_admitida`. Se corrigió
y probó el diagnóstico. El segundo intento se realizó solo después de recibir
autorización expresa adicional del usuario; produjo el resultado detallado arriba.
No se hicieron más preparaciones reales.

Antes y después de ambos intentos se obtuvo el mismo inventario RPM, comprobado
por recuento y SHA-256. Se omiten sus valores por privacidad; la conclusión de
igualdad permanece y la evidencia original se conserva localmente.
No cambiaron los metadatos inspeccionados en /etc/dnf, /etc/yum.repos.d,
/var/cache/libdnf5, /var/cache/dnf y las rutas .cache/libdnf5, .cache/dnf y
.cache/dnf5 del usuario. No hubo errores de cobertura. Esta comparación de
metadatos complementa el aislamiento; no es una certificación de integridad de
todos los archivos del sistema. No se leyeron contenidos de configuración para
mostrar ni registrar credenciales.

## Propuesta para resolverlo

1. Verificar en la API/bindings de la versión instalada una vía pública y fiable
   para inspeccionar el vector de módulos o acreditar que está vacío. Un booleano
   verdadero sobre un objeto opaco no sirve para comprobar su contenido.
2. Si falta el wrapper, estudiar una corrección upstream del binding o un puente
   nativo mínimo que exponga conteo y acciones tipadas de la misma Transaction.
   No se propone instalarlo ni compilarlo en esta fase. No reinterpretar punteros
   C++ con ctypes ni usar el formato experimental serialize como sustituto.
3. Solo cuando exista evidencia fiable de ausencia de operaciones modulares,
   continuar la inspección RPM. Si hay módulos, representarlos fielmente o seguir
   rechazándolos. No deducir ausencia a partir de la distribución o repositorios.
4. Mantener pendientes retenciones, avisos de seguridad, metadatos/configuración,
   firmas y hashes RPM, y continuidad del bloqueo antes de plantear autorización.

En aquella fase no se implementó autorización ni ejecución administrativa DNF5. No se
usó sudo, no se instalaron dependencias ni se descargaron o modificaron paquetes.
