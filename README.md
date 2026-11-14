# RuxBox+

RuxBox+ es una aplicación portátil para Windows que permite consultar y, cuando el firmware lo admite, gestionar funciones de telefonía y red de determinados routers Livebox desde una interfaz web local. El servidor se ejecuta en tu ordenador, no en el router.

[Descargar la última versión](https://github.com/RuymanTrujillo/ruxbox-plus/releases/latest) · [Versiones publicadas](https://github.com/RuymanTrujillo/ruxbox-plus/releases) · [Comunicar un problema](https://github.com/RuymanTrujillo/ruxbox-plus/issues)

## Qué puedes hacer

| Sección | Funciones |
| --- | --- |
| **Llamadas** | Consultar el historial de llamadas entrantes, salientes y perdidas; buscar, filtrar y ordenar los registros disponibles. |
| **Bloqueos** | Ver la lista de bloqueo, añadir o retirar números exactos y simular el alcance de una regla antes de aplicarla. |
| **Telefonía** | Consultar o configurar el automarcado y realizar pruebas de timbre cuando la interfaz del router lo permita. |
| **DNS** | Consultar los servidores DNS y, en firmwares compatibles, preparar y confirmar cambios. |
| **Actividad** | Revisar las operaciones realizadas, sus resultados y los intentos que necesitan comprobación. |
| **Configuración** | Establecer la dirección local del router o detectar la puerta de enlace del equipo. |

Los avisos de llamadas se basan en **nuevos registros del historial** mientras la página está abierta; no detectan el timbrado en tiempo real.

## Compatibilidad y límites

La compatibilidad depende de la **interfaz y el firmware**, no solo del nombre comercial del router. RuxBox+ comprueba los datos que recibe antes de habilitar operaciones de escritura.

| Interfaz del router | Alcance |
| --- | --- |
| **Livebox 6 con el perfil de interfaz reconocido** | Consultas y operaciones disponibles según las comprobaciones de compatibilidad. Un cambio de estructura puede dejar funciones en modo lectura. |
| **Livebox Fibra con interfaz antigua** | Diagnóstico y determinadas consultas en modo lectura. No se habilita una gestión de bloqueos que el firmware no acredite. |
| **Otros modelos o versiones de firmware** | Compatibilidad no verificada; no se garantiza que todas las secciones funcionen. |

Los bloqueos mediante **patrones de nueve posiciones** son experimentales. El simulador muestra coincidencias previstas, pero no demuestra que el firmware las aplique correctamente ni que bloquee la llamada antes del primer timbre.

**No incluye** acceso a credenciales SIP ni gestión DynDNS. Tampoco reemplaza el firmware ni el panel oficial del router.

## Requisitos

- **Windows x64**. La distribución portátil y sus lanzadores están preparados para Windows. **Linux no está soportado actualmente**.
- Carpeta local donde el programa pueda comprobar los permisos del directorio privado `manager/data/`. La instalación se ha probado sobre **NTFS**, pero el código no exige expresamente ese sistema de archivos. Otros sistemas de archivos no están verificados.
- **Chrome, Brave o Edge** instalado para la comunicación automatizada con el router, que utiliza Chromium mediante Playwright. **Firefox puede abrir la interfaz web local, pero no sustituye a esos navegadores**; la interfaz en Firefox no tiene todavía una validación funcional completa.
- Acceso desde el ordenador a la interfaz de administración del router.

El ZIP incluye Node.js y Playwright-core. **No es necesario instalar Node.js globalmente** ni ejecutar `npm install` para utilizar la distribución portátil.

## Instalación

1. Descarga el archivo `RuxBoxPlus-*-win-x64.zip` y su correspondiente `SHA256.txt` desde la [última versión](https://github.com/RuymanTrujillo/ruxbox-plus/releases/latest).
2. Comprueba que el SHA-256 del ZIP coincide con el del archivo de verificación. En PowerShell puedes obtenerlo con:

   ```powershell
   Get-FileHash .\RuxBoxPlus-*-win-x64.zip -Algorithm SHA256
   ```

3. Extrae **todo** el contenido del ZIP en una carpeta local. No ejecutes el programa desde el archivo comprimido ni modifiques los archivos del paquete.
4. Ejecuta `VERIFICAR.cmd` y, si la comprobación termina correctamente, `INICIAR.cmd`.
5. Abre **http://127.0.0.1:8765/** en el mismo ordenador. Desde **Configuración** puedes ajustar la IP del router si la detección automática no encuentra la correcta.

Para consultar o modificar datos protegidos del router, inicia sesión desde el gestor con las credenciales de administración correspondientes. Las operaciones que alteran su configuración requieren comprobaciones y confirmación; su disponibilidad depende del firmware.

### Detener el servidor

Ejecuta **`PARAR.cmd`** desde la misma carpeta en la que instalaste RuxBox+ (disponible desde la versión 0.4.26).

La parada identifica la instancia local, rechaza el cierre cuando existe una operación activa y comprueba que el servidor haya liberado su puerto y el bloqueo de instancia. No finaliza otros procesos Node.js. Para volver a abrir el gestor, ejecuta `INICIAR.cmd`.

## Datos y seguridad

- El panel escucha únicamente en **127.0.0.1:8765**. No necesitas abrir puertos en el router ni publicar el panel en Internet.
- La contraseña de administración se mantiene en memoria durante la sesión local; no forma parte de la distribución.
- Los ajustes y recibos de operaciones se conservan en **`manager/data/`**, un directorio privado de la instalación, excluido del inventario de archivos inmutables del paquete.
- El ZIP publicado no contiene sesiones, historiales personales ni configuraciones de un router particular.

**La distribución no está firmada digitalmente.**

## Si algo falla

| Síntoma | Qué comprobar |
| --- | --- |
| `VERIFICAR.cmd` falla | Vuelve a descargar y extraer el ZIP completo. No añadas ni edites archivos dentro del paquete; la configuración se realiza desde el gestor. |
| El gestor no arranca | Comprueba que utilizas Windows x64, que hay Chrome, Brave o Edge instalado, que el puerto **8765** está libre y que los permisos de `manager/data/` se pueden verificar. Firefox por sí solo no sirve para automatizar el router. |
| No se abre la página | Utiliza `http://127.0.0.1:8765/` **desde el equipo que ejecuta RuxBox+**. |
| Una función aparece en modo lectura | La interfaz o el firmware no han superado las comprobaciones necesarias para habilitar esa operación. |
| `PARAR.cmd` no consigue detenerlo | Revisa si hay trabajo activo o un cierre pendiente. No fuerces el proceso ni elimines `instance.lock` sin comprobar antes el estado de la instancia. |

Para comunicar un fallo, abre una [incidencia en GitHub](https://github.com/RuymanTrujillo/ruxbox-plus/issues) con la versión de RuxBox+, el modelo y firmware del router, los pasos para reproducirlo y el mensaje de error. **No adjuntes contraseñas, cookies, exportaciones privadas, números de teléfono ni el contenido de `manager/data/`.**

## Código fuente y licencia

El código del servidor está en [`manager/`](manager/) y la interfaz en [`manager/public/`](manager/public/). Los binarios y dependencias necesarios para ejecutar la edición portátil se distribuyen con cada release de Windows.

El código propio se publica bajo **[GNU GPLv3](LICENSE)**. Las dependencias y recursos de terceros conservan sus propias licencias y atribuciones, detalladas en [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

RuxBox+ es un proyecto independiente, sin relación oficial ni respaldo de Orange o Jazztel.
