# RuxBox+ 0.4.25

Administrador local e independiente para determinados routers Livebox. Proyecto no oficial de Orange ni de Jazztel, distribuido bajo GNU GPLv3 (GPL-3.0-only).

## Funciones

- Llamadas: historial, búsqueda y revisión.
- Bloqueos: gestión de números exactos y simulación de reglas. El bloqueo por patrón de nueve posiciones es experimental.
- DNS: lecturas y operaciones únicamente cuando el firmware y el controlador lo permiten.
- Actividad y Ayuda: seguimiento y explicación de operaciones.

**DynDNS no está implementado ni se muestra en la interfaz.** La compatibilidad y las capacidades varían por firmware. No se promete acceso a configuraciones SIP ni a funciones del operador que no estén acreditadas.

## Descargar e iniciar

Descarga el ZIP Windows x64 de la [versión 0.4.25](https://github.com/RuymanTrujillo/ruxbox-plus/releases/tag/v0.4.25), comprueba su archivo SHA-256 y ejecútalo descomprimido en una carpeta local NTFS con permisos propios. Ejecuta primero VERIFICAR.cmd y después INICIAR.cmd. El gestor utiliza Node.js incluido en el paquete y se abre exclusivamente en 127.0.0.1:8765.

El ZIP no está firmado digitalmente por su autor. El hash comprueba integridad y no sustituye una firma de autenticidad. Solo introduce tu contraseña de administración en el gestor local.

## Privacidad

La distribución **no incluye datos de un router, credenciales, cookies, sesiones, registros de llamadas ni configuraciones de usuario**. Esos datos se crean y conservan exclusivamente en el almacenamiento privado de cada instalación.

El repositorio se ha creado de nuevo a partir del código de 0.4.25 sin incorporar commits, etiquetas, ramas ni pruebas históricas que contengan números o IP de entornos de desarrollo. Las pruebas sintéticas internas no se publican para minimizar datos de ejemplo innecesarios. El código fuente ejecutable, los manifiestos de origen y la licencia se incluyen.

## Licencias y responsabilidades

El código propio se distribuye bajo GNU GPLv3; las dependencias incluidas mantienen sus licencias originales. Consulta LICENSE y THIRD_PARTY_NOTICES.md.

RuxBox+ no es un producto oficial del operador. Las operaciones sobre el router deben comprobarse de acuerdo con el modelo y firmware autorizados; no se garantizan funciones no verificadas.

## Apagado local

RuxBox+ 0.4.26 incorpora PARAR.cmd en el paquete Windows, con parada autenticada local y bloqueo durante operaciones activas. No se fuerzan procesos externos.
