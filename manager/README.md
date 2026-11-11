# RuxBox+ — gestor local

Este directorio contiene el servidor y la interfaz de RuxBox+. Consulta el README del repositorio para el alcance, limitaciones y compatibilidad. La distribución portátil se prepara por separado.

El perfil antiguo usa el contrato de lectura de `public/legacy-readback.mjs`: cada apartado declara su resultado y la fecha de su última lectura verificada. `attemptedAt` identifica el intento; no acredita que se hayan obtenido datos. La autenticación por sí sola tampoco genera `capturedAt`. El servidor conserva observaciones anteriores al fallar una actualización, sin convertirlas en datos actuales ni reabrir controles de escritura.

Las pruebas con servidores sintéticos requieren `RUXBOX_TEST_TEMP`. Las pruebas del lanzador en Windows pueden usar `RUXBOX_PRIVATE_TEST_TEMP`, una carpeta de prueba con aislamiento NTFS verificable. Esta configuración no omite las comprobaciones de permisos. Las pruebas visuales escriben sus evidencias en `RUXBOX_EVIDENCE` y bloquean peticiones a los routers físicos.
