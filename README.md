# Vigía del registro de transparencia de PulseID

Cada hora, GitHub Actions ejecuta `vigia-registro.mjs` contra https://pulseids.com y comprueba que el registro de comprobantes **solo crece**: no encoge, no cambia de raíz con el mismo tamaño, la prueba de consistencia (RFC 9162) desde la cabecera anterior se sostiene y la clave de firma no cambia sin transición.

- `estado/vigia-registro.json`: la memoria (claves fijadas y últimas cabeceras, cada una firmada por PulseID). Cada commit es una comprobación en orden; el `git log` es el historial.
- Si algo no cuadra: se abre una incidencia con la etiqueta `alerta` y **la memoria no se actualiza** (lo visto antes queda como prueba).
- Sin poder comprobar (red, servicio): aviso, no alerta.
- `vigia-registro.mjs` es copia fijada del que publica PulseID en `/vigia-registro.mjs`; se revisa a mano antes de actualizarla.

Límite: quien lo ejecuta es el mismo titular. Para independencia real, haz un fork y que lo ejecute otra cuenta.
