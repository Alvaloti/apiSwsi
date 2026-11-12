# API SWSI

## Primer inicio

1. Instala las dependencias con `npm ci`.
2. Copia `.env.example` como `.env`.
3. Configura MongoDB, JWT, CORS y correo.
4. Reemplaza `BOOTSTRAP_ADMIN_PASSWORD` por una contraseña propia con mayúscula, minúscula, número y carácter especial.
5. Inicia la API con `npm start`.

Si todavía no existe un administrador activo, la API crea automáticamente:

- El rol `admin` con todos los permisos.
- El área indicada en `BOOTSTRAP_ADMIN_AREA`.
- El usuario definido por las variables `BOOTSTRAP_ADMIN_*`.

El proceso es idempotente: en los reinicios posteriores no duplica ni sobrescribe un administrador existente. Después del primer acceso se recomienda cambiar la contraseña desde el perfil o desactivar `BOOTSTRAP_ADMIN_ENABLED`.

Nunca agregues el archivo `.env` al repositorio ni compartas su contraseña real.
