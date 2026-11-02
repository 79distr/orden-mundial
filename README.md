# ORDEN MUNDIAL — Simulador geopolítico

Juego de estrategia por turnos (un turno = un mes). Con cuenta de usuario, la partida se guarda en la nube y la retomás desde cualquier dispositivo.

```
public/                    sitio estático (index.html, _headers)
functions/api/[[route]].js backend: cuentas, sesión y partidas (Cloudflare Pages Functions + KV)
```

Si abrís `public/index.html` directamente (sin servidor), el juego funciona igual en **modo local**: sin cuenta y con guardado en el navegador.

## Publicar en Cloudflare Pages

1. Subí este repositorio a GitHub.
2. **Crear el almacenamiento:** en el panel de Cloudflare, sección **KV**, creá un namespace (por ejemplo `orden-mundial`).
3. **Crear el proyecto:** *Workers & Pages → Create → Pages → Connect to Git* y elegí el repositorio.
   - Framework preset: **None**
   - Build command: *(vacío)*
   - **Build output directory: `public`**
4. **Vincular el KV:** en el proyecto, *Settings → Bindings → Add → KV namespace*.
   - Variable name: **`OM_KV`** (exactamente así)
   - KV namespace: el que creaste.
5. **Código de invitación (recomendado):** *Settings → Variables and Secrets → Add*, tipo *Secret*, nombre **`REGISTER_CODE`** y un valor que solo vos sepas.
6. **Volvé a desplegar** (*Deployments → Retry/Redeploy*): los bindings y variables recién aplican a un deploy nuevo.
7. Abrí el sitio, tocá **Crear cuenta** e ingresá usuario, contraseña (mínimo 8 caracteres) y el código. Desde ese momento el registro queda cerrado: solo entra esa cuenta.

Después, cada `git push` publica solo. El dominio propio se agrega en *Custom domains*.

> Los nombres exactos de los menús del panel de Cloudflare pueden cambiar con el tiempo; lo importante es el binding `OM_KV` y el directorio `public`.

## Cómo se guarda la partida

- Al entrar se carga la partida de tu cuenta; si es una cuenta nueva se crea la primera.
- Se sube sola cada ~90 segundos **si hubo cambios**, y también al pasar la pestaña a segundo plano. El botón **💾 Guardar** sube al instante. El estado se ve arriba (`☁ Guardado · hora`).
- Si cerrás la pestaña con cambios sin subir, el navegador te avisa.
- Si abrís la partida en dos dispositivos y guardás en ambos, el segundo recibe un aviso de conflicto y elige qué versión conservar.
- Se conserva automáticamente **un respaldo** de la versión anterior (botón **⟲ Respaldo**).
- **⬇ Copia / ⬆ Importar** siguen sirviendo como copia de seguridad en archivo.

El plan gratuito de KV limita las escrituras diarias (a la fecha, 1.000 por día; verificalo en la página de precios de Cloudflare). El guardado automático está espaciado para quedar muy por debajo de ese límite en una sesión normal de juego.

## Seguridad

- Contraseñas con PBKDF2-SHA256 (100.000 iteraciones) y sal aleatoria; nunca se guardan en claro.
- Sesión en cookie `HttpOnly`, `Secure` y `SameSite=Strict` (30 días); el servidor guarda solo el hash del token.
- Bloqueo de 15 minutos tras 8 intentos fallidos desde la misma IP.
- Las escrituras solo se aceptan desde el mismo sitio (defensa contra CSRF).
- Encabezados `Content-Security-Policy`, `X-Frame-Options` y similares en `public/_headers`.
- El login protege **las partidas guardadas**; el HTML del juego en sí es público.

## Olvidé la contraseña

En el panel de Cloudflare abrí el namespace KV y borrá las claves `u:TU_USUARIO` y `meta:users`. Volvé a crear la cuenta con el mismo nombre de usuario: la partida (`save:TU_USUARIO`) se conserva.

## Probar en tu computadora

```bash
npx wrangler pages dev public --kv=OM_KV
```
