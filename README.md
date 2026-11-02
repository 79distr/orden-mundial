# ORDEN MUNDIAL — Multijugador con mundo compartido

## Qué incluye esta entrega
- Sala privada para dos cuentas, con países distintos.
- El creador inicia el mundo cuando ambos jugadores están listos.
- El estado completo de la campaña se almacena en Cloudflare KV y se comparte entre ambos clientes.
- Los guardados del juego publican cambios al mundo compartido con control de versión.
- Cada jugador confirma el próximo mes; solamente el creador de la sala ejecuta el avance cuando ambos confirmaron.
- El otro cliente recibe el nuevo estado del mundo por sincronización periódica.

## Actualización en GitHub / Cloudflare Pages
Reemplazá estos archivos en el repositorio `79distr/orden-mundial`:
- `public/index.html`
- `functions/api/[[route]].js`

Conservá el resto de la configuración. En Cloudflare Pages:
- Build command: vacío.
- Build output directory: `public`.
- Root directory: `/` o vacío.
- Binding KV: `OM_KV` apuntando al namespace existente `orden-mundial`.

**No borres ni recrees el namespace KV**: allí viven las cuentas, sesiones y salas. La actualización no requiere limpiar datos.

## Cómo jugar
1. Cada jugador entra a `https://orden-mundial.pages.dev/` y usa su propia cuenta.
2. El primero crea la sala y comparte el código.
3. El segundo se une con el código y elige otro país.
4. Ambos pulsan `Estoy listo`.
5. El creador pulsa `Iniciar mundo compartido`.
6. Dentro del juego, cada uno realiza sus decisiones y guarda; los cambios se publican al mundo común.
7. Para avanzar el mes, ambos pulsan `Confirmar próximo mes`. Cuando los dos confirmaron, el creador pulsa `Próximo mes` una segunda vez para ejecutar el turno compartido.

## Nota técnica
La sincronización comparte el estado completo del simulador, no un registro granular de cada acción. Si ambos jugadores modifican el mundo exactamente al mismo tiempo, puede aparecer un conflicto de versión: el cliente se actualiza con el último estado guardado en el servidor. Para una primera partida coordinada, conviene que cada uno haga sus decisiones y guarde antes de que el otro empiece a modificar la misma sección. El procesamiento mensual se ejecuta desde el navegador del creador y luego se distribuye el estado resultante al otro jugador.
