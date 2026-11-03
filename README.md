# ORDEN MUNDIAL — Empresas multinacionales y regímenes monetarios

## Instalación en Cloudflare Pages
1. Hacé una copia de seguridad de la versión actual del repositorio.
2. Reemplazá `public/index.html` por el incluido en este paquete.
3. No borres ni recrees `OM_KV`, ni modifiques las Functions/API o los archivos del coordinador multijugador.
4. Hacé commit/push y esperá el despliegue de Cloudflare Pages.
5. Abrí el juego y recargá con Ctrl+F5.

La actualización conserva los sistemas de guardado del juego y agrega los datos de acuerdos corporativos al objeto de bolsas ya persistido (`omCapitalMarkets`) y los regímenes monetarios al estado de divisas (`omFX`). Aun así, hacé una copia de seguridad de tu partida antes de actualizar.

## Funciones añadidas
- Contratos entre empresas de países diferentes: logística, extracción, tecnología, suministro y empresas conjuntas.
- Ofertas de IA, aceptación/rechazo y contratos autónomos entre empresas controladas por la IA.
- Propuestas y fusiones internacionales; se consolidan capitalización, acciones y participaciones.
- Impacto de contratos y fusiones sobre beneficios y cotizaciones bursátiles.
- Decisión nacional de mantener/recuperar moneda propia, adoptar divisa extranjera o moneda común de un bloque.
- Consecuencias simuladas sobre inflación, tasas y valor bursátil según la estabilidad de la moneda elegida.
- Decisiones monetarias autónomas ocasionales de países controlados por la IA.

Validación realizada: comprobación sintáctica de los 21 bloques JavaScript. No equivale a una prueba funcional completa en navegador ni a una prueba de partidas reales.
