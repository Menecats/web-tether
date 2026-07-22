FROM denoland/deno:2.9.3

WORKDIR /app

# The bundled application script produced by `deno task compile`
ARG APP_JS
COPY ${APP_JS} /app/web-tether.js

ENTRYPOINT ["deno", "run", "-A", "/app/web-tether.js"]
