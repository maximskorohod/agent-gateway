# syntax=docker/dockerfile:1

# Stage 1: production dependencies. better-sqlite3 and argon2 are compiled here
# when no prebuilt binary matches the musl (Alpine) runtime.
FROM node:22-alpine AS deps
RUN apk add --no-cache python3 make g++
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

# Stage 2: runtime image. No compilers, no source tree beyond the app, no secrets.
FROM node:22-alpine
ENV NODE_ENV=production \
    GW_DATA_DIR=/data \
    GW_PORT=8080
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./
COPY bin ./bin
COPY src ./src
COPY assets ./assets
COPY providers.yaml ./

# Non-root user. /data is created here so a new named volume inherits its owner.
RUN addgroup -S gateway \
 && adduser -S -D -H -s /sbin/nologin -G gateway gateway \
 && mkdir -p /data \
 && chown gateway:gateway /data

USER gateway
EXPOSE 8080

# Checks /healthz from inside the container (no curl or wget needed in the image).
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:' + (process.env.GW_PORT || 8080) + '/healthz').then((r) => process.exit(r.ok ? 0 : 1), () => process.exit(1))"

CMD ["node", "bin/gateway.js", "start"]
