FROM node:24-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
# Cache mount + retries: a flaky connection shouldn't mean downloading everything again.
RUN --mount=type=cache,target=/root/.npm \
    npm ci --no-audit --no-fund --fetch-retries=5 --fetch-retry-mintimeout=20000 --fetch-retry-maxtimeout=120000
COPY . .
RUN npx ng build --configuration production

FROM nginx:1.30-alpine
# openssl for the self-signed certificate created on first start (see docker/10-certs.sh).
RUN apk add --no-cache openssl && mkdir -p /etc/nginx/certs
COPY docker/10-certs.sh /docker-entrypoint.d/10-certs.sh
COPY --from=build /app/dist/frontend/browser /usr/share/nginx/html
