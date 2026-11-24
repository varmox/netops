#!/bin/sh
# Creates a self-signed certificate on first start, unless one was put into ./certs (netops.crt + netops.key).
set -e
CERTS=/etc/nginx/certs
if [ ! -s "$CERTS/netops.crt" ] || [ ! -s "$CERTS/netops.key" ]; then
  echo "netops: no certificate found, creating a self-signed one for ${NETOPS_HOSTNAME:-netops.lan}"
  openssl req -x509 -newkey rsa:2048 -nodes -days 1825 \
    -keyout "$CERTS/netops.key" -out "$CERTS/netops.crt" \
    -subj "/CN=${NETOPS_HOSTNAME:-netops.lan}" \
    -addext "subjectAltName=DNS:${NETOPS_HOSTNAME:-netops.lan},DNS:localhost,IP:127.0.0.1${NETOPS_IP:+,IP:$NETOPS_IP}" \
    2>/dev/null
  chmod 600 "$CERTS/netops.key"
fi
