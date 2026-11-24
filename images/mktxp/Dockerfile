# mktxp rebuilt from its PyPI release on a current Alpine, with all OS packages upgraded and without pip at
# runtime (pip vendors its own urllib3, certifi, msgpack, which is what Trivy flagged in the upstream image).
ARG PYTHON_IMAGE=python:3.14-alpine
FROM ${PYTHON_IMAGE}
ARG MKTXP_VERSION=2.1.0

LABEL org.opencontainers.image.source="https://github.com/akpw/mktxp" \
      org.opencontainers.image.description="mktxp ${MKTXP_VERSION}, rebuilt by Irrenhaus NetOps with current packages" \
      org.opencontainers.image.licenses="GPL-2.0-or-later"

RUN apk upgrade --no-cache \
 && adduser -u 1000 -D mktxp \
 && mkdir -p /etc/mktxp && chown mktxp:mktxp /etc/mktxp \
 && pip install --no-cache-dir "mktxp==${MKTXP_VERSION}" \
 && (pip uninstall -y pip setuptools wheel || true)

EXPOSE 49090
USER mktxp
ENV PYTHONUNBUFFERED=1 XDG_CONFIG_HOME=/etc
CMD ["mktxp", "export"]
