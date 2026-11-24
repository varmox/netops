FROM python:3.14-slim

# iputils-ping for the ICMP checks (Docker grants NET_RAW by default), nmap (+ vulners script) for the LAN scan.
RUN apt-get update \
 && apt-get upgrade -y \
 && apt-get install -y --no-install-recommends iputils-ping nmap \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /srv
COPY requirements.txt .
# pip isn't needed at runtime, and it vendors its own (often outdated) urllib3, msgpack, setuptools.
RUN pip install --no-cache-dir -r requirements.txt \
 && pip uninstall -y pip setuptools wheel 2>/dev/null || true
COPY app ./app

# Non-root at runtime (NIST SP 800-190): /data and /config are mounted; the root filesystem is read-only.
RUN useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin netops
USER 10001
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 HOME=/tmp
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
