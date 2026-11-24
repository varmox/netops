# Lab target for the Linux providers: a Debian host with SSH, sudo for the package manager only, and a docker CLI.
# Only started with `docker compose --profile lab up -d`. Not for production.
FROM debian:12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server sudo docker.io ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd \
 && useradd -m -s /bin/bash netops \
 && printf 'netops ALL=(root) NOPASSWD: /usr/bin/apt-get, /usr/bin/env DEBIAN_FRONTEND=noninteractive apt-get *\n' > /etc/sudoers.d/netops \
 && chmod 440 /etc/sudoers.d/netops \
 && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
COPY entrypoint.sh /entrypoint.sh
CMD ["/entrypoint.sh"]
