#!/bin/sh
# Authorize NetOps' key and give the user access to the (mounted) docker socket, then run sshd.
set -e
install -d -m 700 -o netops -g netops /home/netops/.ssh
install -m 600 -o netops -g netops /lab-key.pub /home/netops/.ssh/authorized_keys
[ -S /var/run/docker.sock ] && chmod 666 /var/run/docker.sock
exec /usr/sbin/sshd -D -e
