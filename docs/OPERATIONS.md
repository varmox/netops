# Operations (reference setup: Irrenhaus LAN)

A self-hosted control center for the home network:

- **Web UI** (Angular 21 + Clarity 18): HTTPS on 443 with a vSphere-style login page. Every device with live status, an advanced datagrid, config history with diffs, alerts, settings and embedded Grafana.
- **Watcher**: pings, TCP and HTTP checks every minute. Alerts when a device goes down, comes back or degrades.
- **Config backups**: daily, versioned (a new version only when something changed), with diffs in the UI.
  - MikroTik: `/export` over SSH, optionally a binary backup too
  - Zyxel: snapshot via its web API, with passwords redacted
- **Grafana + Prometheus**: device latency, internet reachability, backup age, MikroTik details (mktxp) and the Docker host.
- **ntfy**: every alert in the web UI (live) and on your phone.
- **SFTP**: read-only access to all stored configs, plus an inbox for uploads (for example the Zyxel's official backup file).

```
browser ──► :443 nginx (session) ┬─ /          web UI + login page   (:80 redirects to :443)
                                ├─ /api/      backend (FastAPI) ── checks, backups ──► MikroTik, Zyxel, devices
                                ├─ /grafana/  Grafana ◄── Prometheus ◄── backend /metrics, blackbox, mktxp, node-exporter
                                └─ /ntfy/     ntfy (live alerts)
phone   ──► :8090 ntfy
sftp    ──► :2222 backups (read-only) + inbox
```

## Layout

| Path | What |
|---|---|
| `config/devices.yml` | the inventory: devices, checks, backup method (no secrets) |
| `.env` | passwords and settings (copy from `.env.example`, never committed) |
| `secrets/mikrotik_id_rsa` | SSH key for the MikroTik backup user |
| `data/backups/<device>/` | config versions (`<UTC time>.rsc/.json` + `.meta.json`) |
| `data/inbox/` | SFTP uploads |
| `backend/` | FastAPI app: `jobs.py` (watcher + backups), `collectors/` (mikrotik, zyxel) |
| `frontend/` | Angular 21 + Clarity 18 app, served by nginx |
| `grafana/` | provisioned datasource, dashboards and alert rules |

## Install on the mini PC

1. Install Debian or Ubuntu Server and Docker:
   ```bash
   curl -fsSL https://get.docker.com | sh
   sudo usermod -aG docker $USER    # log out and back in
   ```
2. On the MikroTik, give the mini PC a fixed address, for example `.10`:
   ```
   /ip dhcp-server lease add address=192.168.8.10 mac-address=<mini PC MAC> comment="netops mini PC"
   ```
3. Copy this folder to the mini PC (`git clone` or `rsync`). Then:
   ```bash
   cp .env.example .env && nano .env          # passwords, Zyxel login
   cp ~/.ssh/id_rsa_mikrotik secrets/mikrotik_id_rsa && chmod 600 secrets/mikrotik_id_rsa
   mkdir -p data/backups data/inbox && sudo chown 1001:1001 data/inbox
   cp ~/.ssh/id_ed25519.pub sftp/keys/me.pub  # who may log in to SFTP
   docker compose up -d --build
   ```
4. Open `https://192.168.8.10/` and log in with `WEBUI_USER` / `WEBUI_PASSWORD`. The first start creates a
   self-signed certificate in `certs/`; put your own `netops.crt` + `netops.key` there to replace it.

## Router preparation (recommended)

**A dedicated backup user** instead of `claude`: read-only, key login.
```
/user group add name=netops-backup policy=ssh,read,test,sensitive,ftp comment="NetOps config backups"
/user add name=netops group=netops-backup password=[:rndstr length=32] address=192.168.8.10/32
/user ssh-keys import public-key-file=netops.pub user=netops    # upload netops.pub first (RSA key)
```
Then set `user: netops` for the MikroTik in `config/devices.yml`.
`sensitive` is only needed with `show_sensitive: true`, and `ftp` only for `binary: true`.

**mktxp metrics** (the "MikroTik (mktxp)" dashboard) need the RouterOS API, but only from the mini PC:
```
/user group add name=mktxp policy=api,read
/user add name=mktxp group=mktxp password=<strong password> address=192.168.8.10/32
/ip service set [find name=api and !dynamic] disabled=no address=192.168.8.10/32
```
Then `cp mktxp/mktxp.conf.example mktxp/mktxp.conf`, set the password, and run
`docker compose --profile mktxp up -d`.

## Everyday use

- **Add a device:** add it to `config/devices.yml`. The backend picks up the change at the next check round.
- **Back up now:** in the UI (device page, the Devices action bar, or Backups → "Back up now…").
- **Alerts on your phone:** install the ntfy app → add server `http://192.168.8.10:8090` → subscribe to the topic from `.env`.
- **SFTP:** `sftp -P 2222 backup@192.168.8.10`. `backups/` is read-only; uploads go into `inbox/`.
  After adding or removing a key in `sftp/keys/`, run `docker compose up -d --force-recreate sftp`: the image only
  reads keys when the container is created, not on a restart.
- **API docs:** `https://<host>/api/docs` (after logging in).
- **Update:** `git pull && docker compose up -d --build`.

## Internal registry (Harbor) and self-built images

- `harbor/install.sh`: installs Harbor (official online installer, md5-verified; Sigstore signatures are
  published too) with HTTP on `HARBOR_PORT` (8880) for the Docker host itself, data in `harbor/data`, built-in
  Trivy. Stable Harbor images are amd64-only; on an ARM Mac they run under emulation.
- `harbor/setup-project.sh`: private project `netops` with *scan on push* and *prevent vulnerable images*
  (no pulls of unscanned images or images with critical CVEs), plus a push/pull-only robot account whose
  credentials go into `.env` (single-quoted: the name contains `$`).
- `images/build.sh <name>`: builds `images/<name>` (no attestation manifests), pushes `<version>`, waits for
  Harbor's scan, fails on critical findings, then pushes `<version>-<date>` for rollback.
- `images/mktxp`: mktxp from its PyPI release on `python:3.14-alpine`, `apk upgrade`, pip removed at runtime,
  non-root. Raise `images/mktxp/VERSION` and rebuild for new releases. Build on the host that runs it
  (the image is built for that machine's architecture).

## Security

- **Sources:** CISA KEV (actively exploited) and NVD (version ranges), synced every 6 h, for the products listed
  under `software:` in `config/devices.yml`. RouterOS and Zyxel versions are read from the latest backup.
  Cloudflare's CVE blog is shown as news (Zero Wire itself has no machine-readable feed).
- **LAN scan:** nightly at `SECURITY_SCAN_TIME` (`nmap -sV` + vulners on inventory hosts and every DHCP lease).
  Cleartext management services (Telnet, FTP, TFTP, SNMP, VNC) become exposure findings.
- **Matching:** only a real NVD version range that includes the device's version counts as "confirmed".
  Entries without a usable range (old CVEs, date bounds) and unknown versions are reported only when actively
  exploited, as "check version". Findings no longer reported are resolved automatically.
- **Remediation, only after approval** (UI, or the buttons in the ntfy alert, a signed link valid 24 h):
  firewall quarantine (address list `netops-quarantine`), Wi-Fi disconnect (Wi-Fi access list), RouterOS update.
  `protected: true` devices are never quarantined. Everything goes to `data/security/audit.jsonl`.
  `SECURITY_DRY_RUN=true` logs actions without touching the router.
- Note: vulners sends the detected product/version strings (not IPs) to vulners.com for the CVE lookup.
  Banner-based hits are grouped per service and capped at medium (distributions backport fixes without
  changing the version), and skipped entirely for Linux hosts NetOps can reach over SSH.

### Linux hosts and containers

Add a host with `type: linux` (see `config/devices.d/lab.yml`). On the host:
```bash
sudo useradd -m -s /bin/bash netops
sudo install -d -m 700 -o netops -g netops ~netops/.ssh
sudo cp linux_id_ed25519.pub ~netops/.ssh/authorized_keys && sudo chown netops: ~netops/.ssh/authorized_keys
echo 'netops ALL=(root) NOPASSWD: /usr/bin/apt-get, /usr/bin/env DEBIAN_FRONTEND=noninteractive apt-get *' | sudo tee /etc/sudoers.d/netops
sudo usermod -aG docker netops        # only with docker: true (Trivy + container updates)
```
- **OS updates:** pending apt/dnf updates (security ones flagged) and a pending reboot → one finding per host,
  action *Install updates*.
- **Containers:** Trivy (`aquasec/trivy`, run on the host with its own cache volume) scans the image of every
  running container, fixable CVEs only → one finding per image, action *Update container* (`docker compose pull`
  + `up -d` for that service). Images pinned to a version only change when you raise the tag in the compose file.
- Lab: `docker compose --profile lab up -d` starts a Debian test host that talks to this machine's Docker.
  Remove `config/devices.d/lab.yml` on the real server.

## Alerts

| Source | When |
|---|---|
| Backend | device down, degraded or back up · backup failed · config changed (+/- lines) |
| Grafana | internet down (2 min) · backup older than 48 h · MikroTik CPU > 80 % or temperature > 80 °C (10 min) |

Grafana sends its alerts to `backend /api/hooks/grafana`, which turns each one into a readable ntfy message.

**Which devices page you.** A device going down only pushes a notification when it's worth waking up for. By
default only infrastructure (`protected: true` — router, modem, the box, Harbor) alerts; consumer gear like a
TV or a phone is tracked for uptime but stays silent. Override per device in `config/devices.yml`: `alert: true`
forces paging on anything, `alert: false` mutes an infrastructure device.

## Testing on a Mac (Docker Desktop)

Everything runs the same, with two differences: if the Homebrew `docker` CLI can't find `docker-credential-desktop`,
run `export PATH="/Applications/Docker.app/Contents/Resources/bin:$PATH"` first, and node-exporter then reports the
Docker Desktop VM instead of the Mac.

## Security notes

- One login (from `.env`) protects the API, Grafana and the live alert stream: nginx asks the backend
  (`auth_request`) for every request. The session is an HttpOnly, Secure, SameSite=Strict cookie signed with
  a secret in `data/.session_secret`; deleting that file logs everyone out. Logins are limited to 10 per minute.
- ntfy (8090) is open on the LAN. To lock it down: `auth-default-access: deny-all` in `ntfy/server.yml`, an ntfy user, and an `NTFY_TOKEN`.
- Zyxel snapshots redact every value whose key looks like a password, key or secret (`redact: true`).
- MikroTik exports hide secrets by default (`show_sensitive: false`).
