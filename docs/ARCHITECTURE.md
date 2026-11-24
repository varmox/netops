# Architecture

```
                      ┌──────────────────────── NetOps host (Pi 5, hardened Ubuntu) ─────────────────────────┐
 browser ── 443 ──►   │ web (nginx, static UI) ──► backend (FastAPI) ──► SQLite: accounts, sessions, vault,    │
 phone  ── 8090 ──►   │ ntfy                        │   │   │            inventory, findings, audit           │
 sftp   ── 2222 ──►   │ sftp (read-only backups)    │   │   └─► Prometheus ◄── mktxp, blackbox, node-exporter│
                      │                             │   └─► restic ──► /mnt/netops-backup (LUKS)              │
                      │ updater (host, systemd) ── cosign verify ──► GHCR                                     │
                      └─────────────────────────────┼─────────────────────────────────────────────────────────┘
                                                    ▼
                              drivers: SSH / REST / web APIs ──► routers, firewalls, servers, clients
                              scanners: nmap, Trivy (on Docker hosts), passive discovery
```

## Components

| Component | Role |
|---|---|
| `frontend/` | Angular + Clarity UI, served as static files by nginx. nginx terminates TLS, rate-limits, sets security headers and asks the backend (`auth_request`) whether a session is valid. |
| `backend/` | FastAPI. Accounts and MFA, vault, inventory, health checks, drivers, collectors (backups), security (feeds, scans, findings, remediation), metrics proxy, alert relay. |
| Prometheus + exporters | Time series: device checks, router metrics (mktxp), internet probes (blackbox), host (node-exporter). |
| ntfy | Push alerts to the UI and phones. |
| sftp | Read-only access to stored configs; inbox for manual uploads. |
| updater | Host service: signed updates of the whole stack with health checks and rollback. |

## Backend modules

| Module | |
|---|---|
| `auth.py` | sessions, login, MFA (TOTP, WebAuthn), recovery codes, lockout, first-run setup |
| `vault.py` | encrypted credential store, unlock/lock |
| `inventory.py` | devices (YAML today, database in phase 2) |
| `jobs.py` | health watcher, backup scheduler |
| `collectors/` | config backups per device type |
| `security.py`, `linux.py`, `remediation.py` | CVE feeds, scans, findings, fixes |
| `metrics.py` | read-only Prometheus proxy for the UI |
| `drivers/` (phase 3) | one module per device family: `inventory()`, `backup()`, `updates()`, `update()`, `quarantine()` |

## Principles

- **Nothing changes on the network without approval.** Every action that changes a device goes through
  `remediation.execute`, needs a logged-in user (or a signed, expiring link) and is audited.
- **Protected devices** (router, modem, the NetOps host) are never cut off.
- **Credentials stay in the vault**; drivers receive them only for the duration of a call.
- **Read-only by default**: discovery and scans observe; only explicit actions write.
