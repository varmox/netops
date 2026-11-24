# Roadmap to v1.0

v1.0 covers all four areas below. They are built in this order because each one depends on the one
before; every phase ends with tests on the reference network before the next starts.

## Already working (pre-release)

- Web UI (Angular + Clarity) with dashboard, devices (advanced datagrid), backups, alerts, metrics
  (VCF Operations-style, ECharts), settings.
- Health checks, MikroTik and Zyxel config backups with history and diffs, ntfy alerts.
- Security: CISA KEV + NVD matching, nmap/vulners LAN scan, exposure findings, Linux updates over SSH,
  Trivy for running containers, remediation (quarantine, Wi-Fi kick, RouterOS update, container update)
  with one-click approval and audit log.

## Phase 1 — Core and hardening

Tests: `backend/tests/test_auth_vault.py` (45 checks); browser E2E with a virtual passkey authenticator (11 steps).


- [x] Accounts in a database; Argon2id password hashing; first-run setup with a one-time setup code.
- [x] MFA: TOTP and passkeys (WebAuthn); recovery codes; MFA required for every account.
- [x] Server-side sessions (idle and absolute timeout), account lockout, CSRF protection, strict CSP.
- [x] Vault: device credentials encrypted (libsodium, Argon2id-derived key), unlocked after each boot.
- [x] Hardened containers: non-root backend, read-only, dropped capabilities, resource limits.
- [ ] Network segmentation between containers; sftp container hardening.
- [x] Host: Ansible playbook for Ubuntu Server 24.04 (DISA STIG via SSG remediation + CIS report), OpenSCAP report written for the UI. See `host/ansible`.
- [ ] Encrypted backups (restic) to an external, LUKS-encrypted disk; restore tested.
- [ ] Supply chain: GitHub Actions multi-arch build (arm64/amd64), Trivy gate, cosign signing, GHCR;
      weekly rebuild; on-box updater that verifies signatures, health-checks and rolls back.
- [ ] Remove Harbor and Grafana from the default stack (optional add-ons).

## Phase 2 — Discovery and network map

- [ ] Passive discovery: ARP/DHCP leases, mDNS, SSDP/UPnP, NetBIOS; active: nmap fingerprinting.
- [x] "New device" alerts and a per-device + network change timeline (feature 10).
- [ ] Device classification (vendor from MAC OUI, services, mDNS/SSDP types) incl. TV boxes, speakers,
      cameras.
- [x] Topology from the MikroTik bridge-host + ARP tables → which device is on which physical port.
- [ ] Topology for more vendors (LLDP/CDP, UniFi, OPNsense APIs).
- [x] Traffic graph: who talks to whom (router conntrack), internal and external, on the Map page.
- [x] Interactive map in the UI: physical layer (router → port → device) and traffic layer (conntrack).

## Phase 3 — Device drivers

- [ ] Per-device credentials from the vault, set after discovery.
- [ ] Drivers: Linux (SSH), Windows (WinRM/OpenSSH, winget/Windows Update), OPNsense (API),
      pfSense (SSH/API), UniFi (controller API), MikroTik (SSH/API), Zyxel (web API), generic
      BusyBox/embedded (SSH, read-only checks).
- [ ] Per driver: inventory, config backup, update check, update, health; passive-only profile for
      devices without management access (Sonos, Apple TV, Swisscom TV, Zattoo, smart TVs, cameras).

## Phase 4 — Botnet detection and AI assistant

- [x] DNS filtering + per-device query log via AdGuard Home (feature 1) — the input for the feeds below.
- [ ] Threat-intel feeds: abuse.ch (Feodo, URLhaus, ThreatFox), Spamhaus DROP; matched against DNS
      queries and flows.
- [ ] DNS logging on the resolver; IoT behaviour baselines (new destinations, port scans, high fan-out,
      traffic at odd hours) → findings.
- [x] Remediation for IoT: isolate to an isolated network, Wi-Fi kick, DNS-block of C2 domains (feature 2).
- [ ] Optional AI assistant (Claude / Gemini, user's own API key): setup guidance, explaining findings,
      proposing remediation. Opt-in, redacts secrets, never executes actions without approval.

## Added along the way

A central **Features** page toggles every capability on/off, and each feature's prebuilt UI (if any) is linked there rather than standing alone. Health reports availability, MTTR and p5/p50/p95. Extra features built on top of the core (see [FEATURES.md](FEATURES.md)): DNS filtering (1), certificate watch (3), firmware/OS end-of-life (4), internet-exposure monitoring (6), honeypot (8), opt-in default-password audit (5), change timeline (10), weekly report (9), isolate/DNS-block remediation (2) and a family view (12).

## After v1.0

- Multi-site, HA, a downloadable Pi image, more drivers (Netgear, TP-Link Omada, Fritz!Box, Synology).
