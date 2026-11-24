# NetOps (working title)

**One hardened box that knows, watches and protects everything on your home network.**

NetOps runs on a Raspberry Pi 5 (or any small arm64/amd64 Linux host). It discovers what is on your
network, draws a map of it, keeps an eye on every device, backs up configs, finds vulnerable or
misbehaving devices (outdated firmware, botnet traffic), and helps you fix them: update, isolate,
or cut them off. It is meant to be the one system on your network that is hardened to the core.

> **Status:** pre-release. The reference deployment runs a home network with a MikroTik router,
> a Zyxel VDSL modem, IoT devices and a Docker host. See the [roadmap](docs/ROADMAP.md).

## What it does

| | |
|---|---|
| **Discover & map** | Finds devices (ARP, DHCP, mDNS, SSDP, active fingerprinting), classifies them (router, firewall, server, PC, TV box, speaker, camera, …) and draws a network map with physical ports and who talks to whom. |
| **Watch** | Health checks, metrics (router CPU, Wi-Fi signal, WAN throughput), alerts to the web UI and your phone (ntfy). |
| **Manage** | Store credentials per device in an encrypted vault, then back up configs, check for updates and apply them, with drivers for Linux, Windows, OPNsense, pfSense, UniFi, MikroTik, Zyxel and more. |
| **Protect** | CVE matching (CISA KEV, NVD), container scanning (Trivy), exposure checks (Telnet, FTP, UPnP …), botnet indicators (threat-intel feeds, DNS and traffic anomalies), and one-click remediation: update, quarantine, Wi-Fi kick. |
| **Assist** | Optional AI assistant (Claude or Gemini, with your own API key) to explain findings and guide setup. Nothing leaves the box unless you turn it on. |

## Security first

NetOps holds the keys to your network, so it is built to the published baselines:

- **Login:** passwords hashed with Argon2id, MFA with TOTP or passkeys (WebAuthn), lockout and rate
  limits, server-side sessions — NIST SP 800-63B AAL2.
- **Vault:** device credentials are encrypted with a key derived from an unlock passphrase; after a reboot
  nothing is readable until you unlock it (a stolen Pi or SD card reveals nothing).
- **Host:** Ubuntu Server 24.04 LTS hardened to the **DISA STIG** and **CIS** benchmarks with an Ansible
  playbook, verified with OpenSCAP.
- **Containers:** non-root, read-only, no capabilities unless needed, per **NIST SP 800-190** and the
  **CIS Docker Benchmark**.
- **Supply chain:** images built in GitHub Actions, scanned (Trivy gate), signed (cosign) and published to
  GHCR. The box checks the signature before every update and rolls back if the new version is unhealthy.

Details: [security model](docs/SECURITY-MODEL.md) · [hardening](docs/HARDENING.md) ·
[reporting a vulnerability](SECURITY.md)

## Documentation

| | |
|---|---|
| [Architecture](docs/ARCHITECTURE.md) | Components, data flow, how drivers and remediation work |
| [Host setup](docs/HOST.md) | Raspberry Pi 5 install, the tools on the host, external backup disk |
| [Hardening](docs/HARDENING.md) | Host and container baselines mapped to DISA STIG, CIS, NIST |
| [Security model](docs/SECURITY-MODEL.md) | Threat model, authentication, vault, update chain |
| [Devices](docs/DEVICES.md) | Supported device types and what NetOps can do with each |
| [Features](docs/FEATURES.md) | DNS filtering, certificates, end-of-life, exposure, honeypot, timeline, more |
| [Roadmap](docs/ROADMAP.md) | Phases to v1.0 |
| [Operations](docs/OPERATIONS.md) | The reference deployment (day-to-day commands) |

## License

[AGPL-3.0](LICENSE). If you run a modified version as a service for others, you must publish your changes.
