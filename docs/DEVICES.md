# Devices

What NetOps can do depends on what a device lets it do. Three levels:

- **Managed:** credentials in the vault; inventory, config backup, update check, update, health.
- **Observed:** no management access; discovered, fingerprinted, watched (traffic, exposure, CVEs by
  model/firmware), can be quarantined at the router or kicked from Wi-Fi.
- **Infrastructure:** the router/firewall NetOps uses for topology, quarantine and traffic data.

| Device | Level | Access | Backup | Updates | Notes |
|---|---|---|---|---|---|
| MikroTik RouterOS | infrastructure, managed | SSH (RSA key), API | `/export` | RouterOS update | quarantine, Wi-Fi kick, DHCP, LLDP, metrics (mktxp) — working |
| OPNsense | infrastructure, managed | REST API key | config.xml | firmware API | aliases for quarantine, flows (NetFlow) — phase 3 |
| pfSense | infrastructure, managed | SSH / REST package | config.xml | `pfSense-upgrade` | phase 3 |
| UniFi (Network app) | infrastructure, managed | controller API | site backup | device firmware | client list, ports, block client — phase 3 |
| Zyxel (VMG/EX/DX/GM) | managed | web API (ZCFG), SSH | settings snapshot | manual (vendor) | working |
| Netgear, TP-Link, Fritz!Box | observed (managed later) | web/TR-064 where documented | — | manual | after v1 |
| Linux servers / Raspberry Pis | managed | SSH key, sudo for the package manager | /etc snapshot | apt/dnf | Trivy for Docker hosts — working |
| Windows clients and servers | managed | OpenSSH or WinRM (HTTPS) | — | winget, Windows Update | phase 3 |
| BusyBox / embedded Linux (NAS, cameras) | observed or managed (SSH) | SSH read-only | — | manual | flags Telnet/FTP, default credentials |
| Sonos, Apple TV, Swisscom TV, Zattoo boxes, smart TVs | observed | none | — | vendor | fingerprint via mDNS/SSDP, IoT network, botnet watch |
| Cameras, doorbells, robot vacuums, smart plugs | observed | none | — | vendor | high-risk class: isolated network recommended |

Default-credential checks are only run against devices you have added and only with a short built-in
list of vendor defaults, never brute force.

## Facts used by the added features

In a device's `facts:` block:

- `eol_product` / `eol_cycle` — an [endoflife.date](https://endoflife.date) product id and release cycle (e.g. `ubuntu` / `24.04`, `sonos` / `1`), for the firmware/OS end-of-life check.
- `tls_port` — an extra TLS port to check for certificates, beyond any `https`/`tls` health check.
