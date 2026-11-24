# Added features

Everything NetOps does is a **toggleable feature** managed from one place in the main UI — the **Features**
page (`/features`). Each feature has an on/off switch (persisted in `data/features.json`, effective without a
restart: schedulers check their flag each round and the honeypot's listeners start/stop on toggle). There are
no standalone UIs: where a feature ships its own prebuilt web UI (AdGuard, Grafana), it's **linked from its
card on the Features page**, and its data is pulled into the main UI.

The health/latency feature also reports **availability, MTTR, MTBF and p5/p50/p95 latency** per device
(device page → Reliability tab): downtime is tracked as incidents by the health watcher, and the latency
percentiles come from Prometheus.

These extend the core (health, backups, alerts, metrics, security scanning) toward the "single hardened
box that watches the home network" goal. All of them reuse the existing patterns: findings/alerts go to
ntfy, credentials come from the vault, state is small JSON under `data/`, and acting on anything needs an
admin session plus the `X-NetOps` header.

| # | Feature | Page | Backend | Enable |
|---|---------|------|---------|--------|
| 1 | DNS filtering + per-device query log | DNS | `dns.py` | optional `adguard` container (`--profile dns`) |
| 3 | TLS certificate watch | Posture | `certs.py` | automatic (any device with an https/tls check) |
| 4 | Firmware / OS end-of-life | Posture | `lifecycle.py` | set `eol_product` / `eol_cycle` in a device's facts |
| 6 | Internet exposure (port forwards, UPnP) | Posture | `exposure.py` | automatic (reads the MikroTik) |
| 8 | Honeypot / canary | Posture | `honeypot.py` | `HONEYPOT_ENABLED=true` (default) |
| 5 | Default-password audit | Posture | `credcheck.py` | `CREDCHECK_ENABLED=true` + confirm per run |
| 10 | Change timeline | Timeline, per device | `timeline.py` | automatic |
| 9 | Weekly report | Dashboard card | `report.py` | automatic; `REPORT_DAY` / `REPORT_TIME` |
| 2 | Isolate / DNS-block remediation | Security actions | `remediation.py` | automatic (dry-run honours `SECURITY_DRY_RUN`) |
| 12 | Family view | Family view | `features_api.py` | automatic |

## 1 · DNS filtering
AdGuard Home becomes the LAN resolver (ad/tracker/malware block lists) and keeps a per-client query log.
NetOps reads its API and maps each client IP to a device. Start it with `docker compose --profile dns up -d`,
finish its first-run setup at `http://<host>:3000`, put the admin login in `.env`
(`ADGUARD_USER`/`ADGUARD_PASSWORD`), and point your DHCP's DNS at the box. The query log is the input for
botnet detection (phase 4): a device querying a domain on a malware list is a finding on its own.

## 3 · Certificates
For every device with an `https`/`tls` check NetOps completes a TLS handshake, reads the certificate with
`cryptography`, and warns `CERT_WARN_DAYS` (21) before expiry, on obsolete TLS (1.0/1.1), and when a
certificate changes. Nothing leaves the box.

## 4 · End-of-life
Looks up only the product *names* in your inventory against endoflife.date (cached a week), then maps the
result to each device's version. EOL devices get no more security updates and are the usual botnet recruits,
so they raise an alert.

## 6 · Internet exposure
Reads the MikroTik's own config — port forwards, UPnP state, every UPnP mapping a device opened itself, and
WAN-facing input rules. A device opening its own hole via UPnP is the dangerous case and alerts immediately.

## 8 · Honeypot
Listens on Telnet/SMB/RDP/ADB ports the appliance doesn't really offer. Anything on the LAN that connects is
misconfigured or hostile, so it's logged and the first hit per source alerts. The listeners never offer a
usable service. (The ports are internal by default; publish them in compose to make the canary reachable
across the LAN.)

## 5 · Default-password audit
A defensive posture check for your own LAN: tries a short list of *documented* factory logins (admin/admin,
root/root, …) over SSH, Telnet and HTTP Basic and reports which devices still accept them — the Mirai vector.
It changes nothing. Guard rails: off unless `CREDCHECK_ENABLED=true`, a confirm flag per run, private
(RFC1918) targets only, a hard cap, short timeouts, one probe per credential, stop at the first hit per host,
and every run in the audit log.

## 10 · Timeline
Merges events NetOps already records — config backups (with diffstat), findings and their actions,
certificate changes, exposure, end-of-life and honeypot hits — into one list, network-wide and per device.

## 9 · Weekly report
A digest (open findings, actions applied, new devices, down/backup-failing, certs expiring, EOL, honeypot,
exposure, and the OpenSCAP compliance score if the host playbook wrote one), pushed to ntfy weekly and shown
on the dashboard.

## 2 · Isolate / DNS-block
Two remediation actions beside the existing quarantine: **isolate** a device from the rest of the LAN while
keeping its internet access (a MikroTik address-list used by forward-drop rules, the gateway excepted) — the
right response to a suspect IoT device — and **block a domain** network-wide via AdGuard. Both honour
`SECURITY_DRY_RUN`.

## 12 · Family view
A plain, read-only "is everything OK?" page: a green/amber banner, how many devices are online, and a tile
per device. No technical detail.

## Network map (phase 2)
An interactive topology on the Map page: **router → physical port → device**, with an Internet node.
Built, most-authoritative first, from the inventory, the MikroTik's DHCP leases (via mktxp in Prometheus,
no vault needed) and — when the vault is unlocked — the router's bridge-host and ARP tables, which give
the physical port each device sits on. Unknown devices (a lease with no inventory entry) are flagged,
with a best-effort vendor from the MAC OUI. Drawn with ECharts' graph series (what netjsongraph.js wraps,
so no new dependency); click a known device to open it. Rebuilds on a timer and on demand.

**Traffic layer** — a second view on the Map page (*Physical* / *Traffic* switch): who talks to whom, aggregated from the router's connection tracking (`/ip firewall connection`). Device→device edges for internal chatter, device→Internet for external, arrows for direction and thickness by bytes, plus a "top talkers to the internet" table with each device's heaviest destinations. IPv4 LAN only; IPv6 flows are skipped.

## RF optimizer (Wi-Fi)

**Phase 1 (live now)** — a read-only **Wi-Fi** page that reads the MikroTik's wifiwave2 state over the
existing vault-gated SSH and shows it plainly: each radio's band, channel, width, DFS state, tx-power and
client count; and every associated client with its band, PHY generation (Wi-Fi 4/5/6), signal (as a bar),
Tx/Rx PHY rate and automatically-flagged issues — *5 GHz-capable but sitting on 2.4 GHz*, *weak signal*,
*legacy (airtime-expensive) device*, *low PHY rate for its signal*. Band-level findings (2.4 GHz running
40 MHz, 5 GHz on a DFS channel, clients that belong on 5 GHz) and a 0–100 health score sit on top. No
router writes — opt-in, off by default, gated on the vault being unlocked.

**Visuals (live now)** — a neighbour scan (`Scan neighbours`; briefly hops each radio across channels)
discovers the surrounding networks and feeds three named chart pairs: a WiFi-analyzer **spectrum** view
(one hump per network, centred on its channel, as wide as its width, taller = stronger, yours bold), a
**networks-per-channel** occupancy bar chart, and the planner's congestion ranking (below).

**Phase 2 — channel planner (live now)** — for each band the page ranks the channels this router could
use and recommends the clearest. The cost model is a signal-weighted spectral overlap against the scanned
neighbours (a strong near network on an overlapping channel costs more than a weak distant one), with a
preference for non-DFS 5 GHz. Each band shows *current → recommended*, a plain-English reason, and a
congestion bar chart (recommended in green, current outlined). Applying is still a manual step — the page
prints the exact `ssh mikrotik '…'` command and its rollback — because the dashboard can't write Wi-Fi
settings itself yet.

**Planned:** Prometheus export + Grafana trends + alerts, one-click apply through the remediation
approval/dry-run/rollback path, and a band-steering advisor with before/after simulation.
