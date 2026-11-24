"""Remediation actions, run only after someone approves them (web UI, or a signed link from an ntfy alert).

  quarantine       MikroTik firewall: the host's routed and internet traffic is dropped (address list).
  wifi-disconnect  MikroTik Wi-Fi access list: the client is kicked and can't reconnect.
  update-routeros  install the newest RouterOS on the MikroTik (it reboots).
  acknowledge / resolve   bookkeeping only.

Devices marked `protected: true` in devices.yml (router, modem, the NetOps host) are never quarantined.
Every action is appended to data/security/audit.jsonl. SECURITY_DRY_RUN=true logs actions without running them.
"""
import base64
import json
import os
import re
import time

import asyncssh
import httpx

from . import auth, inventory, security, vault
from .collectors.mikrotik import _ALGS

DRY_RUN = os.environ.get("SECURITY_DRY_RUN", "false").lower() == "true"
TOKEN_HOURS = 24
LIST = "netops-quarantine"
ISO_LIST = "netops-isolated"          # feature 2: LAN-isolated, internet still allowed
RFC1918 = "netops-rfc1918"            # the three private ranges, as a MikroTik address list
AUDIT = security.SEC_DIR / "audit.jsonl"

LABELS = {
    "quarantine": "Quarantine (block all)",
    "isolate": "Isolate from LAN",
    "wifi-disconnect": "Kick from Wi-Fi",
    "block-dns": "Block domain (DNS)",
    "update-routeros": "Update RouterOS",
    "apply-updates": "Install updates",
    "update-container": "Update container",
    "acknowledge": "Acknowledge",
    "resolve": "Mark resolved",
}


# ---------------------------------------------------------------- helpers

def _router():
    dev = next((d for d in inventory.load() if d.type == "mikrotik" and d.backup), None)
    if not dev:
        raise RuntimeError("no MikroTik with SSH credentials in devices.yml")
    return dev


def _protected_hosts() -> set[str]:
    return {d.host for d in inventory.load() if d.protected}


async def _routeros(commands: str) -> str:
    dev = _router()
    key = asyncssh.import_private_key(vault.secret_or_file(dev.backup, "key_vault", "key"))
    async with asyncssh.connect(dev.host, port=int(dev.backup.get("port", 22)), username=dev.backup["user"],
                                client_keys=[key], known_hosts=None, server_host_key_algs=_ALGS,
                                signature_algs=_ALGS, connect_timeout=15) as conn:
        r = await conn.run(commands, check=True, timeout=120)
        return r.stdout


async def lease_info(ip: str) -> dict:
    """MAC and whether the host is a Wi-Fi client, from mktxp metrics in Prometheus."""
    out = {"mac": None, "wireless": False}
    url = os.environ.get("PROMETHEUS_URL", "http://prometheus:9090") + "/api/v1/query"
    async with httpx.AsyncClient(timeout=10) as c:
        leases = (await c.get(url, params={"query": 'mktxp_dhcp_lease_info{address="%s"}' % ip})).json()["data"]["result"]
        if leases:
            out["mac"] = leases[0]["metric"].get("mac_address")
        if out["mac"]:
            wifi = (await c.get(url, params={"query": 'mktxp_wlan_clients_signal_strength{mac_address="%s"}' % out["mac"]})).json()
            out["wireless"] = bool(wifi["data"]["result"])
    return out


def _audit(entry: dict) -> None:
    security.SEC_DIR.mkdir(parents=True, exist_ok=True)
    with AUDIT.open("a") as f:
        f.write(json.dumps({"time": time.time(), "dry_run": DRY_RUN, **entry}) + "\n")


def audit_log(limit: int = 100) -> list[dict]:
    if not AUDIT.is_file():
        return []
    return [json.loads(line) for line in AUDIT.read_text().splitlines()[-limit:]][::-1]


# ---------------------------------------------------------------- what can be done

def proposals(f: dict) -> list[dict]:
    """Actions that make sense for a finding (shown in the UI and as ntfy buttons)."""
    acts = []
    dev = inventory.get(f["device"]) if f.get("device") else None
    if dev and dev.type == "mikrotik":
        acts.append({"action": "update-routeros", "label": LABELS["update-routeros"],
                     "description": "Installs the newest RouterOS; the router reboots (about 2 minutes offline)."})
    # Provider-specific fixes the finding carries itself (Linux updates, container updates).
    acts += [{k: v for k, v in r.items() if k != "params"} for r in f.get("remedy", [])]
    # Container-image and OS-update findings are fixed by updating, not by cutting off the whole host.
    host_level = not ({"trivy", "updates"} & set(f.get("sources", [])))
    if host_level and f["host"] not in _protected_hosts() and f.get("status") not in ("quarantined",):
        acts.append({"action": "isolate", "label": LABELS["isolate"],
                     "description": "Blocks the device from the rest of the LAN but leaves internet access "
                                    "(an isolated network). Good for a suspect IoT device. Reversible."})
        acts.append({"action": "quarantine", "label": LABELS["quarantine"],
                     "description": "Blocks the device's internet and routed traffic on the MikroTik. Reversible."})
        acts.append({"action": "wifi-disconnect", "label": LABELS["wifi-disconnect"],
                     "description": "Wi-Fi clients only: disconnects the device and blocks it from rejoining. Reversible."})
    return acts


def action_token(finding_id: str, action: str) -> str:
    payload = "%s|%s|%d" % (finding_id, action, int(time.time()) + TOKEN_HOURS * 3600)
    raw = "%s|%s" % (payload, auth._sign(payload))
    return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")


def verify_token(token: str) -> tuple[str, str]:
    try:
        raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)).decode()
        fid, action, expiry, sig = raw.rsplit("|", 3)
    except Exception:
        raise PermissionError("malformed link")
    if not auth.hmac.compare_digest(sig, auth._sign("%s|%s|%s" % (fid, action, expiry))):
        raise PermissionError("invalid link")
    if int(expiry) < time.time():
        raise PermissionError("link expired")
    return fid, action


# ---------------------------------------------------------------- doing it

async def quarantine(ip: str, reason: str) -> str:
    if ip in _protected_hosts():
        raise PermissionError("%s is protected and is never quarantined" % ip)
    cmd = (
        # The two drop rules are created once and sit at the top of the forward chain.
        ':if ([:len [/ip firewall filter find where comment="netops: quarantine out"]] = 0) do={'
        '/ip firewall filter add chain=forward src-address-list=%(l)s action=drop comment="netops: quarantine out" place-before=0}\n'
        ':if ([:len [/ip firewall filter find where comment="netops: quarantine in"]] = 0) do={'
        '/ip firewall filter add chain=forward dst-address-list=%(l)s action=drop comment="netops: quarantine in" place-before=0}\n'
        ':if ([:len [/ip firewall address-list find where list=%(l)s address=%(ip)s]] = 0) do={'
        '/ip firewall address-list add list=%(l)s address=%(ip)s comment="netops: %(why)s"}\n'
        '/ip firewall connection remove [find where src-address~"^%(ip)s:"]'
    ) % {"l": LIST, "ip": ip, "why": re.sub(r'["\\$\n]', "", reason)[:60]}
    if not DRY_RUN:
        await _routeros(cmd)
    return "quarantined %s (routed and internet traffic dropped)" % ip


async def isolate(ip: str, reason: str) -> str:
    """Isolated network: the device keeps internet access but can't reach other LAN hosts (nor they it),
    except the router itself (for DHCP/DNS). Good for a suspect IoT device you don't want to cut off fully."""
    if ip in _protected_hosts():
        raise PermissionError("%s is protected and is never isolated" % ip)
    gw = _router().host
    cmd = (
        # the private ranges as a reusable list
        ':foreach r in={"10.0.0.0/8";"172.16.0.0/12";"192.168.0.0/16"} do={'
        ':if ([:len [/ip firewall address-list find where list=%(rfc)s address=$r]] = 0) do={'
        '/ip firewall address-list add list=%(rfc)s address=$r comment="netops"}}\n'
        # allow the device <-> router (so DHCP/DNS keep working), placed above the isolate drops
        ':if ([:len [/ip firewall filter find where comment="netops: isolate gw"]] = 0) do={'
        '/ip firewall filter add chain=forward src-address-list=%(iso)s dst-address=%(gw)s action=accept comment="netops: isolate gw" place-before=0}\n'
        ':if ([:len [/ip firewall filter find where comment="netops: isolate out"]] = 0) do={'
        '/ip firewall filter add chain=forward src-address-list=%(iso)s dst-address-list=%(rfc)s action=drop comment="netops: isolate out" place-before=1}\n'
        ':if ([:len [/ip firewall filter find where comment="netops: isolate in"]] = 0) do={'
        '/ip firewall filter add chain=forward src-address-list=%(rfc)s dst-address-list=%(iso)s action=drop comment="netops: isolate in" place-before=1}\n'
        ':if ([:len [/ip firewall address-list find where list=%(iso)s address=%(ip)s]] = 0) do={'
        '/ip firewall address-list add list=%(iso)s address=%(ip)s comment="netops: %(why)s"}\n'
        '/ip firewall connection remove [find where src-address~"^%(ip)s:"]'
    ) % {"iso": ISO_LIST, "rfc": RFC1918, "gw": gw, "ip": ip, "why": re.sub(r'["\\$\n]', "", reason)[:60]}
    if not DRY_RUN:
        await _routeros(cmd)
    return "isolated %s from the LAN (internet still allowed)" % ip


async def release(ip: str) -> str:
    cmd = ('/ip firewall address-list remove [find where list=%s address=%s]\n'
           '/ip firewall address-list remove [find where list=%s address=%s]') % (LIST, ip, ISO_LIST, ip)
    if not DRY_RUN:
        await _routeros(cmd)
    _audit({"action": "release", "host": ip})
    return "released %s" % ip


async def block_dns(domain: str, device: str | None) -> str:
    """Block a domain network-wide via AdGuard Home (feature 1) — e.g. a C2 host a device is contacting."""
    from . import dns
    result = "would block %s via AdGuard" % domain if DRY_RUN else await dns.block_domain(domain)
    _audit({"action": "block-dns", "domain": domain, "device": device})
    return result


async def wifi_disconnect(ip: str, reason: str) -> str:
    if ip in _protected_hosts():
        raise PermissionError("%s is protected" % ip)
    info = await lease_info(ip)
    if not info["mac"] or not info["wireless"]:
        raise RuntimeError("%s is not a Wi-Fi client of the MikroTik" % ip)
    mac = info["mac"]
    cmd = ('/interface wifi access-list add mac-address=%(m)s action=reject comment="netops: %(why)s" place-before=0\n'
           '/interface wifi registration-table remove [find where mac-address=%(m)s]') % {
        "m": mac, "why": re.sub(r'["\\$\n]', "", reason)[:60]}
    if not DRY_RUN:
        await _routeros(cmd)
    return "disconnected %s (%s) from Wi-Fi and blocked it" % (ip, mac)


async def wifi_allow(mac: str) -> str:
    if not re.fullmatch(r"[0-9A-Fa-f:]{17}", mac):
        raise ValueError("bad MAC")
    if not DRY_RUN:
        await _routeros('/interface wifi access-list remove [find where mac-address=%s and comment~"^netops:"]' % mac)
    _audit({"action": "wifi-allow", "mac": mac})
    return "allowed %s on Wi-Fi again" % mac


async def update_routeros() -> str:
    check = ('/system package update check-for-updates once\n:delay 6s\n'
             ':put [/system package update get status]\n:put [/system package update get latest-version]')
    out = await _routeros(check)
    if "New version" not in out:
        return "RouterOS is up to date (%s)" % out.strip().replace("\n", " ")
    if not DRY_RUN:
        await _routeros("/system package update install")   # downloads, then reboots
    return "installing RouterOS %s; the router reboots" % out.strip().splitlines()[-1]


async def execute(finding_id: str, action: str, by: str) -> str:
    findings = security.load()
    f = findings.get(finding_id)
    if not f:
        raise KeyError(finding_id)
    reason = "%s %s" % (f["cve"], f.get("device_name") or f["host"])
    if action == "quarantine":
        result, status = await quarantine(f["host"], reason), "quarantined"
    elif action == "isolate":
        result, status = await isolate(f["host"], reason), "quarantined"
    elif action == "wifi-disconnect":
        result, status = await wifi_disconnect(f["host"], reason), "quarantined"
    elif action == "update-routeros":
        result, status = await update_routeros(), "remediating"
    elif action in ("apply-updates", "update-container"):
        from . import linux
        remedy = next((r for r in f.get("remedy", []) if r["action"] == action), None)
        dev = inventory.get(f["device"]) if f.get("device") else None
        if not remedy or not dev or not dev.ssh:
            raise ValueError("%s is not available for this finding" % action)
        if DRY_RUN:
            result = "would run %s on %s" % (action, dev.name)
        elif action == "apply-updates":
            result = await linux.apply_updates(dev)
        else:
            result = await linux.update_container(dev, remedy.get("params", []))
        status = "remediating"
    elif action == "acknowledge":
        result, status = "acknowledged", "acknowledged"
    elif action == "resolve":
        result, status = "marked resolved", "resolved"
    else:
        raise ValueError("unknown action %s" % action)
    if DRY_RUN and action in ("quarantine", "isolate", "wifi-disconnect", "update-routeros", "apply-updates", "update-container"):
        result = "[dry run] " + result
    f["status"] = status
    f.setdefault("history", []).append({"time": time.time(), "action": action, "by": by, "result": result})
    security.save(findings)
    _audit({"action": action, "finding": finding_id, "host": f["host"], "by": by, "result": result})
    return result


async def quarantined() -> list[dict]:
    """Current state on the router (what the UI shows under 'Quarantine')."""
    if DRY_RUN:
        return [{"kind": "dry-run", "address": e["host"], "comment": e.get("finding", "")}
                for e in audit_log(500) if e["action"] in ("quarantine", "wifi-disconnect")]
    out = await _routeros(
        ':foreach i in=[/ip firewall address-list find where list=%s] do={:put ("fw|" . [/ip firewall address-list get $i address] . "|" . [/ip firewall address-list get $i comment])}\n'
        ':foreach i in=[/interface wifi access-list find where comment~"^netops:"] do={:put ("wifi|" . [/interface wifi access-list get $i mac-address] . "|" . [/interface wifi access-list get $i comment])}'
        % LIST)
    rows = []
    for line in out.splitlines():
        kind, addr, comment = (line.strip().split("|", 2) + ["", ""])[:3]
        if kind in ("fw", "wifi"):
            rows.append({"kind": kind, "address": addr, "comment": comment})
    return rows
