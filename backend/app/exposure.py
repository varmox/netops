"""Internet exposure (feature 6). Instead of scanning from outside (unreliable, and rude to the uplink),
we read the MikroTik's own configuration — the authoritative list of what it lets in from the WAN:

  - destination-NAT rules (port forwards)
  - UPnP: whether it is enabled at all, and every mapping a device has opened on its own
  - input-chain accept rules that face the WAN

UPnP mappings opened by a device are the dangerous ones: a compromised IoT box can punch its own hole to
the internet. New exposure raises an alert; disappeared exposure auto-resolves.
"""
import asyncio
import json
import logging
import time

from . import alerts, settings

log = logging.getLogger("netops.exposure")

DIR = settings.DATA_DIR / "exposure"
STATE = DIR / "state.json"


async def _collect() -> dict:
    from . import remediation   # its RouterOS helper and credentials
    script = (
        ':put "=== upnp ==="\n'
        ':put [/ip upnp get enabled]\n'
        ':put "=== upnp-active ==="\n'
        ':foreach i in=[/ip firewall nat find where comment~"upnp"] do={'
        ':put ([/ip firewall nat get $i dst-port] . "|" . [/ip firewall nat get $i to-addresses] . "|" . [/ip firewall nat get $i protocol] . "|" . [/ip firewall nat get $i comment])}\n'
        ':put "=== portforward ==="\n'
        ':foreach i in=[/ip firewall nat find where action=dst-nat] do={'
        ':put ([/ip firewall nat get $i dst-port] . "|" . [/ip firewall nat get $i to-addresses] . "|" . [/ip firewall nat get $i protocol] . "|" . [/ip firewall nat get $i comment])}\n'
        ':put "=== input ==="\n'
        ':foreach i in=[/ip firewall filter find where chain=input action=accept] do={'
        ':put ([/ip firewall filter get $i dst-port] . "|" . [/ip firewall filter get $i protocol] . "|" . [/ip firewall filter get $i in-interface-list] . "|" . [/ip firewall filter get $i comment])}'
    )
    out = await remediation._routeros(script)
    return _parse(out)


def _parse(out: str) -> dict:
    section, data = None, {"upnp_enabled": False, "upnp_mappings": [], "port_forwards": [], "input_accepts": []}
    for raw in out.splitlines():
        line = raw.strip()
        if line.startswith("=== ") and line.endswith(" ==="):
            section = line[4:-4]
            continue
        if not line:
            continue
        if section == "upnp":
            data["upnp_enabled"] = line.lower() == "true"
        elif section == "upnp-active":
            port, to, proto, comment = (line.split("|") + ["", "", "", ""])[:4]
            data["upnp_mappings"].append({"port": port, "to": to, "proto": proto, "comment": comment})
        elif section == "portforward":
            port, to, proto, comment = (line.split("|") + ["", "", "", ""])[:4]
            data["port_forwards"].append({"port": port, "to": to, "proto": proto, "comment": comment})
        elif section == "input":
            port, proto, iflist, comment = (line.split("|") + ["", "", "", ""])[:4]
            if iflist.upper() in ("WAN", "") and port:
                data["input_accepts"].append({"port": port, "proto": proto, "interface": iflist, "comment": comment})
    return data


def _exposures(data: dict) -> list[dict]:
    out = []
    for m in data["upnp_mappings"]:
        out.append({"kind": "upnp", "port": m["port"], "proto": m["proto"], "to": m["to"],
                    "label": "UPnP mapping opened by %s" % (m["to"] or "a device"), "level": "warning"})
    for p in data["port_forwards"]:
        if {m["port"] for m in data["upnp_mappings"]} and p["port"] in {m["port"] for m in data["upnp_mappings"]}:
            continue
        out.append({"kind": "port-forward", "port": p["port"], "proto": p["proto"], "to": p["to"],
                    "label": "Port forward to %s" % (p["to"] or "?"), "level": "info"})
    for a in data["input_accepts"]:
        out.append({"kind": "router-input", "port": a["port"], "proto": a["proto"], "to": "router",
                    "label": "Router accepts %s/%s from WAN" % (a["port"], a["proto"] or "tcp"), "level": "info"})
    return out


def load() -> dict:
    return json.loads(STATE.read_text()) if STATE.is_file() else {"time": None, "upnp_enabled": None, "exposures": []}


async def scan() -> dict:
    DIR.mkdir(parents=True, exist_ok=True)
    data = await _collect()
    exposures = _exposures(data)
    prev = {(e["kind"], e["port"], e["to"]) for e in load()["exposures"]}
    now = {(e["kind"], e["port"], e["to"]) for e in exposures}
    STATE.write_text(json.dumps({"time": time.time(), "upnp_enabled": data["upnp_enabled"],
                                 "exposures": exposures}, indent=1))
    for e in exposures:
        if (e["kind"], e["port"], e["to"]) not in prev and e["kind"] == "upnp":
            await alerts.notify("New internet exposure: %s" % e["label"],
                                "A device opened port %s/%s to the internet via UPnP. If you didn't expect this, "
                                "the device may be compromised; consider turning UPnP off." % (e["port"], e["proto"]),
                                "warning", None)
    gone = prev - now
    return {"exposures": len(exposures), "upnp_enabled": data["upnp_enabled"], "new": len(now - prev), "gone": len(gone)}


async def scheduler() -> None:
    from . import features
    from .jobs import _seconds_until
    await asyncio.sleep(90)
    while True:
        if features.enabled("exposure"):
            try:
                await scan()
            except Exception:
                log.exception("exposure scan failed (no MikroTik, or vault locked)")
        await asyncio.sleep(_seconds_until(settings.EXPOSURE_SCAN_TIME))
