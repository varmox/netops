"""Per-device (and whole-network) change timeline (feature 10).

Nothing new is collected: this merges events NetOps already records into one chronological list, so
"what changed on this device since Tuesday?" has an answer. Sources:

  - config backups: each new version, with its line diffstat
  - security findings: first seen, and every action in its history
  - certificates: certificate changes
  - internet exposure: UPnP mappings / port forwards appearing
  - honeypot: connections the device made to a fake service
  - end-of-life: a device crossing into EOL / near-EOL
"""
import time

from . import backups, certs, exposure, honeypot, inventory, lifecycle, security


def _backup_events(device_id: str) -> list[dict]:
    out = []
    for v in backups.versions(device_id):
        ds = v.get("diffstat") or {}
        detail = ("+%d / -%d lines" % (ds.get("added", 0), ds.get("removed", 0))) if v.get("previous") else "first backup"
        out.append({"time": _version_ts(v["version"]), "kind": "config", "level": "info",
                    "title": "Config backup %s" % v["version"], "detail": detail, "ref": v["version"]})
    return out


def _version_ts(version: str) -> float:
    # versions are YYYYMMDD-HHMMSS
    try:
        return time.mktime(time.strptime(version, "%Y%m%d-%H%M%S"))
    except ValueError:
        return 0.0


def _finding_events(device_id: str) -> list[dict]:
    out = []
    for f in security.load().values():
        if f.get("device") != device_id:
            continue
        out.append({"time": f.get("first_seen"), "kind": "security", "level": f.get("severity", "info"),
                    "title": "Finding: %s" % f["cve"], "detail": (f.get("summary") or "")[:160], "ref": f["id"]})
        for h in f.get("history", []):
            out.append({"time": h.get("time"), "kind": "security", "level": "info",
                        "title": "%s — %s" % (f["cve"], h.get("action")), "detail": h.get("result", ""), "ref": f["id"]})
    return out


def _cert_events(device_id: str) -> list[dict]:
    st = certs.load()
    out = []
    for c in st.get("certs", []):
        if c.get("device") == device_id and c.get("expires"):
            days = int((c["expires"] - time.time()) / 86400)
            if days <= 60:
                out.append({"time": st.get("time"), "kind": "certificate", "level": "warning" if days < 21 else "info",
                            "title": "Certificate on %s:%d" % (c["host"], c["port"]),
                            "detail": "expires in %d days" % days, "ref": c.get("fingerprint")})
    return out


def _exposure_events(device_id: str) -> list[dict]:
    dev = inventory.get(device_id)
    if not dev:
        return []
    st = exposure.load()
    out = []
    for e in st.get("exposures", []):
        if dev.host in (e.get("to") or ""):
            out.append({"time": st.get("time"), "kind": "exposure", "level": e.get("level", "info"),
                        "title": e.get("label"), "detail": "port %s/%s" % (e.get("port"), e.get("proto")), "ref": None})
    return out


def _honeypot_events(device_id: str) -> list[dict]:
    out = []
    for h in honeypot.hits(1000):
        if h.get("device") == device_id:
            out.append({"time": h.get("time"), "kind": "honeypot", "level": "warning",
                        "title": "Hit the %s honeypot" % h.get("service"),
                        "detail": "connected to port %d" % h.get("port"), "ref": None})
    return out


def _lifecycle_events(device_id: str) -> list[dict]:
    st = lifecycle.load()
    out = []
    for d in st.get("devices", []):
        if d.get("device") == device_id and d.get("status") in ("eol", "warn"):
            out.append({"time": st.get("time"), "kind": "lifecycle",
                        "level": "warning" if d["status"] == "eol" else "info",
                        "title": "%s %s is %s" % (d["product"], d["cycle"],
                                                  "end-of-life" if d["status"] == "eol" else "nearing end-of-life"),
                        "detail": "", "ref": None})
    return out


def for_device(device_id: str, limit: int = 200) -> list[dict]:
    events = (_backup_events(device_id) + _finding_events(device_id) + _cert_events(device_id)
              + _exposure_events(device_id) + _honeypot_events(device_id) + _lifecycle_events(device_id))
    events = [e for e in events if e.get("time")]
    return sorted(events, key=lambda e: e["time"], reverse=True)[:limit]


def network(limit: int = 300) -> list[dict]:
    out = []
    for dev in inventory.load():
        for e in for_device(dev.id, limit):
            out.append({**e, "device": dev.id, "device_name": dev.name})
    return sorted(out, key=lambda e: e["time"], reverse=True)[:limit]
