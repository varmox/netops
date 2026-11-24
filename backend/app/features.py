"""Feature registry and runtime on/off toggles.

Everything NetOps does is a "feature" with a key, a one-line description, a category and — where it ships its
own prebuilt web UI (AdGuard, Grafana) — a link to it, so the whole surface is visible and switchable from
one page in the main UI instead of scattered across separate UIs. Toggles are persisted in
data/features.json and take effect without a restart: schedulers check `enabled(key)` each round, and the
honeypot's listeners are started/stopped on toggle.
"""
import json
import os
from dataclasses import asdict, dataclass

from . import settings


@dataclass
class Feature:
    key: str
    title: str
    description: str
    category: str                      # core | watch | active | view | planned
    toggleable: bool = True
    default: bool = True
    env: str | None = None             # environment variable that sets the initial state
    external: dict | None = None       # a shipped prebuilt UI: {label, url, note}
    nav: dict | None = None            # where it lives in the main UI: {route, label, icon}
    planned: bool = False              # not built yet (shown, not toggleable)


REGISTRY: list[Feature] = [
    Feature("health", "Health & latency", "Reachability checks, latency, availability, MTTR and p5/p95.",
            "core", nav={"route": "/dashboard", "label": "Dashboard", "icon": "dashboard"}),
    Feature("backups", "Config backups", "Daily config backups with history and diffs.", "core",
            nav={"route": "/backups", "label": "Backups", "icon": "backup"}),
    Feature("security", "Vulnerability scanning", "CVE feeds (KEV/NVD), nmap/vulners LAN scan, remediation.",
            "core", nav={"route": "/security", "label": "Security", "icon": "shield"}),
    Feature("metrics", "Metrics", "Native VCF-style charts; Grafana ships richer dashboards.", "view",
            external={"label": "Open Grafana", "url": "/grafana", "note": "prebuilt dashboards"},
            nav={"route": "/metrics", "label": "Metrics", "icon": "line-chart"}),
    Feature("dns", "DNS filtering", "Ad/tracker/malware blocking and a per-device query log.", "watch",
            default=False, external={"label": "Open AdGuard admin", "url": "", "note": "blocklists, clients"},
            nav={"route": "/dns", "label": "DNS", "icon": "block"}),
    Feature("certs", "Certificates", "TLS expiry, weak TLS and certificate-change watch.", "watch",
            nav={"route": "/posture", "label": "Posture", "icon": "certificate"}),
    Feature("lifecycle", "Firmware / OS end-of-life", "Flags devices past (or nearing) end-of-life.", "watch",
            nav={"route": "/posture", "label": "Posture", "icon": "hourglass"}),
    Feature("exposure", "Internet exposure", "Port forwards and UPnP mappings read from the router.", "watch",
            nav={"route": "/posture", "label": "Posture", "icon": "world"}),
    Feature("honeypot", "Honeypot", "Fake Telnet/SMB/RDP/ADB services; any LAN connection alerts.", "active",
            env="HONEYPOT_ENABLED", nav={"route": "/posture", "label": "Posture", "icon": "bug"}),
    Feature("hibp", "Have I Been Pwned", "Breach check for stored credentials (keyless) and emails (needs a HIBP API key).",
            "watch", default=False, nav={"route": "/posture", "label": "Posture", "icon": "shield"}),
    Feature("credcheck", "Default-password audit", "Checks your devices for factory logins (LAN-only, opt-in).",
            "active", default=False, env="CREDCHECK_ENABLED",
            nav={"route": "/posture", "label": "Posture", "icon": "key"}),
    Feature("timeline", "Change timeline", "Every change across the network, per device and network-wide.",
            "view", nav={"route": "/timeline", "label": "Timeline", "icon": "clock"}),
    Feature("report", "Weekly report", "A weekly digest pushed to ntfy and shown on the dashboard.", "view",
            nav={"route": "/dashboard", "label": "Dashboard", "icon": "dashboard"}),
    Feature("map", "Network map", "Interactive topology: router → port → device, from leases and the router.",
            "view", default=False, nav={"route": "/map", "label": "Map", "icon": "network-globe"}),
    Feature("wifi", "RF optimizer", "Live Wi-Fi radios and clients, channel/width and signal analysis.",
            "view", default=False, nav={"route": "/wifi", "label": "Wi-Fi", "icon": "wifi"}),
]

BY_KEY = {f.key: f for f in REGISTRY}
STATE = settings.DATA_DIR / "features.json"


def _default(f: Feature) -> bool:
    if f.env and os.environ.get(f.env) is not None:
        return os.environ[f.env].lower() == "true"
    return f.default


def _overrides() -> dict:
    try:
        return json.loads(STATE.read_text())
    except (OSError, ValueError):
        return {}


def enabled(key: str) -> bool:
    f = BY_KEY.get(key)
    if not f or f.planned:
        return False
    return _overrides().get(key, _default(f))


def set_enabled(key: str, on: bool) -> None:
    f = BY_KEY.get(key)
    if not f or not f.toggleable:
        raise ValueError("feature %r cannot be toggled" % key)
    settings.DATA_DIR.mkdir(parents=True, exist_ok=True)
    ov = _overrides()
    ov[key] = bool(on)
    tmp = STATE.with_suffix(".tmp")
    tmp.write_text(json.dumps(ov, indent=1))
    tmp.replace(STATE)


def listing() -> list[dict]:
    ov = _overrides()
    out = []
    for f in REGISTRY:
        d = asdict(f)
        d["enabled"] = False if f.planned else ov.get(f.key, _default(f))
        d["overridden"] = f.key in ov
        out.append(d)
    return out
