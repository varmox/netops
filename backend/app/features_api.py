"""HTTP API for the added features: DNS, certificates, lifecycle, exposure, honeypot, credential audit,
timeline, weekly report and the family view. Read endpoints are GET; anything that acts is POST (and so
needs the X-NetOps header and an admin session, enforced by the guard middleware in main.py)."""
import asyncio
import logging

import asyncssh
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from . import (auth, certs, credcheck, discovery, dns, exposure, features, honeypot, inventory,
               lifecycle, netmap, reliability, report, settings, timeline, vault, wifi)

router = APIRouter(prefix="/api")
log = logging.getLogger("netops.features")
_jobs: dict[str, asyncio.Task] = {}


# ---------------------------------------------------------------- feature registry + toggles

@router.get("/features")
async def features_list():
    rows = features.listing()
    for r in rows:                       # fill the AdGuard admin link if configured
        if r["key"] == "dns" and r.get("external") and not r["external"]["url"]:
            r["external"]["url"] = settings.ADGUARD_PUBLIC_URL
    return rows


class Toggle(BaseModel):
    enabled: bool


class AlertPref(BaseModel):
    enabled: bool | None = None  # True/False override; null resets to the device default


@router.post("/features/{key}")
async def feature_toggle(key: str, body: Toggle):
    try:
        features.set_enabled(key, body.enabled)
    except ValueError as e:
        raise HTTPException(400, str(e))
    if key == "honeypot":
        await honeypot.apply(body.enabled)
    return {"key": key, "enabled": body.enabled}


# ---------------------------------------------------------------- reliability (latency / MTTR / percentiles)

@router.get("/reliability")
async def reliability_fleet():
    return reliability.fleet()


@router.get("/devices/{device_id}/reliability")
async def reliability_device(device_id: str):
    if not inventory.get(device_id):
        raise HTTPException(404, "unknown device")
    return await reliability.summary(device_id)


def _start(name: str, coro) -> bool:
    if name in _jobs and not _jobs[name].done():
        coro.close()
        return False
    _jobs[name] = asyncio.create_task(coro)
    return True


# ---------------------------------------------------------------- DNS (feature 1)

@router.get("/dns/overview")
async def dns_overview():
    if not features.enabled("dns"):
        return {"available": False, "disabled": True, "error": "DNS filtering is turned off (enable it under Features)"}
    try:
        return {"available": True, **(await dns.overview())}
    except Exception as e:
        return {"available": False, "error": str(e)}


@router.get("/dns/clients")
async def dns_clients():
    return await dns.top_clients()


@router.get("/dns/querylog")
async def dns_querylog(limit: int = 100, search: str = ""):
    return await dns.querylog(limit, search)


class Protection(BaseModel):
    enabled: bool


@router.post("/dns/protection")
async def dns_protection(body: Protection):
    try:
        return {"result": await dns.set_protection(body.enabled)}
    except Exception as e:
        raise HTTPException(502, str(e))


# ---------------------------------------------------------------- certificates (feature 3)

@router.get("/certs")
async def certs_list():
    return certs.load()


@router.post("/certs/scan")
async def certs_scan():
    return {"started": _start("certs", certs.scan())}


# ---------------------------------------------------------------- lifecycle / EOL (feature 4)

@router.get("/lifecycle")
async def lifecycle_list():
    return lifecycle.load()


@router.post("/lifecycle/scan")
async def lifecycle_scan():
    return {"started": _start("lifecycle", lifecycle.scan())}


# ---------------------------------------------------------------- exposure (feature 6)

@router.get("/exposure")
async def exposure_list():
    return exposure.load()


@router.post("/exposure/scan")
async def exposure_scan():
    return {"started": _start("exposure", exposure.scan())}


# ---------------------------------------------------------------- honeypot (feature 8)

@router.get("/honeypot")
async def honeypot_state():
    return {"summary": honeypot.summary(), "hits": honeypot.hits(200)}


# ---------------------------------------------------------------- credential audit (feature 5)

@router.get("/credcheck")
async def credcheck_state():
    return {"enabled": features.enabled("credcheck"), "last": credcheck.load(),
            "targets": credcheck.targets_from_inventory()}


class CredAudit(BaseModel):
    confirm: bool = False
    targets: list[dict] | None = None


@router.post("/credcheck/run")
async def credcheck_run(body: CredAudit, request: Request):
    if not body.confirm:
        raise HTTPException(400, "this audit tries factory logins against your devices; confirm to run it")
    user = (auth.current_user(request) or {}).get("username") or "?"
    targets = body.targets or credcheck.targets_from_inventory()
    try:
        return await credcheck.audit(targets, by=user)
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))


# ---------------------------------------------------------------- network map (phase 2)

@router.get("/netmap")
async def netmap_get():
    return netmap.load()


@router.get("/netmap/traffic")
async def netmap_traffic():
    return netmap.load_traffic()


async def _rebuild_map():
    await netmap.build()
    await netmap.build_traffic()


@router.post("/netmap/scan")
async def netmap_scan():
    return {"started": _start("netmap", _rebuild_map())}


# ---------------------------------------------------------------- RF optimizer / Wi-Fi

@router.get("/wifi")
async def wifi_snapshot():
    if not features.enabled("wifi"):
        return {"available": False, "error": "The RF optimizer feature is off.", "time": None,
                "radios": [], "clients": [], "findings": [], "score": None, "neighbors": [], "scan_time": None,
                "plan": {"bands": [], "command": "", "rollback": ""}}
    return await wifi.snapshot()


@router.post("/wifi/scan")
async def wifi_scan():
    """Neighbour scan — briefly interrupts Wi-Fi on each radio while it hops channels."""
    if not features.enabled("wifi"):
        raise HTTPException(400, "The RF optimizer feature is off.")
    try:
        return await wifi.scan()
    except Exception as e:                           # noqa: BLE001
        raise HTTPException(502, "scan failed: %s" % e)


# ---------------------------------------------------------------- timeline (feature 10)

@router.get("/timeline")
async def timeline_network():
    return timeline.network()


@router.get("/devices/{device_id}/timeline")
async def timeline_device(device_id: str):
    if not inventory.get(device_id):
        raise HTTPException(404, "unknown device")
    return timeline.for_device(device_id)


class DeviceSpec(BaseModel):
    id: str
    name: str
    type: str = "generic"
    host: str
    role: str = ""
    notes: str = ""
    checks: list[dict] = []
    protected: bool = False
    alert: bool | None = None
    links: dict[str, str] = {}
    facts: dict[str, str] = {}


@router.post("/devices")
async def create_device(spec: DeviceSpec):
    """Add a device from the UI; stored in /data, never written into devices.yml."""
    try:
        return inventory.save_device(spec.model_dump(), creating=True).public()
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.put("/devices/{device_id}")
async def update_device(device_id: str, spec: DeviceSpec):
    if spec.id != device_id:
        raise HTTPException(400, "id in the body does not match the URL")
    existing = inventory.get(device_id)
    if existing and not existing.managed:
        raise HTTPException(409, "this device is defined in devices.yml and is read-only here")
    try:
        return inventory.save_device(spec.model_dump(), creating=False).public()
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.delete("/devices/{device_id}")
async def delete_device(device_id: str):
    existing = inventory.get(device_id)
    if not existing:
        raise HTTPException(404, "unknown device")
    if not existing.managed:
        raise HTTPException(409, "this device is defined in devices.yml and cannot be deleted here")
    inventory.delete_device(device_id)
    return {"deleted": device_id}


# ---------------------------------------------------------------- per-device credentials (vault-backed)

_CRED_SLOTS = {"ssh-key": "ssh-key", "password": "password"}   # slot -> vault kind


def _cred_name(device_id: str, slot: str) -> str:
    return "dev-%s-%s" % (device_id, slot)


def _wire_credential(device_id: str, dev, slot: str, name: str, user: str | None, port: int | None) -> None:
    """Point a managed device's connection config at the vault secret we just stored."""
    if slot == "ssh-key" and dev.type == "mikrotik":
        b = dict(dev.backup or {})
        b.setdefault("method", "mikrotik-ssh")
        b["key_vault"] = name
        if user:
            b["user"] = user
        inventory.patch_managed(device_id, {"backup": b})
    elif slot == "ssh-key":
        s = dict(dev.ssh or {})
        s["key_vault"] = name
        if user:
            s["user"] = user
        if port:
            s["port"] = port
        inventory.patch_managed(device_id, {"ssh": s})
    elif slot == "password":
        b = dict(dev.backup or {})
        if dev.type == "zyxel":
            b.setdefault("method", "zyxel-zcfg")
            b["redact"] = True
            b["scheme"] = "https"
        b["password_vault"] = name
        if user:
            b["user"] = user
        inventory.patch_managed(device_id, {"backup": b})


@router.get("/devices/{device_id}/credentials")
async def device_credentials(device_id: str):
    dev = inventory.get(device_id)
    if not dev:
        raise HTTPException(404, "unknown device")
    slots = []
    for slot in _CRED_SLOTS:
        name = _cred_name(device_id, slot)
        refs = {(dev.ssh or {}).get("key_vault"), (dev.backup or {}).get("key_vault"),
                (dev.backup or {}).get("password_vault")}
        slots.append({"slot": slot, "name": name, "set": vault.has(name), "referenced": name in refs})
    return {
        "vault": {"initialized": vault.initialized(), "unlocked": vault.unlocked()},
        "managed": dev.managed, "type": dev.type,
        "ssh_user": (dev.ssh or {}).get("user") or (dev.backup or {}).get("user"),
        "ssh_port": (dev.ssh or {}).get("port"),
        "slots": slots,
    }


class CredSet(BaseModel):
    slot: str
    value: str | None = None
    generate: bool = False
    user: str | None = None
    port: int | None = None


@router.post("/devices/{device_id}/credentials")
async def set_credential(device_id: str, body: CredSet):
    dev = inventory.get(device_id)
    if not dev:
        raise HTTPException(404, "unknown device")
    if body.slot not in _CRED_SLOTS:
        raise HTTPException(400, "unknown credential slot")
    if not vault.unlocked():
        raise HTTPException(409, "Unlock the vault first (Vault page).")
    name = _cred_name(device_id, body.slot)
    public_key = None
    try:
        if body.slot == "ssh-key" and body.generate:
            key = asyncssh.generate_private_key("ssh-ed25519", comment="netops-%s" % device_id)
            vault.put(name, key.export_private_key().decode(), "ssh-key", "SSH key for device %s" % device_id)
            public_key = key.export_public_key().decode().strip()
        elif body.value:
            vault.put(name, body.value, _CRED_SLOTS[body.slot], "%s for device %s" % (body.slot, device_id))
        else:
            raise HTTPException(400, "provide a value, or generate=true for an SSH key")
    except vault.VaultLocked as e:
        raise HTTPException(409, str(e))
    if dev.managed:
        _wire_credential(device_id, dev, body.slot, name, body.user, body.port)
    return {"ok": True, "slot": body.slot, "set": True, "public_key": public_key}


@router.delete("/devices/{device_id}/credentials/{slot}")
async def clear_credential(device_id: str, slot: str):
    dev = inventory.get(device_id)
    if not dev:
        raise HTTPException(404, "unknown device")
    if slot not in _CRED_SLOTS:
        raise HTTPException(400, "unknown credential slot")
    name = _cred_name(device_id, slot)
    vault.delete(name)
    if dev.managed:                                  # drop any config reference to it
        patch: dict = {}
        if (dev.ssh or {}).get("key_vault") == name:
            patch["ssh"] = {k: v for k, v in dev.ssh.items() if k != "key_vault"}
        b = dict(dev.backup or {})
        if b.get("key_vault") == name or b.get("password_vault") == name:
            b = {k: v for k, v in b.items() if v != name}
            patch["backup"] = b
        if patch:
            inventory.patch_managed(device_id, patch)
    return {"ok": True, "slot": slot, "set": False}


@router.get("/devices/{device_id}/discovery")
async def device_discovery(device_id: str):
    """The last hardware/firmware probe for a device (model, serial, CPU/RAM, OS/firmware, uptime)."""
    if not inventory.get(device_id):
        raise HTTPException(404, "unknown device")
    return discovery.load(device_id) or {"time": None, "sources": [], "facts": {}, "vault_locked": False}


@router.post("/devices/{device_id}/discover")
async def device_discover(device_id: str):
    """Probe the device now — read-only (SSH where possible, SNMP, then passive enrichment)."""
    dev = inventory.get(device_id)
    if not dev:
        raise HTTPException(404, "unknown device")
    try:
        return await discovery.probe(dev)
    except vault.VaultLocked as e:
        raise HTTPException(409, str(e))
    except Exception as e:                           # noqa: BLE001
        raise HTTPException(502, "probe failed: %s" % e)


@router.post("/devices/{device_id}/alert")
async def device_alert(device_id: str, body: AlertPref):
    """Set whether this device pages on down/degraded. null = back to the default."""
    dev = inventory.get(device_id)
    if not dev:
        raise HTTPException(404, "unknown device")
    inventory.set_alert(device_id, body.enabled)
    pub = dev.public()
    return {"id": device_id, "alert_on_down": pub["alert_on_down"],
            "alert_default": pub["alert_default"], "alert_overridden": pub["alert_overridden"]}


# ---------------------------------------------------------------- weekly report (feature 9)

@router.get("/report")
async def report_latest():
    return report.latest() or {}


@router.post("/report/run")
async def report_run():
    return await report.send()


# ---------------------------------------------------------------- family view (feature 12)

@router.get("/family")
async def family():
    """A plain, read-only summary: what's online, nothing technical."""
    from . import state
    devices = inventory.load()
    rows = []
    for d in devices:
        st = state.get(d.id)
        rows.append({"name": d.name, "role": d.role or d.type, "status": st.status,
                     "kind": d.type, "icon": _family_icon(d.type)})
    online = sum(1 for r in rows if r["status"] == "up")
    exp = exposure.load()
    hp = honeypot.summary()
    return {
        "ok": all(r["status"] in ("up", "unknown") for r in rows) and not exp.get("exposures"),
        "online": online, "total": len(rows),
        "devices": sorted(rows, key=lambda r: (r["status"] != "down", r["name"])),
        "warnings": {"exposures": len(exp.get("exposures", [])), "honeypot": hp.get("total", 0)},
    }


def _family_icon(kind: str) -> str:
    return {"mikrotik": "router", "zyxel": "router", "linux": "host", "tv": "display",
            "speaker": "volume-up", "camera": "video-camera", "phone": "mobile"}.get(kind, "devices")
