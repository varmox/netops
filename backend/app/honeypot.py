"""Honeypot / canary (feature 8). The appliance listens on a handful of ports that nothing on a home
network should be dialing — Telnet, SMB, RDP, ADB. These services don't exist here; anything on the LAN
that connects to one is either misconfigured or looking for something to take over, so every connection
is logged and the first one from each source raises an alert.

The listeners never send a usable service: they read a little, record the peer, and close. Ports come from
settings.HONEYPOT_PORTS ("port:label,..."). Privileged ports (23, 445, 3389) are only bound if the
container is allowed to; unprivileged fallbacks (2323, …) always work.
"""
import asyncio
import json
import logging
import time

from . import alerts, inventory, settings

log = logging.getLogger("netops.honeypot")

DIR = settings.DATA_DIR / "honeypot"
HITS = DIR / "hits.jsonl"
_seen: dict[str, float] = {}          # source IP -> last alert time (rate-limit alerts to 1/hour/source)
_servers: list[asyncio.base_events.Server] = []
ALERT_EVERY = 3600


def _device_for(ip: str) -> object | None:
    return next((d for d in inventory.load() if d.host == ip), None)


def _record(hit: dict) -> None:
    DIR.mkdir(parents=True, exist_ok=True)
    with HITS.open("a") as f:
        f.write(json.dumps(hit) + "\n")


async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int, label: str) -> None:
    peer = writer.get_extra_info("peername")
    ip = peer[0] if peer else "?"
    try:
        # read a little of whatever they send, then drop them
        try:
            data = await asyncio.wait_for(reader.read(256), timeout=3)
        except (asyncio.TimeoutError, ConnectionError):
            data = b""
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass
        dev = _device_for(ip)
        hit = {"time": time.time(), "src": ip, "port": port, "service": label,
               "device": dev.id if dev else None, "device_name": dev.name if dev else None,
               "bytes": len(data), "preview": data[:64].hex()}
        _record(hit)
        log.warning("honeypot hit: %s -> :%d (%s)", ip, port, label)
        last = _seen.get(ip, 0)
        if time.time() - last > ALERT_EVERY:
            _seen[ip] = time.time()
            who = (dev.name if dev else ip)
            await alerts.notify(
                "Honeypot triggered by %s" % who,
                "%s connected to the fake %s service on port %d. Nothing here offers that service; "
                "investigate this device." % (ip, label, port),
                "warning", dev.id if dev else None)
    except Exception:
        log.exception("honeypot handler failed")


def _ports() -> list[tuple[int, str]]:
    out = []
    for item in settings.HONEYPOT_PORTS.split(","):
        item = item.strip()
        if not item:
            continue
        port, _, label = item.partition(":")
        try:
            out.append((int(port), label or "unknown"))
        except ValueError:
            log.warning("bad HONEYPOT_PORTS entry: %r", item)
    return out


async def start() -> None:
    if _servers:
        return
    for port, label in _ports():
        try:
            srv = await asyncio.start_server(lambda r, w, p=port, l=label: _handle(r, w, p, l), "0.0.0.0", port)
            _servers.append(srv)
            log.info("honeypot listening on :%d (%s)", port, label)
        except OSError as e:
            log.warning("honeypot could not bind :%d (%s): %s", port, label, e)


async def stop() -> None:
    for srv in _servers:
        srv.close()
    _servers.clear()
    log.info("honeypot listeners stopped")


async def apply(enabled: bool) -> None:
    """Start or stop the listeners to match the feature toggle, without a restart."""
    if enabled and not _servers:
        await start()
    elif not enabled and _servers:
        await stop()


def running() -> bool:
    return bool(_servers)


def hits(limit: int = 200) -> list[dict]:
    if not HITS.is_file():
        return []
    return [json.loads(line) for line in HITS.read_text().splitlines()[-limit:]][::-1]


def summary() -> dict:
    rows = hits(1000)
    sources = {}
    for h in rows:
        sources[h["src"]] = sources.get(h["src"], 0) + 1
    return {"total": len(rows), "sources": len(sources), "ports": sorted({h["port"] for h in rows}),
            "listening": [{"port": p, "service": l} for p, l in _ports()] if running() else []}
