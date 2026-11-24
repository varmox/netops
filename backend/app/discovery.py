"""Per-device hardware & firmware discovery — read-only.

Fills in what the inventory can't hand-maintain: model, serial, CPU/RAM, OS/firmware version and uptime.
Best source first, degrading gracefully, and never changing anything on the device:

  - MikroTik: SSH ``/system resource|routerboard|identity`` (vault-gated, same key as the backup collector).
  - Linux:    SSH ``uname`` / ``/etc/os-release`` / ``/proc/cpuinfo|meminfo`` / DMI (vault-gated, ``dev.ssh``).
  - SNMP:     a best-effort SNMPv2c GET of sysDescr/sysName/sysUpTime — no login, no third-party dependency.
  - Passive:  always — the MAC's OUI vendor and the service banners from the last LAN scan as an OS hint.

Results are cached in ``data/discovery.json`` and refreshed on demand from the device page.
"""
import asyncio
import json
import logging
import random
import re
import socket
import time

import asyncssh

from . import inventory, security, settings, vault
from .collectors.mikrotik import _ALGS
from .netmap import OUI

log = logging.getLogger("netops.discovery")

_STORE = settings.DATA_DIR / "discovery.json"


# ---------------------------------------------------------------- SSH probes

async def _ssh(host: str, cfg: dict, commands: list[str], mikrotik: bool = False) -> dict[str, str]:
    """Run several read-only commands over one SSH connection; returns {command: stdout}."""
    key = asyncssh.import_private_key(vault.secret_or_file(cfg, "key_vault", "key"))
    kw: dict = dict(port=int(cfg.get("port", 22)), username=cfg["user"], client_keys=[key],
                    known_hosts=None, connect_timeout=12)
    if mikrotik:                                      # RouterOS 7.16 only verifies RSA signatures
        kw.update(server_host_key_algs=_ALGS, signature_algs=_ALGS)
    out: dict[str, str] = {}
    async with asyncssh.connect(host, **kw) as conn:
        for c in commands:
            r = await conn.run(c, check=False, timeout=30)
            out[c] = r.stdout or ""
    return out


def _kv(text: str) -> dict[str, str]:
    """RouterOS ``print`` output: ``  key: value`` lines -> dict (last value wins)."""
    d = {}
    for line in text.splitlines():
        m = re.match(r"\s*([a-z0-9-]+):\s*(.*?)\s*$", line)
        if m:
            d[m.group(1)] = m.group(2)
    return d


async def _mikrotik(dev) -> dict[str, str]:
    o = await _ssh(dev.host, dev.backup or {}, [
        "/system resource print without-paging",
        "/system routerboard print without-paging",
        "/system identity print without-paging",
    ], mikrotik=True)
    res, rb, ident = _kv(o[list(o)[0]]), _kv(o[list(o)[1]]), _kv(o[list(o)[2]])
    facts: dict[str, str] = {}
    if rb.get("model"):
        facts["Model"] = rb["model"]
    if rb.get("serial-number"):
        facts["Serial"] = rb["serial-number"]
    if ident.get("name"):
        facts["Identity"] = ident["name"]
    if res.get("version"):
        facts["RouterOS"] = res["version"].split()[0]
    if rb.get("current-firmware"):
        fw = rb["current-firmware"]
        if rb.get("upgrade-firmware") and rb["upgrade-firmware"] != fw:
            fw += " (upgrade to %s available)" % rb["upgrade-firmware"]
        facts["Firmware"] = fw
    cores, freq = res.get("cpu-count"), res.get("cpu-frequency")
    core = "%s cores @ %s" % (cores, freq) if cores and freq else \
        ("%s cores" % cores if cores else ("@ %s" % freq if freq else ""))
    cpu = " · ".join(x for x in (res.get("cpu"), core) if x)
    if cpu:
        facts["CPU"] = cpu
    if res.get("architecture-name"):
        facts["Architecture"] = res["architecture-name"]
    if res.get("total-memory"):
        mem = res["total-memory"]
        if res.get("free-memory"):
            mem += " (%s free)" % res["free-memory"]
        facts["Memory"] = mem
    if res.get("uptime"):
        facts["Uptime"] = res["uptime"]
    return facts


async def _linux(dev) -> dict[str, str]:
    o = await _ssh(dev.host, dev.ssh or {}, [
        "uname -sr",
        "cat /etc/os-release 2>/dev/null",
        "grep -m1 'model name' /proc/cpuinfo 2>/dev/null; nproc 2>/dev/null",
        "grep -m1 MemTotal /proc/meminfo 2>/dev/null",
        "cat /proc/device-tree/model 2>/dev/null; cat /sys/class/dmi/id/sys_vendor /sys/class/dmi/id/product_name 2>/dev/null",
        "uptime -p 2>/dev/null",
    ])
    cmds = list(o)
    osr = {}
    for line in o[cmds[1]].splitlines():
        m = re.match(r'([A-Z_]+)=(.*)', line)
        if m:
            osr[m.group(1)] = m.group(2).strip('"')
    facts: dict[str, str] = {}
    facts["OS"] = osr.get("PRETTY_NAME") or o[cmds[0]].strip() or "Linux"
    if o[cmds[0]].strip():
        facts["Kernel"] = o[cmds[0]].strip()
    cpu_lines = [ln for ln in o[cmds[2]].splitlines() if ln.strip()]
    model = next((ln.split(":", 1)[1].strip() for ln in cpu_lines if ":" in ln), None)
    cores = next((ln.strip() for ln in cpu_lines if ln.strip().isdigit()), None)
    if model:
        facts["CPU"] = model + (" · %s cores" % cores if cores else "")
    elif cores:
        facts["CPU"] = "%s cores" % cores
    m = re.search(r"MemTotal:\s*(\d+)\s*kB", o[cmds[3]])
    if m:
        facts["Memory"] = "%.1f GiB" % (int(m.group(1)) / 1024 / 1024)
    hw = " ".join(x.strip() for x in o[cmds[4]].splitlines() if x.strip())
    if hw:
        facts["Hardware"] = hw
    if o[cmds[5]].strip():
        facts["Uptime"] = o[cmds[5]].strip().removeprefix("up ")
    return facts


# ---------------------------------------------------------------- SNMPv2c GET (dependency-free)

_SNMP_OIDS = {
    "1.3.6.1.2.1.1.1.0": "sysDescr",
    "1.3.6.1.2.1.1.5.0": "sysName",
    "1.3.6.1.2.1.1.3.0": "sysUpTime",
}


def _ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv(tag: int, val: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(val)) + val


def _ber_int(n: int) -> bytes:
    if n == 0:
        return _tlv(0x02, b"\x00")
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return _tlv(0x02, b)


def _ber_oid(s: str) -> bytes:
    p = [int(x) for x in s.split(".")]
    body = bytes([40 * p[0] + p[1]])
    for n in p[2:]:
        if n < 0x80:
            body += bytes([n])
        else:
            stack = []
            while n:
                stack.insert(0, n & 0x7F)
                n >>= 7
            for i in range(len(stack) - 1):
                stack[i] |= 0x80
            body += bytes(stack)
    return _tlv(0x06, body)


def _ber_parse(data: bytes, i: int = 0) -> tuple[int, bytes, int]:
    """One TLV at offset i -> (tag, value_bytes, next_offset)."""
    tag = data[i]
    length = data[i + 1]
    i += 2
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[i:i + n], "big")
        i += n
    return tag, data[i:i + length], i + length


def _snmp_sync(host: str, community: str, oids: list[str], timeout: float) -> bytes | None:
    varbinds = b"".join(_tlv(0x30, _ber_oid(o) + _tlv(0x05, b"")) for o in oids)
    pdu = _tlv(0xA0, _ber_int(random.randint(1, 0x7FFFFFFF)) + _ber_int(0) + _ber_int(0) + _tlv(0x30, varbinds))
    msg = _tlv(0x30, _ber_int(1) + _tlv(0x04, community.encode()) + pdu)   # version=1 → SNMPv2c
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(msg, (host, 161))
        return s.recvfrom(4096)[0]
    except OSError:
        return None
    finally:
        s.close()


def _snmp_decode(data: bytes) -> dict[str, str]:
    """Pull the varbind values out of a GET response; tolerant, returns {oid: text}."""
    _, body, _ = _ber_parse(data)                    # outer SEQUENCE
    i = 0
    _, _, i = _ber_parse(body, i)                    # version
    _, _, i = _ber_parse(body, i)                    # community
    tag, pdu, _ = _ber_parse(body, i)                # PDU (response, 0xa2)
    j = 0
    for _ in range(3):                               # request-id, error-status, error-index
        _, _, j = _ber_parse(pdu, j)
    _, vbl, _ = _ber_parse(pdu, j)                   # varbind list SEQUENCE
    out: dict[str, str] = {}
    k = 0
    while k < len(vbl):
        _, vb, k = _ber_parse(vbl, k)                # one varbind SEQUENCE
        otag, oid, m = _ber_parse(vb, 0)
        vtag, val, _ = _ber_parse(vb, m)
        name = ".".join(_oid_nums(oid))
        if vtag == 0x43:                             # TimeTicks (1/100 s)
            out[name] = _ticks(int.from_bytes(val, "big"))
        elif vtag in (0x02, 0x41):                   # INTEGER / Counter
            out[name] = str(int.from_bytes(val, "big"))
        else:                                        # OCTET STRING and friends
            out[name] = val.decode("utf-8", "replace").strip()
    return out


def _oid_nums(body: bytes) -> list[str]:
    nums = [str(body[0] // 40), str(body[0] % 40)]
    n = 0
    for b in body[1:]:
        n = (n << 7) | (b & 0x7F)
        if not b & 0x80:
            nums.append(str(n))
            n = 0
    return nums


def _ticks(t: int) -> str:
    s = t // 100
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    return (("%dd " % d) if d else "") + "%dh %dm" % (h, m)


async def _snmp(dev) -> dict[str, str]:
    community = (dev.facts or {}).get("snmp_community") or "public"
    data = await asyncio.to_thread(_snmp_sync, dev.host, community, list(_SNMP_OIDS), 2.0)
    if not data:
        return {}
    try:
        vals = _snmp_decode(data)
    except Exception as e:                           # noqa: BLE001 — never let a malformed packet crash a probe
        log.debug("snmp decode failed for %s: %s", dev.host, e)
        return {}
    facts: dict[str, str] = {}
    labels = {v: k for k, v in _SNMP_OIDS.items()}
    if vals.get(labels["sysDescr"]):
        facts["System"] = vals[labels["sysDescr"]][:200]
    if vals.get(labels["sysName"]):
        facts["Name"] = vals[labels["sysName"]]
    if vals.get(labels["sysUpTime"]):
        facts["Uptime"] = vals[labels["sysUpTime"]]
    return facts


# ---------------------------------------------------------------- passive enrichment

def _vendor(mac: str | None) -> str | None:
    if not mac:
        return None
    return OUI.get(mac.replace(":", "").replace("-", "").upper()[:6])


async def _passive(dev) -> dict[str, str]:
    facts: dict[str, str] = {}
    svcs = [s for s in security.services().get("services", []) if s.get("host") == dev.host]
    if svcs:
        facts["Open ports"] = ", ".join(sorted({"%s/%s" % (s["port"], s.get("proto", "tcp")) for s in svcs},
                                               key=lambda x: int(x.split("/")[0])))
        banner = next((s["product"] for s in svcs if s.get("service") in ("ssh", "http", "https") and s.get("product")), None)
        if banner:
            facts["Service banner"] = banner
    mac = (dev.facts or {}).get("MAC") or (dev.facts or {}).get("mac")
    if not mac:
        try:
            from . import remediation
            mac = (await remediation.lease_info(dev.host)).get("mac")
        except Exception:                            # noqa: BLE001 — Prometheus optional
            mac = None
    if mac:
        facts["MAC"] = mac.upper()
        if _vendor(mac):
            facts["Vendor"] = _vendor(mac)
    return facts


# ---------------------------------------------------------------- orchestration + store

async def probe(dev) -> dict:
    """Probe one device with the best available method(s); persist and return the result."""
    facts: dict[str, str] = {}
    sources: list[str] = []
    vault_locked = False
    try:
        if dev.type == "mikrotik" and dev.backup:
            facts |= await _mikrotik(dev)
            sources.append("ssh")
        elif dev.type == "linux" and dev.ssh:
            facts |= await _linux(dev)
            sources.append("ssh")
    except vault.VaultLocked:
        vault_locked = True
    except Exception as e:                           # noqa: BLE001 — fall through to the loginless probes
        log.warning("ssh probe of %s failed: %s", dev.id, e)

    if "ssh" not in sources:                         # only reach out by SNMP when SSH didn't answer
        snmp = await _snmp(dev)
        if snmp:
            facts |= snmp
            sources.append("snmp")

    passive = await _passive(dev)
    for k, v in passive.items():
        facts.setdefault(k, v)
    if passive:
        sources.append("passive")

    rec = {"time": time.time(), "sources": sources, "facts": facts, "vault_locked": vault_locked}
    _save(dev.id, rec)
    return rec


def _all() -> dict[str, dict]:
    try:
        return json.loads(_STORE.read_text())
    except (OSError, ValueError):
        return {}


def _save(device_id: str, rec: dict) -> None:
    settings.DATA_DIR.mkdir(parents=True, exist_ok=True)
    data = _all()
    data[device_id] = rec
    tmp = _STORE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=1))
    tmp.replace(_STORE)


def load(device_id: str) -> dict | None:
    return _all().get(device_id)
