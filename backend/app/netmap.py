"""Network map (phase 2, feature "map"): a topology graph of what's on the LAN and how it's wired.

Discovery, most-authoritative first:
  - inventory devices (names, types, status) from devices.yml / state
  - active DHCP leases the MikroTik reports via mktxp in Prometheus (IP, MAC, hostname) — no vault needed
  - the MikroTik's bridge host table and ARP table over SSH (vault) → which physical port each device is on

The graph is router → port → device, so you can see which device hangs off which switch port, plus an
"internet" node off the router. Unknown devices (a lease with no inventory entry) show as such, with a
best-effort vendor from the MAC OUI. Degrades gracefully: no vault → a flat star from leases; no router at
all → just the inventory. Cached in data/netmap/graph.json; rebuilt on a timer and on demand.
"""
import asyncio
import json
import logging
import os
import re
import time

import httpx

from . import inventory, settings, state

log = logging.getLogger("netops.netmap")

DIR = settings.DATA_DIR / "netmap"
GRAPH = DIR / "graph.json"
TRAFFIC = DIR / "traffic.json"
PROM = os.environ.get("PROMETHEUS_URL", "http://prometheus:9090")
RFC1918 = re.compile(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)")
MAX_EDGES = 60

# Small OUI → vendor table for labelling unknown devices (first 3 MAC octets, upper-case, no separators).
OUI = {
    "F0272D": "Apple", "A4B197": "Apple", "DCA632": "Raspberry Pi", "B827EB": "Raspberry Pi",
    "E45F01": "Raspberry Pi", "2CF05D": "MikroTik", "4C5E0C": "MikroTik", "48A98A": "MikroTik",
    "001599": "Sonos", "347E5C": "Sonos", "B8E937": "Sonos", "FC65DE": "Amazon", "44650D": "Amazon",
    "1C53F9": "Samsung", "D0176A": "Samsung", "A0C9A0": "Murata", "F0EF86": "Google", "D4F547": "Google",
    "3C5AB4": "Google", "DCA4CA": "Apple", "001788": "Philips Hue", "00178E": "Philips", "E0286D": "AVM",
    "244CE3": "Amazon", "B0A737": "Roku", "CC9EA2": "LG", "00E04C": "Realtek", "DC4427": "LG",
}


async def _prom_leases() -> list[dict]:
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(PROM + "/api/v1/query", params={"query": "mktxp_dhcp_lease_info"})
            r.raise_for_status()
            rows = r.json()["data"]["result"]
    except Exception as e:
        log.warning("could not read DHCP leases: %s", e)
        return []
    out = []
    for m in rows:
        lbl = m["metric"]
        if lbl.get("address"):
            out.append({"ip": lbl["address"], "mac": (lbl.get("mac_address") or "").upper(),
                        "hostname": lbl.get("host_name") or lbl.get("comment") or ""})
    return out


async def _router_topology() -> tuple[dict, dict, str | None]:
    """(mac->port, ip->mac, router_host) from the MikroTik. Needs the vault unlocked; empty if unavailable."""
    from . import remediation
    try:
        router = remediation._router().host
        out = await remediation._routeros(
            ':foreach h in=[/interface bridge host find where !local] do={'
            ':put ("host|" . [/interface bridge host get $h mac-address] . "|" . [/interface bridge host get $h on-interface])}\n'
            ':foreach a in=[/ip arp find where complete=yes] do={'
            ':put ("arp|" . [/ip arp get $a address] . "|" . [/ip arp get $a mac-address] . "|" . [/ip arp get $a interface])}')
    except Exception as e:
        log.info("router topology unavailable (vault locked or no MikroTik): %s", e)
        return {}, {}, None
    mac_port, ip_mac = {}, {}
    for line in out.splitlines():
        p = line.strip().split("|")
        if p[0] == "host" and len(p) >= 3:
            mac_port[p[1].upper()] = p[2]
        elif p[0] == "arp" and len(p) >= 4:
            ip_mac[p[1]] = {"mac": p[2].upper(), "iface": p[3]}
    return mac_port, ip_mac, router


def _vendor(mac: str) -> str:
    return OUI.get(mac.replace(":", "").replace("-", "").upper()[:6], "")


def load() -> dict:
    return json.loads(GRAPH.read_text()) if GRAPH.is_file() else {"time": None, "nodes": [], "links": []}


# Manual interface assignments, for devices whose physical port the router topology couldn't tell us (vault
# locked, a dumb switch in between, a static-IP device with no DHCP lease). {device_id: "ether3"}.
_IFACES = DIR / "interfaces.json"
_COMMON_IFACES = ["ether1", "ether2", "ether3", "ether4", "ether5", "sfp1",
                  "wifi1", "wifi2", "wlan1", "wlan2", "bridge"]


def iface_overrides() -> dict[str, str]:
    try:
        return json.loads(_IFACES.read_text())
    except (OSError, ValueError):
        return {}


def set_interface(device_id: str, iface: str | None) -> None:
    """Assign (or, with iface None/"" , clear) a device's physical interface manually."""
    ov = iface_overrides()
    if iface:
        ov[device_id] = iface.strip()
    else:
        ov.pop(device_id, None)
    DIR.mkdir(parents=True, exist_ok=True)
    tmp = _IFACES.with_suffix(".tmp")
    tmp.write_text(json.dumps(ov, indent=1))
    tmp.replace(_IFACES)


def view() -> dict:
    """The stored graph with manual interface assignments overlaid, plus interface suggestions for editing.
    Overlaying at read time means an edit shows up immediately, without re-running a router scan."""
    g = load()
    ov = iface_overrides()
    for n in g.get("nodes", []):
        if n.get("category") in ("device", "unknown") and n.get("device_id") in ov:
            n["port"] = ov[n["device_id"]]
            n["port_manual"] = True
    ports = {n["port"] for n in g.get("nodes", []) if n.get("port")} | set(ov.values())
    g["iface_options"] = sorted(ports | set(_COMMON_IFACES))
    return g


async def build() -> dict:
    DIR.mkdir(parents=True, exist_ok=True)
    devices = inventory.load()
    by_ip = {d.host: d for d in devices}
    by_mac: dict[str, object] = {}

    leases = await _prom_leases()
    mac_port, ip_mac, router_host = await _router_topology()
    for lease in leases:                       # let leases fill in MACs for inventory devices
        dev = by_ip.get(lease["ip"])
        if dev and lease["mac"]:
            by_mac[lease["mac"]] = dev

    nodes: list[dict] = []
    links: list[dict] = []
    seen_ports: set[str] = set()

    # Router + internet
    router = next((d for d in devices if d.type == "mikrotik"), None)
    router_id = router.id if router else "router"
    router_name = router.name if router else (router_host or "Router")
    nodes.append({"id": router_id, "name": router_name, "category": "router",
                  "ip": router.host if router else router_host, "status": state.get(router.id).status if router else "unknown"})
    nodes.append({"id": "internet", "name": "Internet", "category": "internet"})
    links.append({"source": "internet", "target": router_id})

    def port_node(port: str) -> str:
        pid = "port:" + port
        if port not in seen_ports:
            seen_ports.add(port)
            nodes.append({"id": pid, "name": port, "category": "port"})
            links.append({"source": router_id, "target": pid})
        return pid

    # Merge inventory devices and discovered leases into one set, keyed by IP.
    merged: dict[str, dict] = {}
    for d in devices:
        if d.type == "mikrotik":
            continue
        merged[d.host] = {"ip": d.host, "mac": "", "name": d.name, "type": d.type, "known": True,
                          "status": state.get(d.id).status, "device_id": d.id, "protected": d.protected}
    for lease in leases:
        row = merged.get(lease["ip"])
        if row:
            row["mac"] = row["mac"] or lease["mac"]
        else:
            merged[lease["ip"]] = {"ip": lease["ip"], "mac": lease["mac"],
                                   "name": lease["hostname"] or lease["ip"], "type": "unknown",
                                   "known": False, "status": "unknown", "device_id": None, "protected": False}

    for ip, row in merged.items():
        mac = row["mac"] or (ip_mac.get(ip, {}).get("mac", ""))
        port = mac_port.get(mac) or ip_mac.get(ip, {}).get("iface")
        nid = row["device_id"] or ("lease:" + ip)
        cat = "device" if row["known"] else "unknown"
        nodes.append({"id": nid, "name": row["name"], "category": cat, "ip": ip, "mac": mac,
                      "vendor": _vendor(mac), "type": row["type"], "status": row["status"],
                      "known": row["known"], "port": port, "device_id": row["device_id"]})
        links.append({"source": port_node(port) if port else router_id, "target": nid})

    graph = {
        "time": time.time(),
        "topology": "router" if (mac_port or ip_mac) else ("leases" if leases else "inventory"),
        "counts": {"devices": sum(1 for n in nodes if n["category"] in ("device", "unknown")),
                   "unknown": sum(1 for n in nodes if n["category"] == "unknown"),
                   "ports": len(seen_ports)},
        "nodes": nodes, "links": links,
    }
    GRAPH.write_text(json.dumps(graph, indent=1))
    return graph


# ---------------------------------------------------------------- traffic layer ("who talks to whom")

def _ip(addr: str | None) -> str | None:
    """IPv4 out of a RouterOS 'ip:port' address; None for IPv6 or empty (we map the IPv4 LAN)."""
    if not addr or "." not in addr:
        return None
    return addr.rsplit(":", 1)[0] if ":" in addr else addr


async def _conntrack() -> list[tuple]:
    from . import remediation
    out = await remediation._routeros(
        ':foreach c in=[/ip firewall connection find] do={'
        ':put ([/ip firewall connection get $c src-address] . "|" . [/ip firewall connection get $c dst-address] . "|"'
        ' . [/ip firewall connection get $c protocol] . "|" . [/ip firewall connection get $c orig-bytes] . "|"'
        ' . [/ip firewall connection get $c repl-bytes])}')
    rows = []
    for line in out.splitlines():
        p = line.strip().split("|")
        if len(p) >= 5:
            rows.append((p[0], p[1], p[2], p[3], p[4]))
    return rows


def load_traffic() -> dict:
    return json.loads(TRAFFIC.read_text()) if TRAFFIC.is_file() else {"time": None, "flows": [], "external": []}


async def build_traffic() -> dict:
    """Aggregate the router's connection tracking into device→device and device→internet flows."""
    DIR.mkdir(parents=True, exist_ok=True)
    graph = load()
    if not graph["nodes"]:
        graph = await build()
    ip_node = {n["ip"]: n["id"] for n in graph["nodes"] if n.get("ip")}
    names = {n["id"]: n["name"] for n in graph["nodes"]}
    router_id = next((n["id"] for n in graph["nodes"] if n["category"] == "router"), "router")

    try:
        conns = await _conntrack()
    except Exception as e:
        log.info("conntrack unavailable (vault locked or no MikroTik): %s", e)
        conns = []

    agg: dict[tuple, list] = {}            # (src_id, dst_id) -> [conns, bytes]
    ext: dict[str, dict] = {}              # src_id -> {bytes, conns, dsts}
    for src, dst, _proto, ob, rb in conns:
        si, di = _ip(src), _ip(dst)
        if not si or si not in ip_node:    # only flows that start at a known LAN node
            continue
        src_id = ip_node[si]
        if src_id == router_id:
            continue
        try:
            b = int(ob or 0) + int(rb or 0)
        except ValueError:
            b = 0
        if di and di in ip_node:
            dst_id = ip_node[di]
            if dst_id == src_id:
                continue
        elif di and RFC1918.match(di):
            continue                       # internal but not a known node: skip
        else:
            dst_id = "internet"
            e = ext.setdefault(src_id, {"bytes": 0, "conns": 0, "dsts": {}})
            e["bytes"] += b
            e["conns"] += 1
            if di:
                e["dsts"][di] = e["dsts"].get(di, 0) + b
        a = agg.setdefault((src_id, dst_id), [0, 0])
        a[0] += 1
        a[1] += b

    flows = [{"source": s, "target": t, "conns": c, "bytes": b} for (s, t), (c, b) in agg.items()]
    flows.sort(key=lambda f: -f["bytes"])
    flows = flows[:MAX_EDGES]
    external = [{"device": d, "device_name": names.get(d, d), "bytes": v["bytes"], "conns": v["conns"],
                "top": sorted(v["dsts"].items(), key=lambda x: -x[1])[:5]} for d, v in ext.items()]
    external.sort(key=lambda x: -x["bytes"])
    data = {"time": time.time(), "flows": flows, "external": external,
            "counts": {"flows": len(flows), "internal": sum(1 for f in flows if f["target"] != "internet"),
                       "external": sum(1 for f in flows if f["target"] == "internet"),
                       "conntrack": len(conns)}}
    TRAFFIC.write_text(json.dumps(data, indent=1))
    return data


async def scheduler() -> None:
    from . import features
    await asyncio.sleep(75)
    while True:
        if features.enabled("map"):
            try:
                await build()
                await build_traffic()
            except Exception:
                log.exception("network map build failed")
        await asyncio.sleep(900)
