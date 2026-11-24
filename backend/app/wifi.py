"""Wi-Fi / RF telemetry from the MikroTik — read-only.

Phase 1 of the RF Optimizer: a live snapshot of the radios and their associated clients, parsed from the
RouterOS wifiwave2 CLI over the same vault-gated SSH the remediation module uses. Nothing here changes the
router; channel planning and apply come in later phases. The scheduler/collector only runs while the "wifi"
feature is enabled.
"""
import json
import logging
import re
import time

from . import inventory, remediation, settings

log = logging.getLogger("netops.wifi")

_SCAN_STATE = settings.DATA_DIR / "wifi_scan.json"

# One script, two record types: RADIO| per interface and STA| per associated client. `as-value` on monitor
# gives us the live operating channel/power/peer counts without scraping the human-formatted table.
_SCRIPT = (
    ':foreach i in=[/interface/wifi find] do={'
    ' :local m [/interface/wifi monitor $i once as-value];'
    ' :put ("RADIO|" . [/interface/wifi get $i name] . "|" . [/interface/wifi get $i configuration.ssid]'
    ' . "|" . ($m->"channel") . "|" . ($m->"tx-power") . "|" . ($m->"registered-peers")'
    ' . "|" . ($m->"authorized-peers")) }\n'
    ':foreach r in=[/interface/wifi registration-table find] do={'
    ' :put ("STA|" . [/interface/wifi registration-table get $r interface]'
    ' . "|" . [/interface/wifi registration-table get $r mac-address]'
    ' . "|" . [/interface/wifi registration-table get $r signal]'
    ' . "|" . [/interface/wifi registration-table get $r band]'
    ' . "|" . [/interface/wifi registration-table get $r uptime]'
    ' . "|" . [/interface/wifi registration-table get $r tx-rate]'
    ' . "|" . [/interface/wifi registration-table get $r rx-rate]'
    ' . "|" . [/interface/wifi registration-table get $r dhcp-hostname]) }'
)

_PHY_LABEL = {"ax": "Wi-Fi 6", "ac": "Wi-Fi 5", "n": "Wi-Fi 4", "a": "legacy a", "g": "legacy g", "b": "legacy b"}


def _freq_to_channel(freq: int) -> int:
    if 2400 <= freq <= 2500:
        return 14 if freq == 2484 else (freq - 2407) // 5
    if 5000 <= freq <= 5900:
        return (freq - 5000) // 5
    if 5925 <= freq <= 7125:                      # 6 GHz, should the hardware ever support it
        return (freq - 5950) // 5
    return 0


def _parse_channel(chan: str) -> dict:
    """'5280/ax/eCee/DI' -> freq 5280, phy ax, 80 MHz, DFS, indoor. Width comes from the length of the
    primary-position code (Ce=40, Ceee=80, …); a bare freq/phy means 20 MHz."""
    parts = chan.split("/")
    freq = int(parts[0]) if parts and parts[0].isdigit() else 0
    phy = parts[1] if len(parts) > 1 else ""
    code = parts[2] if len(parts) > 2 and re.fullmatch(r"[Ce]+", parts[2]) else ""
    flags = parts[-1] if len(parts) > 2 else ""
    width = {0: 20, 1: 20, 2: 40, 4: 80, 8: 160}.get(len(code), 20)
    return {
        "frequency": freq, "channel": _freq_to_channel(freq), "phy": phy, "width_mhz": width,
        "dfs": "D" in flags, "indoor": "I" in flags,
        "band": "2.4" if freq < 3000 else ("5" if freq < 5925 else "6"),
    }


def _uptime_s(v: str) -> int:
    v = v.strip()
    if ":" in v:                                   # 00:03:25
        h, m, s = (v.split(":") + ["0", "0"])[:3]
        return int(h) * 3600 + int(m) * 60 + int(float(s))
    total, num = 0, ""
    for ch in v:                                   # 22h7m15s
        if ch.isdigit():
            num += ch
        elif num:
            total += int(num) * {"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1}.get(ch, 0)
            num = ""
    return total


def _mac_index() -> dict[str, dict]:
    """MAC -> {id, name} for the devices we know, so a client row can link to its device page."""
    idx: dict[str, dict] = {}
    for d in inventory.load():
        for v in list(d.facts.values()) + [d.host]:
            if isinstance(v, str) and re.fullmatch(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", v.strip()):
                idx[v.strip().upper()] = {"id": d.id, "name": d.name}
    return idx


def _client_issues(c: dict) -> list[str]:
    out = []
    best = max(c["tx_mbps"], c["rx_mbps"])
    if c["band"].startswith("2.4") and c["phy"] in ("ax", "ac"):
        out.append("5 GHz-capable but on 2.4 GHz")
    if c["signal"] <= -70:
        out.append("weak signal")
    if c["phy"] in ("a", "g", "b"):
        out.append("legacy device (airtime-expensive)")
    elif best and best < 50 and c["signal"] > -60:
        out.append("low PHY rate for its signal")
    return out


def _radio_findings(radios: list[dict], clients: list[dict]) -> list[dict]:
    out = []
    for r in radios:
        if r["band"] == "2.4" and r["width_mhz"] >= 40:
            out.append({"level": "warning", "radio": r["name"],
                        "title": "2.4 GHz is %d MHz wide" % r["width_mhz"],
                        "detail": "2.4 GHz only fits three non-overlapping channels (1/6/11). Use 20 MHz."})
        if r["band"] == "5" and r["dfs"]:
            out.append({"level": "info", "radio": r["name"],
                        "title": "5 GHz on a DFS channel (%d)" % r["channel"],
                        "detail": "A radar detection event can force a channel change and a brief outage. "
                                  "A non-DFS channel (36–48) is steadier for streaming."})
    misplaced = [c for c in clients if "5 GHz-capable but on 2.4 GHz" in c["issues"]]
    if misplaced:
        out.append({"level": "warning", "radio": "",
                    "title": "%d client(s) on 2.4 GHz could use 5 GHz" % len(misplaced),
                    "detail": ", ".join(c["name"] for c in misplaced) + " — move to the 5 GHz SSID or enable band steering."})
    return out


def _score(radios: list[dict], clients: list[dict]) -> int:
    score = 100
    for r in radios:
        if r["band"] == "2.4" and r["width_mhz"] >= 40:
            score -= 25
        if r["band"] == "5" and r["dfs"]:
            score -= 15
    for c in clients:
        if "5 GHz-capable but on 2.4 GHz" in c["issues"]:
            score -= 10
        if "weak signal" in c["issues"]:
            score -= 5
    return max(0, min(100, score))


# ---------------------------------------------------------------- channel planner (phase 2)
#
# Given the neighbours we scanned, rank the channels this router could sit on and recommend the clearest
# one per band. Pure function of (radios, neighbours) so it can be unit-tested and, later, feed a one-click
# apply through the remediation approval path. The model is deliberately simple and explainable:
#   cost(candidate) = Σ over overlapping neighbours of  (overlap MHz / candidate width) · weight(signal)
# where weight maps dBm onto 0..1 the same way the UI's signal bars do (−30 → 1, −90 → 0). Lower is better.
# We only count *other people's* networks — our own radio is the thing we're moving, so it isn't interference.

_WIDTH_STR = {20: "20mhz", 40: "20/40mhz", 80: "20/40/80mhz", 160: "20/40/80/160mhz"}

# 2.4 GHz: only 1 / 6 / 11 don't overlap, always at 20 MHz.
_2G_CANDS = [(1, False, ""), (6, False, ""), (11, False, "")]
# 5 GHz 80-MHz blocks usable indoors under ETSI (Switzerland): UNII-1 is non-DFS; the rest are DFS. We leave
# out UNII-3 (5.8 GHz), which ETSI doesn't permit for Wi-Fi, so every recommendation stays legal to apply.
_5G_CANDS = [
    (36, False, "UNII-1 · non-DFS, steadiest for streaming"),
    (52, True, "UNII-2A · DFS, radar may force a hop"),
    (100, True, "UNII-2C · DFS, radar may force a hop"),
]
_DFS_PENALTY = 0.35          # a DFS channel must be clearly clearer than UNII-1 to win (in cost units)


def _ch_freq(ch: int, band: str) -> int:
    return (2407 if band == "2.4" else 5000) + ch * 5


def _weight(signal: int) -> float:
    return max(0.0, min(1.0, (signal + 90) / 60))


def _channel_cost(center: float, width: int, band: str, neighbors: list[dict]) -> tuple[float, int]:
    """Signal-weighted spectral overlap of a candidate [center ± width/2] against the neighbours on its band."""
    c_lo, c_hi = center - width / 2, center + width / 2
    cost, n = 0.0, 0
    for nb in neighbors:
        if nb["band"] != band:
            continue
        a_lo = nb["frequency"] - nb["width_mhz"] / 2
        a_hi = nb["frequency"] + nb["width_mhz"] / 2
        overlap = max(0.0, min(c_hi, a_hi) - max(a_lo, c_lo))
        if overlap <= 0:
            continue
        cost += (overlap / width) * _weight(nb["signal"])
        n += 1
    return cost, n


def _plan_reason(band: str, cur: dict | None, best: dict) -> str:
    where = "channel %d at %d MHz" % (best["channel"], best["width_mhz"])
    if not cur:
        return "No radio is active on this band; %s is the clearest option." % where
    if cur["channel"] == best["channel"] and cur["width_mhz"] == best["width_mhz"]:
        return "Already on the clearest channel (%s) — no change needed." % where
    bits = []
    if cur["channel"] != best["channel"]:
        bits.append("move from channel %d to %d" % (cur["channel"], best["channel"]))
    if cur["width_mhz"] != best["width_mhz"]:
        bits.append("narrow to %d MHz" % best["width_mhz"] if best["width_mhz"] < cur["width_mhz"]
                    else "set width to %d MHz" % best["width_mhz"])
    tail = " — it's clear of other networks" if best["networks"] == 0 else " — the least congested usable channel"
    if band == "2.4":
        tail += "; 2.4 GHz only has three non-overlapping channels (1 / 6 / 11)."
    elif not best["dfs"]:
        tail += "; non-DFS avoids radar-driven channel changes."
    else:
        tail += "."
    return "Recommend: " + " and ".join(bits) + tail


def _plan_band(band: str, cands: list[tuple], width: int, cur: dict | None, neighbors: list[dict]) -> dict:
    rows = []
    for ch, dfs, note in cands:
        pf = _ch_freq(ch, band)
        center = pf - 10 + width / 2                 # primary freq → block centre (20→+0, 40→+10, 80→+30)
        cost, n = _channel_cost(center, width, band, neighbors)
        rows.append({"channel": ch, "frequency": pf, "width_mhz": width, "dfs": dfs, "note": note,
                     "networks": n, "congestion": round(cost * 100),
                     "current": bool(cur) and cur["channel"] == ch,
                     "_rank": cost + (_DFS_PENALTY if dfs else 0)})
    best = min(rows, key=lambda r: r["_rank"])
    for r in rows:
        r["recommended"] = r is best
        r.pop("_rank")
    rows.sort(key=lambda r: r["channel"])
    change = (not cur) or cur["channel"] != best["channel"] or cur["width_mhz"] != width
    return {"band": band, "current": cur, "recommended": best, "change": change,
            "candidates": rows, "reason": _plan_reason(band, cur, best)}


def _plan(radios: list[dict], neighbors: list[dict]) -> dict:
    """Per-band channel recommendation plus the exact (manual) RouterOS command to apply it."""
    by_band = {r["band"]: r for r in radios}
    bands, cmds, rollbacks = [], [], []
    for band, cands, width in (("2.4", _2G_CANDS, 20), ("5", _5G_CANDS, 80)):
        p = _plan_band(band, cands, width, by_band.get(band), neighbors)
        bands.append(p)
        cur = by_band.get(band)
        if cur and p["change"]:
            cmds.append("/interface/wifi set %s channel.frequency=%d channel.width=%s"
                        % (cur["name"], p["recommended"]["frequency"], _WIDTH_STR[width]))
            rollbacks.append('/interface/wifi set %s channel.frequency="" channel.width=""' % cur["name"])
    return {"bands": bands, "command": "; ".join(cmds), "rollback": "; ".join(rollbacks)}


# A scan row: [flags] BSSID  SSID (may contain spaces or be empty)  FREQ/phy[/code][/flags]  SECURITY  SIGNAL  [STA]
# We anchor on the BSSID and the distinctive channel token, so a space-filled SSID parses cleanly; wrapped
# continuation lines (extra security modes, no BSSID) simply don't match and are skipped.
_SCAN_RE = re.compile(
    r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\s+(.*?)\s+(\d{3,4}/\S+)\s+(\S*?)\s*(-\d+)\s*(\d*)\s*$")


def _parse_scan(text: str) -> list[dict]:
    """Dedupe a (repeatedly reprinted) scan table by BSSID, keeping the strongest sighting."""
    best: dict[str, dict] = {}
    for line in text.splitlines():
        m = _SCAN_RE.search(line.strip())
        if not m:
            continue
        bssid, ssid, chan, sec, sig, sta = m.groups()
        ch = _parse_channel(chan)
        if not ch["frequency"]:
            continue
        signal = int(sig)
        prev = best.get(bssid.upper())
        if prev and prev["signal"] >= signal:
            continue
        name = ssid.strip() or "(hidden)"
        low = name.lower()
        best[bssid.upper()] = {
            "bssid": bssid.upper(), "ssid": name, "frequency": ch["frequency"], "channel": ch["channel"],
            "band": ch["band"], "width_mhz": ch["width_mhz"], "signal": signal,
            "security": sec or "open", "stations": int(sta) if sta else None,
            "note": "your work SD-WAN" if ("velocloud" in low or low == "vc-wifi") else "",
        }
    return sorted(best.values(), key=lambda n: (n["band"], -n["signal"]))


async def scan(duration: int = 5) -> dict:
    """Run a neighbour scan on every radio and persist the result. Briefly de-auths clients per radio."""
    names = [ln.strip() for ln in (await remediation._routeros(
        ':foreach i in=[/interface/wifi find] do={ :put [/interface/wifi get $i name] }')).splitlines() if ln.strip()]
    raw = ""
    for name in names:
        raw += await remediation._routeros("/interface/wifi scan %s duration=%ds" % (name, duration)) + "\n"
    data = {"time": time.time(), "neighbors": _parse_scan(raw)}
    settings.DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = _SCAN_STATE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=1))
    tmp.replace(_SCAN_STATE)
    return data


def load_scan() -> dict:
    try:
        return json.loads(_SCAN_STATE.read_text())
    except (OSError, ValueError):
        return {"time": None, "neighbors": []}


async def snapshot() -> dict:
    """Live radios + clients, plus the last persisted neighbour scan. available=False if unreachable."""
    sc = load_scan()
    try:
        out = await remediation._routeros(_SCRIPT)
    except Exception as e:                          # noqa: BLE001 — surface, don't crash the API
        log.warning("wifi snapshot failed: %s", e)
        return {"available": False, "error": "%s: %s" % (type(e).__name__, e), "time": time.time(),
                "radios": [], "clients": [], "findings": [], "score": None,
                "neighbors": sc["neighbors"], "scan_time": sc["time"],
                "plan": _plan([], sc["neighbors"])}

    macs = _mac_index()
    radios, clients = [], []
    for line in out.splitlines():
        f = line.rstrip().split("|")
        if f[0] == "RADIO" and len(f) >= 7:
            ch = _parse_channel(f[3])
            radios.append({"name": f[1], "ssid": f[2], **ch,
                           "tx_power": int(f[4]) if f[4].lstrip("-").isdigit() else None,
                           "peers": int(f[5] or 0), "authorized": int(f[6] or 0)})
        elif f[0] == "STA" and len(f) >= 9:
            mac = f[2].upper()
            dev = macs.get(mac, {})
            phy = f[4].split("-")[-1]                # 2ghz-ax -> ax
            c = {
                "interface": f[1], "mac": mac, "device_id": dev.get("id"),
                "name": dev.get("name") or f[8] or mac,
                "signal": int(f[3]) if f[3].lstrip("-").isdigit() else 0,
                "band": "2.4" if f[4].startswith("2") else ("5" if f[4].startswith("5") else "6"),
                "phy": phy, "phy_label": _PHY_LABEL.get(phy, phy),
                "uptime_s": _uptime_s(f[5]),
                "tx_mbps": round(int(f[6] or 0) / 1e6, 1), "rx_mbps": round(int(f[7] or 0) / 1e6, 1),
            }
            c["issues"] = _client_issues(c)
            clients.append(c)

    clients.sort(key=lambda c: (c["band"], c["signal"]))
    return {"available": True, "error": None, "time": time.time(), "radios": radios,
            "clients": clients, "findings": _radio_findings(radios, clients),
            "score": _score(radios, clients), "neighbors": sc["neighbors"], "scan_time": sc["time"],
            "plan": _plan(radios, sc["neighbors"])}
