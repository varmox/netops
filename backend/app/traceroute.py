"""Traceroute — the path to a device, not just whether it answers.

Works inside the hardened, capability-dropped container (no CAP_NET_RAW, no raw sockets) by using Linux
"ping sockets" (unprivileged ICMP datagram sockets, the same kind the health-check ping uses) together with
IP_RECVERR: we send ICMP echoes with an increasing TTL and read the kernel's error queue to learn which
router sent back each "time exceeded". This is exactly how ``ping -t<ttl>`` reports an intermediate hop.

Hops that match a device in the inventory are labelled with the device's name.
"""
import asyncio
import socket
import struct
import time

from . import inventory

_ICMP_ECHO = 8
_IP_TTL = socket.IP_TTL
_IP_RECVERR = 11                       # <linux/in.h>, not exposed as a socket constant in Python


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def _probe(dest: str, ttl: int, seq: int, timeout: float) -> tuple[str | None, float | None, bool]:
    """One ICMP echo at the given TTL. Returns (responder_ip, rtt_ms, reached_destination)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
    try:
        s.setsockopt(socket.IPPROTO_IP, _IP_TTL, ttl)
        s.setsockopt(socket.IPPROTO_IP, _IP_RECVERR, 1)
        s.settimeout(timeout)
        ident = 0x4E54                 # 'NT'
        head = struct.pack("!BBHHH", _ICMP_ECHO, 0, 0, ident, seq)
        payload = b"netops-trace"
        pkt = struct.pack("!BBHHH", _ICMP_ECHO, 0, _checksum(head + payload), ident, seq) + payload
        t0 = time.monotonic()
        try:
            s.sendto(pkt, (dest, 0))
        except OSError:
            return None, None, False
        deadline = t0 + timeout
        while time.monotonic() < deadline:
            s.settimeout(max(0.01, deadline - time.monotonic()))
            # A normal reply means we reached the destination.
            try:
                _, addr = s.recvfrom(1024)
                return addr[0], round((time.monotonic() - t0) * 1000, 1), True
            except OSError:
                pass
            # The error queue carries the "time exceeded" from an intermediate router.
            try:
                _, anc, _, _ = s.recvmsg(1024, 1024, socket.MSG_ERRQUEUE)
                for _lvl, _typ, cdata in anc:
                    offender = cdata[16:]          # struct sock_extended_err (16 bytes) + sockaddr_in
                    if len(offender) >= 8:
                        ip = socket.inet_ntoa(offender[4:8])
                        return ip, round((time.monotonic() - t0) * 1000, 1), False
            except OSError:
                pass
        return None, None, False
    finally:
        s.close()


def _trace(dest: str, host: str, max_hops: int, timeout: float, probes: int) -> dict:
    names = {d.host: d.name for d in inventory.load()}
    hops = []
    reached = False
    for ttl in range(1, max_hops + 1):
        ip, best, hit = None, None, False
        for p in range(probes):
            r_ip, rtt, r_hit = _probe(dest, ttl, ttl * 10 + p, timeout)
            if r_ip:
                ip = ip or r_ip
                hit = hit or r_hit
                if rtt is not None:
                    best = rtt if best is None else min(best, rtt)
        hops.append({"ttl": ttl, "ip": ip, "name": names.get(ip) or (host if ip == dest else None),
                     "rtt_ms": best})
        if hit:
            reached = True
            break
    return {"host": host, "dest": dest, "hops": hops, "reached": reached, "time": time.time()}


async def trace(host: str, max_hops: int = 20, timeout: float = 1.0, probes: int = 2) -> dict:
    """Trace the network path to a host (IP or name). Read-only; safe to run any time."""
    try:
        dest = await asyncio.to_thread(socket.gethostbyname, host)
    except OSError as e:
        return {"host": host, "dest": None, "hops": [], "reached": False,
                "error": "could not resolve %s: %s" % (host, e), "time": time.time()}
    return await asyncio.to_thread(_trace, dest, host, max_hops, timeout, probes)
