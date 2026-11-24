"""Health checks: ICMP ping, TCP connect, HTTP(S) GET. Each returns (ok, latency_ms, detail)."""
import asyncio
import re
import time

import httpx

Result = tuple[bool, float | None, str]


async def ping(host: str, timeout: float = 2.0) -> Result:
    proc = await asyncio.create_subprocess_exec(
        "ping", "-c", "1", "-W", str(int(timeout)), host,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    out, _ = await proc.communicate()
    m = re.search(rb"time[=<]([\d.]+) ?ms", out)
    if proc.returncode == 0 and m:
        return True, float(m.group(1)), "reply"
    return False, None, "no reply"


async def tcp(host: str, port: int, timeout: float = 3.0) -> Result:
    start = time.monotonic()
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except (OSError, asyncio.TimeoutError) as e:
        return False, None, "port %d closed (%s)" % (port, type(e).__name__)
    writer.close()
    return True, (time.monotonic() - start) * 1000, "port %d open" % port


async def http(url: str, timeout: float = 5.0) -> Result:
    start = time.monotonic()
    try:
        async with httpx.AsyncClient(verify=False, timeout=timeout, follow_redirects=False) as c:
            r = await c.get(url)
    except httpx.HTTPError as e:
        return False, None, type(e).__name__
    ok = r.status_code < 500
    return ok, (time.monotonic() - start) * 1000, "HTTP %d" % r.status_code


async def run(host: str, check: dict) -> Result:
    kind = check["type"]
    if kind == "ping":
        return await ping(host)
    if kind == "tcp":
        return await tcp(host, int(check["target"]))
    if kind == "http":
        return await http(check["target"])
    return False, None, "unknown check type %r" % kind


def label(check: dict) -> str:
    kind, target = check["type"], check.get("target")
    if kind == "http":
        return "https" if str(target).startswith("https:") else "http"
    return kind if target is None else "%s:%s" % (kind, target)
