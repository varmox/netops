"""Have I Been Pwned integration for the security posture.

Two capabilities, both privacy-preserving:
  - Pwned Passwords (keyless, k-anonymity): check whether a password's SHA-1 appears in known breaches by
    sending only its first 5 hex chars. Used to test a password typed in the UI (the browser hashes it, so
    the password never reaches this box — only the hash does) and to audit the credentials this box already
    holds (service env vars + vault secrets), reporting which are breached without ever revealing them.
  - Breach lookup by email (needs a paid HIBP API key, HIBP_API_KEY): which breaches an address appears in.
"""
import hashlib
import logging
import os

import httpx

from . import db, settings, vault

log = logging.getLogger("netops.hibp")

_PWNED = "https://api.pwnedpasswords.com/range/"
_HIBP = "https://haveibeenpwned.com/api/v3"
_UA = "NetOps-SecurityPosture"


async def _range(prefix: str) -> dict[str, int]:
    """{SHA1-suffix: breach count} for a 5-hex-char prefix; padded so the response size reveals nothing."""
    async with httpx.AsyncClient(timeout=6) as c:
        r = await c.get(_PWNED + prefix, headers={"Add-Padding": "true", "User-Agent": _UA})
    r.raise_for_status()
    out: dict[str, int] = {}
    for line in r.text.splitlines():
        suf, _, cnt = line.partition(":")
        if suf:
            out[suf.strip().upper()] = int(cnt or 0)
    return out


async def password_count(sha1_prefix: str, sha1_suffix: str) -> int:
    """Breach count for a password whose SHA-1 is prefix(5)+suffix(35). The browser hashes; we only see this."""
    rng = await _range(sha1_prefix.upper()[:5])
    return rng.get(sha1_suffix.upper(), 0)


async def _count_for(value: str) -> int:
    d = hashlib.sha1(value.encode()).hexdigest().upper()
    rng = await _range(d[:5])
    return rng.get(d[5:], 0)


def _stored_credentials() -> list[tuple[str, str]]:
    """(label, value) for the passwords this box can see — values are hashed, never returned."""
    creds: list[tuple[str, str]] = []
    if settings.ADGUARD_PASSWORD:
        creds.append(("AdGuard admin", settings.ADGUARD_PASSWORD))
    for env in ("ZYXEL_PASSWORD", "GRAFANA_ADMIN_PASSWORD", "WEBUI_PASSWORD"):
        v = os.environ.get(env)
        if v:
            creds.append((env, v))
    if vault.unlocked():
        for row in db.query("SELECT name FROM vault WHERE kind = 'password' ORDER BY name"):
            try:
                creds.append(("vault: " + row["name"], vault.get(row["name"])))
            except Exception:                        # noqa: BLE001 — a bad secret shouldn't break the audit
                pass
    return creds


async def audit_stored() -> dict:
    """Check every password this box holds against Pwned Passwords. Reports status, never the value."""
    items = []
    for label, value in _stored_credentials():
        try:
            n = await _count_for(value)
            items.append({"source": label, "breached": n > 0, "count": n})
        except httpx.HTTPError as e:
            items.append({"source": label, "breached": None, "count": 0, "error": str(e)})
    return {"vault_unlocked": vault.unlocked(), "checked": len(items), "items": items}


async def account_breaches(email: str) -> dict:
    """Breaches an email appears in (needs HIBP_API_KEY). 404 from HIBP = clean, not an error."""
    if not settings.HIBP_API_KEY:
        return {"configured": False, "email": email, "breaches": []}
    try:
        async with httpx.AsyncClient(timeout=12) as c:
            r = await c.get("%s/breachedaccount/%s?truncateResponse=false" % (_HIBP, email),
                            headers={"hibp-api-key": settings.HIBP_API_KEY, "User-Agent": _UA})
        if r.status_code == 404:
            return {"configured": True, "email": email, "breaches": []}
        r.raise_for_status()
        breaches = [{"name": b.get("Name"), "title": b.get("Title"), "domain": b.get("Domain"),
                     "date": b.get("BreachDate"), "count": b.get("PwnCount"),
                     "data": b.get("DataClasses", []), "verified": b.get("IsVerified", False)}
                    for b in r.json()]
        return {"configured": True, "email": email, "breaches": breaches}
    except httpx.HTTPStatusError as e:
        return {"configured": True, "email": email, "breaches": [], "error": "HIBP returned %s" % e.response.status_code}
    except httpx.HTTPError as e:
        return {"configured": True, "email": email, "breaches": [], "error": str(e)}


def status() -> dict:
    return {"account_lookup": bool(settings.HIBP_API_KEY)}
