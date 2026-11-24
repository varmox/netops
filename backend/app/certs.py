"""TLS certificate watch (feature 3): for every device with an https/tls check, read the certificate,
warn before it expires, and flag weak or self-signed certificates and obsolete TLS versions.

Everything happens on the LAN; no certificate or host name leaves the box. Results are stored in
data/certs/state.json and surfaced on the Security page and the per-device timeline.
"""
import asyncio
import json
import logging
import socket
import ssl
import time

from . import alerts, inventory, settings

log = logging.getLogger("netops.certs")

DIR = settings.DATA_DIR / "certs"
STATE = DIR / "state.json"
WEAK_TLS = {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}


def _targets() -> list[tuple[str, int, object]]:
    """(host, port, device) for each device that has an https/tls check or an https link."""
    out = []
    for dev in inventory.load():
        ports = set()
        for c in dev.checks:
            if c["type"] in ("https", "tls"):
                ports.add(int(c.get("target") or 443))
            elif c["type"] == "tcp" and int(c.get("target") or 0) in (443, 8443, 9443):
                ports.add(int(c["target"]))
        if dev.facts.get("tls_port"):
            ports.add(int(dev.facts["tls_port"]))
        for p in ports:
            out.append((dev.host, p, dev))
    return out


def _probe(host: str, port: int) -> dict:
    """Blocking TLS handshake; run in a thread. Returns the certificate facts or an error."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE          # we inspect the cert ourselves; LAN devices are often self-signed
    ctx.minimum_version = ssl.TLSVersion.SSLv3
    try:
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
                version = ssock.version()
                cipher = ssock.cipher()
    except (OSError, ssl.SSLError) as e:
        return {"error": "%s: %s" % (type(e).__name__, e)}
    cert = _parse_cert(der)
    cert.update({"tls_version": version, "cipher": cipher[0] if cipher else None, "error": None})
    return cert


def _parse_cert(der: bytes) -> dict:
    """Subject, issuer and validity from the DER, using cryptography (already a dependency)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID
    cert = x509.load_der_x509_certificate(der)

    def cn(name) -> str | None:
        attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        return attrs[0].value if attrs else None

    try:
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    sig = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None

    return {
        "subject_cn": cn(cert.subject),
        "issuer_cn": cn(cert.issuer),
        "self_signed": cert.subject == cert.issuer,
        "expires": cert.not_valid_after_utc.timestamp(),
        "not_before": cert.not_valid_before_utc.timestamp(),
        "fingerprint": cert.fingerprint(hashes.SHA256()).hex()[:32],
        "sans": sans[:16],
        "key_bits": getattr(cert.public_key(), "key_size", None),
        "sig_algo": sig,
    }


def _findings_from(host: str, port: int, dev, cert: dict) -> list[dict]:
    """Human-readable findings for one certificate (expiry, weak TLS, self-signed on a non-protected box)."""
    out = []
    now = time.time()
    exp = cert.get("expires")
    if exp is not None:
        days = int((exp - now) / 86400)
        if days < 0:
            out.append(("critical", "Certificate expired %d days ago" % -days))
        elif days <= settings.CERT_WARN_DAYS:
            out.append(("warning", "Certificate expires in %d days" % days))
    if cert.get("tls_version") in WEAK_TLS:
        out.append(("warning", "Obsolete %s offered" % cert["tls_version"]))
    return [{"host": host, "port": port, "device": dev.id, "device_name": dev.name,
             "level": lvl, "text": txt} for lvl, txt in out]


def load() -> dict:
    return json.loads(STATE.read_text()) if STATE.is_file() else {"time": None, "certs": []}


async def scan() -> dict:
    DIR.mkdir(parents=True, exist_ok=True)
    targets = _targets()
    certs, findings, changes = [], [], []
    prev = {("%s:%d" % (c["host"], c["port"])): c for c in load()["certs"]}
    for host, port, dev in targets:
        cert = await asyncio.to_thread(_probe, host, port)
        key = "%s:%d" % (host, port)
        row = {"host": host, "port": port, "device": dev.id, "device_name": dev.name, **cert}
        certs.append(row)
        if cert.get("error"):
            continue
        findings += _findings_from(host, port, dev, cert)
        old = prev.get(key)
        if old and old.get("fingerprint") and old["fingerprint"] != cert.get("fingerprint"):
            changes.append(row)
    STATE.write_text(json.dumps({"time": time.time(), "certs": certs}, indent=1))
    for c in changes:
        await alerts.notify("Certificate changed on %s" % c["device_name"],
                            "%s:%d now presents a different certificate (CN %s)." % (c["host"], c["port"], c.get("subject_cn")),
                            "info", c["device"])
    for f in findings:
        if f["level"] in ("warning", "critical"):
            await alerts.notify("%s on %s" % (f["text"], f["device_name"]),
                                "%s:%d" % (f["host"], f["port"]), f["level"], f["device"])
    return {"checked": len(certs), "findings": len(findings), "changed": len(changes)}


async def scheduler() -> None:
    from . import features
    from .jobs import _seconds_until
    await asyncio.sleep(45)
    while True:
        if features.enabled("certs"):
            try:
                await scan()
            except Exception:
                log.exception("certificate scan failed")
        await asyncio.sleep(_seconds_until(settings.CERT_SCAN_TIME))
