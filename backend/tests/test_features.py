"""Pure-logic tests for the added features (no network, no VM). Run:
  docker compose exec -T backend python - < backend/tests/test_features.py
or in the python image with requirements installed."""
import os
import tempfile
import time

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("DEVICES_FILE", os.path.join(tempfile.mkdtemp(), "devices.yml"))
open(os.environ["DEVICES_FILE"], "w").write("devices: []\n")

from app import certs, credcheck, exposure, honeypot, lifecycle, report, timeline  # noqa: E402

ok = 0


def check(name, cond):
    global ok
    assert cond, "FAILED: " + name
    ok += 1


# ---- certs: cert parsing + expiry thresholds
def _self_signed(days):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    import datetime
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "box.lan")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=days))
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.DER)


c = certs._parse_cert(_self_signed(10))
check("cert cn", c["subject_cn"] == "box.lan")
check("cert self-signed", c["self_signed"] is True)
check("cert expiry soon", 9 <= (c["expires"] - time.time()) / 86400 <= 11)


class Dev:
    id, name = "d1", "Box"


f = certs._findings_from("10.0.0.1", 443, Dev, {"expires": time.time() + 5 * 86400, "tls_version": "TLSv1.3"})
check("cert warn <21d", any(x["level"] == "warning" and "expires in" in x["text"] for x in f))
f2 = certs._findings_from("10.0.0.1", 443, Dev, {"expires": time.time() - 86400, "tls_version": "TLSv1.3"})
check("cert expired critical", any(x["level"] == "critical" for x in f2))
f3 = certs._findings_from("10.0.0.1", 443, Dev, {"expires": time.time() + 400 * 86400, "tls_version": "TLSv1"})
check("cert weak tls", any("TLSv1" in x["text"] for x in f3))
check("cert fine no finding", certs._findings_from("10.0.0.1", 443, Dev,
      {"expires": time.time() + 400 * 86400, "tls_version": "TLSv1.3"}) == [])

# ---- lifecycle: EOL assessment
check("eol true", lifecycle._assess(True) == ("eol", None))
check("eol false", lifecycle._assess(False)[0] == "ok")
check("eol past date", lifecycle._assess("2000-01-01")[0] == "eol")
soon = time.strftime("%Y-%m-%d", time.localtime(time.time() + 30 * 86400))
check("eol warn soon", lifecycle._assess(soon)[0] == "warn")
far = time.strftime("%Y-%m-%d", time.localtime(time.time() + 400 * 86400))
check("eol ok far", lifecycle._assess(far)[0] == "ok")
check("eol cycle match", lifecycle._eol_for([{"cycle": "24.04", "eol": "2029-05-31", "latest": "24.04.1"}], "24.04")[0] == "2029-05-31")

# ---- credcheck: LAN guard
check("lan 192.168", credcheck._is_lan("192.168.1.5"))
check("lan 10", credcheck._is_lan("10.1.2.3"))
check("lan 172.16", credcheck._is_lan("172.16.0.9"))
check("not lan public", not credcheck._is_lan("8.8.8.8"))
check("not lan garbage", not credcheck._is_lan("example.com"))

# ---- exposure: RouterOS output parsing
sample = """=== upnp ===
true
=== upnp-active ===
8080|192.168.1.50|tcp|upnp 192.168.1.50: 8080
=== portforward ===
443|192.168.1.10|tcp|web
8080|192.168.1.50|tcp|upnp 192.168.1.50: 8080
=== input ===
22|tcp|WAN|ssh from wan
53|udp|LAN|dns
"""
d = exposure._parse(sample)
check("exp upnp enabled", d["upnp_enabled"] is True)
check("exp upnp mapping", d["upnp_mappings"][0]["port"] == "8080")
check("exp portforward", any(p["port"] == "443" for p in d["port_forwards"]))
check("exp input wan only", [a["port"] for a in d["input_accepts"]] == ["22"])
exps = exposure._exposures(d)
check("exp upnp is warning", any(e["kind"] == "upnp" and e["level"] == "warning" for e in exps))
check("exp dedup forward", not any(e["kind"] == "port-forward" and e["port"] == "8080" for e in exps))

# ---- honeypot: port parsing
hp = honeypot._ports()
check("honeypot ports parsed", (23, "telnet") in hp and (3389, "rdp") in hp)

# ---- timeline: version timestamp
check("timeline ts", timeline._version_ts("20260101-120000") > 0)
check("timeline ts bad", timeline._version_ts("nope") == 0.0)

# ---- report: text rendering
r = {"devices": 5, "findings_open": {"critical": 1, "high": 2, "medium": 0, "low": 0}, "kev": 1,
     "updates_applied": 3, "new_devices": [{"id": "x", "name": "New Thing"}], "down": ["Router"],
     "backups_failing": [], "certs_expiring": [{"device": "Box", "days": 4}], "end_of_life": [],
     "honeypot_hits": 2, "exposures": 1, "upnp_enabled": True, "compliance": None}
txt = report.as_text(r)
check("report critical", "1 critical" in txt)
check("report new device", "New Thing" in txt)
check("report cert", "Box (" in txt and "d)" in txt)
check("report honeypot", "Honeypot hits: 2" in txt)

print("features: %d checks passed" % ok)
