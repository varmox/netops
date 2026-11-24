"""Zyxel ZCFG web API (GM4100, EX/VMG/DX series): reads the main config objects as one JSON snapshot.

Login: RSA-wrapped AES key, AES-256-CBC bodies (/UserLogin), then GET /cgi-bin/DAL?oid=... with a CSRFToken.
Read-only: the account only needs to be able to view settings. Values whose key looks like a secret are
redacted unless `redact: false` is set for the device.
"""
import asyncio
import base64
import json
import os
import re

import httpx
from cryptography.hazmat.primitives import padding as sympad
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .. import vault

OIDS = ["cardpage_status", "wan", "lan", "lanadv", "nat_conf", "firewall", "tr69", "time", "snmp",
        "ddns", "igmp_mld", "static_dhcp", "vlan_group", "intfgrp", "static_route", "lanhosts"]
SECRET = re.compile(r"(?i)(pass|psk|secret|token|key$|community)")
# Live counters and timestamps: left out of the comparison so a backup only counts as changed when config does.
VOLATILE = re.compile(r"(?i)(uptime|time$|^date$|lastchange|currentlocaltime|rate_?(rx|tx)|bytes|packets|"
                      r"rate$|currbitrate|leasetime_remain|active$)")


class ZyxelClient:
    def __init__(self, base: str):
        self.base = base.rstrip("/")
        self.http = httpx.Client(timeout=20, verify=False)
        self.key = os.urandom(32)
        self.iv = os.urandom(32)
        self.token = None

    def _enc(self, obj) -> str:
        p = sympad.PKCS7(128).padder()
        data = p.update(json.dumps(obj).encode()) + p.finalize()
        e = Cipher(algorithms.AES(self.key), modes.CBC(self.iv[:16])).encryptor()
        return base64.b64encode(e.update(data) + e.finalize()).decode()

    def _dec(self, r: httpx.Response):
        j = r.json()
        if "content" not in j:
            return j
        d = Cipher(algorithms.AES(self.key), modes.CBC(base64.b64decode(j["iv"])[:16])).decryptor()
        raw = d.update(base64.b64decode(j["content"])) + d.finalize()
        u = sympad.PKCS7(128).unpadder()
        return json.loads(u.update(raw) + u.finalize())

    def login(self, user: str, password: str) -> None:
        pem = self.http.get(self.base + "/getRSAPublickKey").json()["RSAPublicKey"]
        pub = serialization.load_pem_public_key(pem.encode())
        body = {
            "content": self._enc({"Input_Account": user, "Input_Passwd": base64.b64encode(password.encode()).decode(),
                                  "currLang": "en", "RememberPassword": 0, "SHA512_password": False}),
            "key": base64.b64encode(pub.encrypt(base64.b64encode(self.key), padding.PKCS1v15())).decode(),
            "iv": base64.b64encode(self.iv).decode(),
        }
        r = self._dec(self.http.post(self.base + "/UserLogin", json=body))
        if r.get("result") != "ZCFG_SUCCESS":
            raise RuntimeError("Zyxel login failed: %s" % r.get("result"))
        self.token = str(r.get("sessionkey"))

    def get(self, oid: str):
        return self._dec(self.http.get(self.base + "/cgi-bin/DAL", params={"oid": oid},
                                       headers={"CSRFToken": self.token}))

    def logout(self) -> None:
        try:
            self.http.post(self.base + "/cgi-bin/UserLogout", headers={"CSRFToken": self.token or ""})
        finally:
            self.http.close()


def _walk(obj, fn):
    if isinstance(obj, dict):
        return {k: fn(k, _walk(v, fn)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_walk(v, fn) for v in obj]
    return obj


def _redact(obj):
    return _walk(obj, lambda k, v: "<redacted>" if SECRET.search(k) and isinstance(v, str) and v else v)


def _stable(obj):
    return _walk(obj, lambda k, v: None if VOLATILE.search(k) and not isinstance(v, (dict, list)) else v)


def _snapshot(host: str, user: str, password: str, scheme: str = "https") -> dict:
    z = ZyxelClient("%s://%s" % (scheme, host))
    z.login(user, password)
    try:
        return {oid: z.get(oid).get("Object") for oid in OIDS}
    finally:
        z.logout()


async def collect(device, cfg: dict) -> list[tuple[str, bytes, str | None]]:
    user = cfg.get("user") or os.environ[cfg.get("user_env", "ZYXEL_USER")]
    password = vault.secret_or_file(cfg, "password_vault", env_field="password_env")
    snap = await asyncio.to_thread(_snapshot, device.host, user, password, cfg.get("scheme", "https"))
    if cfg.get("redact", True):
        snap = _redact(snap)
    text = json.dumps(snap, indent=1, sort_keys=True)
    comparable = json.dumps(_stable({k: v for k, v in snap.items() if k not in ("cardpage_status", "lanhosts")}),
                            indent=1, sort_keys=True)
    return [("json", text.encode(), comparable)]
