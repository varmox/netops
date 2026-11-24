"""Vault for device credentials (SSH keys, API tokens, passwords).

libsodium secretbox (XSalsa20-Poly1305) per secret; the key comes from an unlock passphrase via Argon2id
and lives only in this process's memory. After every restart the vault is locked until an administrator
unlocks it in the UI; jobs that need a credential wait (VaultLocked) instead of failing loudly.

Values are write-only through the API: they can be set or deleted, never read back.
"""
import asyncio
import os
import re
import time
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from nacl import pwhash, utils
from nacl.exceptions import CryptoError
from nacl.secret import SecretBox
from pydantic import BaseModel

from . import auth, db, settings

router = APIRouter(prefix="/api/vault")

# Argon2id cost: "moderate" (~256 MB, ~1 s on a Pi 5). Stored per vault so it can be raised later.
OPS = pwhash.argon2id.OPSLIMIT_MODERATE
MEM = pwhash.argon2id.MEMLIMIT_MODERATE
CHECK = b"netops-vault-v1"
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
KINDS = ("password", "ssh-key", "api-token", "other")

_key: bytes | None = None
_unlocked_at: float | None = None


class VaultLocked(RuntimeError):
    """A credential is needed but the vault hasn't been unlocked since the last restart."""


def _derive(passphrase: str, salt: bytes, ops: int, mem: int) -> bytes:
    return pwhash.argon2id.kdf(SecretBox.KEY_SIZE, passphrase.encode(), salt, opslimit=ops, memlimit=mem)


def initialized() -> bool:
    return db.one("SELECT 1 FROM vault_meta WHERE id = 1") is not None


def unlocked() -> bool:
    return _key is not None


def get(name: str) -> str:
    """The secret's value, for drivers and collectors only (never returned by the API)."""
    if _key is None:
        raise VaultLocked("vault is locked: unlock it in the web UI (Vault)")
    row = db.one("SELECT ct FROM vault WHERE name = ?", name)
    if not row:
        raise KeyError("no secret named %r in the vault" % name)
    return SecretBox(_key).decrypt(row["ct"]).decode()


def has(name: str) -> bool:
    return db.one("SELECT 1 FROM vault WHERE name = ?", name) is not None


def put(name: str, value: str, kind: str = "other", description: str = "") -> None:
    """Store a secret (vault must be unlocked). For backend callers like per-device credentials."""
    if _key is None:
        raise VaultLocked("vault is locked")
    if not NAME_RE.match(name):
        raise ValueError("invalid secret name")
    _put(name, value, kind, description[:200])


def delete(name: str) -> None:
    with db.tx() as c:
        c.execute("DELETE FROM vault WHERE name = ?", (name,))


def _put(name: str, value: str, kind: str, description: str = "") -> None:
    ct = bytes(SecretBox(_key).encrypt(value.encode()))
    with db.tx() as c:
        c.execute("INSERT INTO vault (name, kind, description, ct, updated) VALUES (?,?,?,?,?) "
                  "ON CONFLICT(name) DO UPDATE SET kind=excluded.kind, description=excluded.description, "
                  "ct=excluded.ct, updated=excluded.updated", (name, kind, description, ct, time.time()))


def secret_or_file(cfg: dict, vault_field: str, file_field: str | None = None, env_field: str | None = None) -> str:
    """A credential from the vault (preferred) or, during migration, from a file or environment variable."""
    if cfg.get(vault_field):
        return get(cfg[vault_field])
    if file_field and cfg.get(file_field):
        return Path(cfg[file_field]).read_text()
    if env_field and cfg.get(env_field):
        return os.environ[cfg[env_field]]
    raise KeyError("no credential configured (%s)" % vault_field)


# ---------------------------------------------------------------- API

class Passphrase(BaseModel):
    passphrase: str


class ChangePassphrase(BaseModel):
    current: str
    new: str


class Secret(BaseModel):
    value: str
    kind: str = "password"
    description: str = ""


def _admin(request: Request) -> dict:
    s = auth.current_user(request)
    if not s:
        raise HTTPException(401, "not logged in")
    if s["role"] != "admin":
        raise HTTPException(403, "Only administrators can use the vault.")
    return s


@router.get("/status")
async def status(request: Request):
    if not auth.current_user(request):
        raise HTTPException(401)
    n = db.one("SELECT COUNT(*) AS n FROM vault")["n"]
    return {"initialized": initialized(), "unlocked": unlocked(), "secrets": n, "unlocked_at": _unlocked_at}


@router.post("/init")
async def init(body: Passphrase, request: Request):
    global _key, _unlocked_at
    s = _admin(request)
    if initialized():
        raise HTTPException(409, "The vault is already set up.")
    if len(body.passphrase) < 15:
        raise HTTPException(400, "Use a passphrase of at least 15 characters. There is no way to recover it.")
    salt = utils.random(pwhash.argon2id.SALTBYTES)
    key = await asyncio.to_thread(_derive, body.passphrase, salt, OPS, MEM)
    with db.tx() as c:
        c.execute("INSERT INTO vault_meta (id, salt, ops, mem, check_ct, created) VALUES (1, ?, ?, ?, ?, ?)",
                  (salt, OPS, MEM, bytes(SecretBox(key).encrypt(CHECK)), time.time()))
    _key, _unlocked_at = key, time.time()
    db.audit("vault-initialized", s["username"], "", auth._ip(request))
    return {"ok": True}


@router.post("/unlock")
async def unlock(body: Passphrase, request: Request):
    global _key, _unlocked_at
    s = _admin(request)
    meta = db.one("SELECT * FROM vault_meta WHERE id = 1")
    if not meta:
        raise HTTPException(409, "The vault isn't set up yet.")
    key = await asyncio.to_thread(_derive, body.passphrase, meta["salt"], meta["ops"], meta["mem"])
    try:
        if SecretBox(key).decrypt(meta["check_ct"]) != CHECK:
            raise CryptoError()
    except CryptoError:
        db.audit("vault-unlock-failed", s["username"], "", auth._ip(request))
        await asyncio.sleep(2)
        raise HTTPException(403, "Wrong passphrase.")
    _key, _unlocked_at = key, time.time()
    db.audit("vault-unlocked", s["username"], "", auth._ip(request))
    return {"ok": True}


@router.post("/lock")
async def lock(request: Request):
    global _key, _unlocked_at
    s = _admin(request)
    _key, _unlocked_at = None, None
    db.audit("vault-locked", s["username"], "", auth._ip(request))
    return {"ok": True}


@router.post("/passphrase")
async def change_passphrase(body: ChangePassphrase, request: Request):
    global _key
    s = _admin(request)
    meta = db.one("SELECT * FROM vault_meta WHERE id = 1")
    old = await asyncio.to_thread(_derive, body.current, meta["salt"], meta["ops"], meta["mem"])
    try:
        SecretBox(old).decrypt(meta["check_ct"])
    except CryptoError:
        raise HTTPException(403, "The current passphrase is wrong.")
    if len(body.new) < 15:
        raise HTTPException(400, "Use at least 15 characters.")
    salt = utils.random(pwhash.argon2id.SALTBYTES)
    new = await asyncio.to_thread(_derive, body.new, salt, OPS, MEM)
    rows = db.query("SELECT name, ct FROM vault")
    with db.tx() as c:   # re-encrypt everything in one transaction
        for r in rows:
            c.execute("UPDATE vault SET ct = ? WHERE name = ?",
                      (bytes(SecretBox(new).encrypt(SecretBox(old).decrypt(r["ct"]))), r["name"]))
        c.execute("UPDATE vault_meta SET salt = ?, ops = ?, mem = ?, check_ct = ? WHERE id = 1",
                  (salt, OPS, MEM, bytes(SecretBox(new).encrypt(CHECK))))
    _key = new
    db.audit("vault-passphrase-changed", s["username"], "%d secrets re-encrypted" % len(rows), auth._ip(request))
    return {"ok": True, "reencrypted": len(rows)}


@router.get("/secrets")
async def secrets_list(request: Request):
    _admin(request)
    return [dict(r) for r in db.query("SELECT name, kind, description, updated FROM vault ORDER BY name")]


@router.put("/secrets/{name}")
async def secret_put(name: str, body: Secret, request: Request):
    s = _admin(request)
    if not NAME_RE.match(name):
        raise HTTPException(400, "Name: lowercase letters, digits, . _ - (max 64)")
    if body.kind not in KINDS:
        raise HTTPException(400, "kind: one of %s" % ", ".join(KINDS))
    if _key is None:
        raise HTTPException(423, "Unlock the vault first.")
    _put(name, body.value, body.kind, body.description[:200])
    db.audit("secret-set", s["username"], name, auth._ip(request))
    return {"ok": True}


@router.delete("/secrets/{name}")
async def secret_delete(name: str, request: Request):
    s = _admin(request)
    with db.tx() as c:
        c.execute("DELETE FROM vault WHERE name = ?", (name,))
    db.audit("secret-deleted", s["username"], name, auth._ip(request))
    return {"ok": True}


@router.post("/import-legacy")
async def import_legacy(request: Request):
    """Moves the credentials of the pre-vault setup (files in secrets/, ZYXEL_PASSWORD) into the vault."""
    s = _admin(request)
    if _key is None:
        raise HTTPException(423, "Unlock the vault first.")
    found = []
    for name, path, kind in (("mikrotik-ssh-key", "/secrets/mikrotik_id_rsa", "ssh-key"),
                             ("linux-ssh-key", "/secrets/linux_id_ed25519", "ssh-key")):
        if Path(path).is_file() and not has(name):
            _put(name, Path(path).read_text(), kind, "imported from %s" % path)
            found.append(name)
    if os.environ.get("ZYXEL_PASSWORD") and not has("zyxel-password"):
        _put("zyxel-password", os.environ["ZYXEL_PASSWORD"], "password", "imported from ZYXEL_PASSWORD")
        found.append("zyxel-password")
    db.audit("vault-import", s["username"], ", ".join(found) or "nothing new", auth._ip(request))
    return {"imported": found}
