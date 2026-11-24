"""Accounts, sessions and MFA (NIST SP 800-63B AAL2).

Login: password (Argon2id) + a second factor (TOTP, passkey or recovery code), or a passkey alone
(phishing-resistant, user verification required). Every account must have a second factor: right after
the first-run setup the session is limited to enrolling one.

Sessions are server-side: the cookie (__Host-netops) carries a random token, the database only its SHA-256.
Stages: passkey (passwordless challenge), mfa (password ok, waiting for the 2nd factor), enroll (must add a
factor), full. nginx asks GET /api/auth/check (auth_request) on every protected request.
"""
import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time

import httpx
import pyotp
import segno
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from fastapi import APIRouter, HTTPException, Request, Response
from nacl.secret import SecretBox
from pydantic import BaseModel
from webauthn import (generate_authentication_options, generate_registration_options, options_to_json,
                      verify_authentication_response, verify_registration_response)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (AuthenticatorSelectionCriteria, PublicKeyCredentialDescriptor,
                                      ResidentKeyRequirement, UserVerificationRequirement)

from . import db, settings

log = logging.getLogger("netops.auth")
router = APIRouter(prefix="/api/auth")

COOKIE = "__Host-netops"
IDLE = int(os.environ.get("SESSION_IDLE_MINUTES", "30")) * 60
ABSOLUTE = int(os.environ.get("SESSION_HOURS", "12")) * 3600
PENDING = 300                       # passkey / mfa stage lifetime
MIN_PASSWORD = 15                   # NIST SP 800-63B (single-factor rule, applied to all)
MAX_PASSWORD = 128
LOCK_AFTER = 3                      # failed attempts before a lock (DISA ASD STIG / AC-7)
LOCK_BASE = 15 * 60                 # first lock 15 min, then doubling, at most 24 h
HIBP = os.environ.get("NETOPS_HIBP", "true").lower() == "true"
HOSTNAME = os.environ.get("NETOPS_HOSTNAME", "netops.lan")
RP_NAME = os.environ.get("NETOPS_NAME", "NetOps")

ph = PasswordHasher()               # argon2-cffi defaults follow RFC 9106 (Argon2id)
_DUMMY_HASH = ph.hash(secrets.token_hex(16))
_setup_code: str | None = None


# ---------------------------------------------------------------- keys and helpers

def _app_key() -> bytes:
    """Encrypts TOTP secrets and signs action links. Not the vault: login must work while it is locked."""
    path = settings.DATA_DIR / ".app_key"
    if not path.exists():
        settings.DATA_DIR.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(secrets.token_bytes(32))
    return path.read_bytes()


def _sign(payload: str) -> str:
    """HMAC for signed links (remediation one-click actions)."""
    return base64.urlsafe_b64encode(hmac.new(_app_key(), payload.encode(), hashlib.sha256).digest()).decode().rstrip("=")


def _enc(secret: str) -> bytes:
    return bytes(SecretBox(_app_key()).encrypt(secret.encode()))


def _dec(blob: bytes) -> str:
    return SecretBox(_app_key()).decrypt(blob).decode()


def _ip(request: Request) -> str:
    return (request.headers.get("x-forwarded-for") or (request.client.host if request.client else "")).split(",")[0].strip()


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _rp(request: Request) -> tuple[str, str]:
    """WebAuthn relying party ID and origin. IPs are not allowed as RP IDs; only known host names are accepted."""
    hostport = (request.headers.get("x-forwarded-host") or request.headers.get("host") or "").lower()
    host = hostport.split(":")[0]
    allowed = {HOSTNAME.lower(), "localhost"}
    if host not in allowed:
        raise HTTPException(400, "Passkeys need the box's host name: open https://%s" % HOSTNAME)
    # The origin includes a non-default port (https://netops.lan:8443); the RP ID never does.
    return host, "https://%s" % (hostport if ":" in hostport and not hostport.endswith(":443") else host)


# ---------------------------------------------------------------- sessions

def _new_session(response: Response, request: Request, user_id: int | None, stage: str, challenge: str | None = None) -> str:
    token = secrets.token_urlsafe(32)
    now = time.time()
    with db.tx() as c:
        # a new session replaces whatever this browser had (no fixation)
        old = request.cookies.get(COOKIE)
        if old:
            c.execute("DELETE FROM sessions WHERE id = ?", (_hash_token(old),))
        c.execute("INSERT INTO sessions (id, user_id, stage, created, seen, ip, ua, challenge) VALUES (?,?,?,?,?,?,?,?)",
                  (_hash_token(token), user_id, stage, now, now, _ip(request), request.headers.get("user-agent", "")[:200], challenge))
        c.execute("DELETE FROM sessions WHERE seen < ?", (now - ABSOLUTE,))
    response.set_cookie(COOKIE, token, httponly=True, secure=True, samesite="strict", path="/",
                        max_age=ABSOLUTE)
    return token


def session(request: Request, touch: bool = True) -> dict | None:
    token = request.cookies.get(COOKIE)
    if not token:
        return None
    row = db.one("SELECT s.*, u.username, u.role FROM sessions s LEFT JOIN users u ON u.id = s.user_id WHERE s.id = ?",
                 _hash_token(token))
    if not row:
        return None
    now = time.time()
    limit = PENDING if row["stage"] in ("passkey", "mfa") else IDLE
    if now - row["seen"] > limit or now - row["created"] > ABSOLUTE:
        with db.tx() as c:
            c.execute("DELETE FROM sessions WHERE id = ?", (row["id"],))
        return None
    if touch:
        with db.tx() as c:
            c.execute("UPDATE sessions SET seen = ? WHERE id = ?", (now, row["id"]))
    return dict(row)


def _set_stage(sess: dict, stage: str, challenge: str | None = None) -> None:
    with db.tx() as c:
        c.execute("UPDATE sessions SET stage = ?, challenge = ? WHERE id = ?", (stage, challenge, sess["id"]))


def _require(request: Request, *stages: str) -> dict:
    s = session(request)
    if not s or s["stage"] not in stages:
        raise HTTPException(401, "not logged in")
    return s


def current_user(request: Request) -> dict | None:
    """For other modules: the fully logged-in user, or None."""
    s = session(request, touch=False)
    return s if s and s["stage"] == "full" else None


# ---------------------------------------------------------------- passwords

async def _breached(password: str) -> bool:
    """Have I Been Pwned range API (k-anonymity: only the first 5 hex chars of the SHA-1 leave the box)."""
    if not HIBP:
        return False
    digest = hashlib.sha1(password.encode()).hexdigest().upper()
    try:
        async with httpx.AsyncClient(timeout=5) as c:
            r = await c.get("https://api.pwnedpasswords.com/range/" + digest[:5], headers={"Add-Padding": "true"})
        return any(line.split(":")[0] == digest[5:] and not line.endswith(":0") for line in r.text.splitlines())
    except httpx.HTTPError:
        return False   # offline: don't block, the other rules still apply


async def check_password(password: str, username: str) -> None:
    if len(password) < MIN_PASSWORD:
        raise HTTPException(400, "Use at least %d characters (a passphrase of a few words works well)." % MIN_PASSWORD)
    if len(password) > MAX_PASSWORD:
        raise HTTPException(400, "At most %d characters." % MAX_PASSWORD)
    if username.lower() in password.lower():
        raise HTTPException(400, "The password must not contain the user name.")
    if await _breached(password):
        raise HTTPException(400, "This password appears in known data breaches. Choose another one.")


# ---------------------------------------------------------------- first run

def ensure_setup_code() -> None:
    """No account yet: create a one-time setup code, visible only to someone with access to the host's logs."""
    global _setup_code
    if db.one("SELECT 1 FROM users LIMIT 1"):
        _setup_code = None
        return
    _setup_code = "-".join(secrets.token_hex(2).upper() for _ in range(3))
    log.warning("FIRST-RUN SETUP CODE: %s  (open the web UI and enter it to create the first account)", _setup_code)


# ---------------------------------------------------------------- lockout

def _locked(user) -> float:
    return max(0.0, (user["locked_until"] or 0) - time.time())


def _fail(user, request: Request, what: str) -> None:
    failed = user["failed"] + 1
    locked_until = 0.0
    if failed >= LOCK_AFTER:
        locked_until = time.time() + min(LOCK_BASE * 2 ** (failed - LOCK_AFTER), 86400)
    with db.tx() as c:
        c.execute("UPDATE users SET failed = ?, locked_until = ? WHERE id = ?", (failed, locked_until, user["id"]))
    db.audit("login-failed", user["username"], "%s (attempt %d)%s" % (what, failed, ", account locked" if locked_until else ""), _ip(request))


def _succeed(user_id: int) -> None:
    with db.tx() as c:
        c.execute("UPDATE users SET failed = 0, locked_until = 0, last_login = ? WHERE id = ?", (time.time(), user_id))


def _factors(user_id: int) -> dict:
    u = db.one("SELECT totp_enc FROM users WHERE id = ?", user_id)
    pk = db.one("SELECT COUNT(*) AS n FROM passkeys WHERE user_id = ?", user_id)["n"]
    rc = db.one("SELECT COUNT(*) AS n FROM recovery_codes WHERE user_id = ? AND used IS NULL", user_id)["n"]
    return {"totp": bool(u and u["totp_enc"]), "passkeys": pk, "recovery_codes": rc}


def _has_factor(user_id: int) -> bool:
    f = _factors(user_id)
    return f["totp"] or f["passkeys"] > 0


# ---------------------------------------------------------------- API: state, setup, login

class Credentials(BaseModel):
    username: str
    password: str


class Setup(Credentials):
    code: str


class Code(BaseModel):
    code: str


@router.get("/state")
async def state(request: Request):
    s = session(request, touch=False)
    out = {"setup_required": _setup_code is not None, "stage": s["stage"] if s else None, "user": None,
           "hostname": HOSTNAME}
    if s and s["user_id"]:
        out["user"] = {"name": s["username"], "role": s["role"], "factors": _factors(s["user_id"])}
    return out


@router.post("/setup")
async def setup(body: Setup, request: Request, response: Response):
    if _setup_code is None:
        raise HTTPException(409, "Setup is already done.")
    if not hmac.compare_digest(body.code.strip().upper(), _setup_code):
        await asyncio.sleep(1)
        raise HTTPException(403, "Wrong setup code (see the backend log).")
    name = body.username.strip()
    if not (3 <= len(name) <= 32) or not name.replace("-", "").replace("_", "").replace(".", "").isalnum():
        raise HTTPException(400, "User name: 3-32 letters, digits, - _ .")
    await check_password(body.password, name)
    with db.tx() as c:
        cur = c.execute("INSERT INTO users (username, pw_hash, role, created) VALUES (?, ?, 'admin', ?)",
                        (name, ph.hash(body.password), time.time()))
        uid = cur.lastrowid
    ensure_setup_code()
    _new_session(response, request, uid, "enroll")
    db.audit("setup", name, "first account created", _ip(request))
    return {"stage": "enroll"}


@router.post("/login")
async def login(body: Credentials, request: Request, response: Response):
    user = db.one("SELECT * FROM users WHERE username = ?", body.username.strip())
    if not user:
        try:
            ph.verify(_DUMMY_HASH, body.password)   # same work as a real check: no user enumeration by timing
        except VerifyMismatchError:
            pass
        await asyncio.sleep(0.5)
        db.audit("login-failed", body.username[:32], "unknown user", _ip(request))
        raise HTTPException(401, "Wrong user name or password.")
    if _locked(user):
        raise HTTPException(429, "Too many failed attempts. Try again in %d minutes." % (_locked(user) // 60 + 1))
    try:
        ph.verify(user["pw_hash"], body.password)
    except (VerifyMismatchError, InvalidHashError):
        _fail(user, request, "password")
        await asyncio.sleep(0.5)
        raise HTTPException(401, "Wrong user name or password.")
    if ph.check_needs_rehash(user["pw_hash"]):
        with db.tx() as c:
            c.execute("UPDATE users SET pw_hash = ? WHERE id = ?", (ph.hash(body.password), user["id"]))
    if not _has_factor(user["id"]):
        _succeed(user["id"])
        _new_session(response, request, user["id"], "enroll")
        return {"stage": "enroll"}
    _new_session(response, request, user["id"], "mfa")
    f = _factors(user["id"])
    return {"stage": "mfa", "methods": [m for m, ok in (("totp", f["totp"]), ("passkey", f["passkeys"] > 0),
                                                      ("recovery", f["recovery_codes"] > 0)) if ok]}


def _finish(sess: dict, request: Request, how: str) -> dict:
    _succeed(sess["user_id"])
    _set_stage(sess, "full")
    db.audit("login", sess["username"], how, _ip(request))
    return {"stage": "full"}


@router.post("/totp/verify")
async def totp_verify(body: Code, request: Request):
    s = _require(request, "mfa")
    user = db.one("SELECT * FROM users WHERE id = ?", s["user_id"])
    if _locked(user):
        raise HTTPException(429, "Too many failed attempts. Try again later.")
    if not user["totp_enc"]:
        raise HTTPException(400, "No authenticator app set up for this account.")
    totp = pyotp.TOTP(_dec(user["totp_enc"]))
    step = int(time.time() // 30)
    code = body.code.replace(" ", "")
    for offset in (0, -1, 1):
        if hmac.compare_digest(totp.at((step + offset) * 30), code) and step + offset > (user["totp_last"] or 0):
            with db.tx() as c:
                c.execute("UPDATE users SET totp_last = ? WHERE id = ?", (step + offset, user["id"]))
            return _finish(s, request, "password + TOTP")
    _fail(user, request, "TOTP code")
    raise HTTPException(401, "Wrong or already used code.")


def _code_hash(code: str) -> str:
    return hashlib.sha256(code.replace("-", "").replace(" ", "").upper().encode()).hexdigest()


@router.post("/recovery/verify")
async def recovery_verify(body: Code, request: Request):
    s = _require(request, "mfa")
    user = db.one("SELECT * FROM users WHERE id = ?", s["user_id"])
    if _locked(user):
        raise HTTPException(429, "Too many failed attempts. Try again later.")
    h = _code_hash(body.code)
    with db.tx() as c:
        row = c.execute("SELECT rowid FROM recovery_codes WHERE user_id = ? AND code_hash = ? AND used IS NULL",
                        (user["id"], h)).fetchone()
        if row:
            c.execute("UPDATE recovery_codes SET used = ? WHERE rowid = ?", (time.time(), row["rowid"]))
    if not row:
        _fail(user, request, "recovery code")
        raise HTTPException(401, "Wrong or already used recovery code.")
    db.audit("recovery-code-used", user["username"], "", _ip(request))
    return _finish(s, request, "password + recovery code")


@router.post("/logout")
async def logout(request: Request, response: Response):
    token = request.cookies.get(COOKIE)
    if token:
        with db.tx() as c:
            c.execute("DELETE FROM sessions WHERE id = ?", (_hash_token(token),))
    response.delete_cookie(COOKIE, path="/", secure=True, httponly=True, samesite="strict")
    return {"ok": True}


@router.get("/check")
async def check(request: Request):
    """nginx auth_request: 204 only for a full (MFA-complete) session."""
    if not current_user(request):
        raise HTTPException(401)
    session(request)   # refresh idle timer
    return Response(status_code=204)


@router.get("/me")
async def me(request: Request):
    s = current_user(request)
    if not s:
        raise HTTPException(401, "not logged in")
    return {"user": s["username"], "role": s["role"]}


# ---------------------------------------------------------------- passkeys (WebAuthn)

class PasskeyResponse(BaseModel):
    credential: dict
    name: str | None = None


@router.post("/passkey/login/options")
async def passkey_login_options(request: Request, response: Response):
    rp_id, _ = _rp(request)
    s = session(request, touch=False)
    allow = []
    if s and s["stage"] == "mfa":        # second factor after the password: only this user's passkeys
        allow = [PublicKeyCredentialDescriptor(id=base64url_to_bytes(r["cred_id"]))
                 for r in db.query("SELECT cred_id FROM passkeys WHERE user_id = ?", s["user_id"])]
    opts = generate_authentication_options(rp_id=rp_id, allow_credentials=allow,
                                           user_verification=UserVerificationRequirement.REQUIRED)
    challenge = bytes_to_base64url(opts.challenge)
    if s and s["stage"] == "mfa":
        _set_stage(s, "mfa", challenge)
    else:                                  # passwordless: a short-lived pre-session holds the challenge
        _new_session(response, request, None, "passkey", challenge)
    return json.loads(options_to_json(opts))


@router.post("/passkey/login/verify")
async def passkey_login_verify(body: PasskeyResponse, request: Request):
    rp_id, origin = _rp(request)
    s = _require(request, "passkey", "mfa")
    cred_id = body.credential.get("id", "")
    pk = db.one("SELECT p.*, u.username, u.locked_until FROM passkeys p JOIN users u ON u.id = p.user_id WHERE p.cred_id = ?", cred_id)
    if not pk or (s["stage"] == "mfa" and pk["user_id"] != s["user_id"]):
        raise HTTPException(401, "Unknown passkey.")
    if pk["locked_until"] and pk["locked_until"] > time.time():
        raise HTTPException(429, "Account locked. Try again later.")
    try:
        v = verify_authentication_response(
            credential=body.credential, expected_challenge=base64url_to_bytes(s["challenge"] or ""),
            expected_rp_id=rp_id, expected_origin=origin, credential_public_key=pk["public_key"],
            credential_current_sign_count=pk["sign_count"], require_user_verification=True)
    except Exception as e:
        db.audit("login-failed", pk["username"], "passkey: %s" % type(e).__name__, _ip(request))
        raise HTTPException(401, "Passkey check failed.")
    with db.tx() as c:
        c.execute("UPDATE passkeys SET sign_count = ?, last_used = ? WHERE id = ?", (v.new_sign_count, time.time(), pk["id"]))
        c.execute("UPDATE sessions SET user_id = ? WHERE id = ?", (pk["user_id"], s["id"]))
    s["user_id"], s["username"] = pk["user_id"], pk["username"]
    return _finish(s, request, "passkey" if s["stage"] == "passkey" else "password + passkey")


@router.post("/passkey/register/options")
async def passkey_register_options(request: Request):
    rp_id, _ = _rp(request)
    s = _require(request, "enroll", "full")
    existing = [PublicKeyCredentialDescriptor(id=base64url_to_bytes(r["cred_id"]))
                for r in db.query("SELECT cred_id FROM passkeys WHERE user_id = ?", s["user_id"])]
    opts = generate_registration_options(
        rp_id=rp_id, rp_name=RP_NAME, user_id=str(s["user_id"]).encode(), user_name=s["username"],
        exclude_credentials=existing,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED, user_verification=UserVerificationRequirement.REQUIRED))
    _set_stage(s, s["stage"], bytes_to_base64url(opts.challenge))
    return json.loads(options_to_json(opts))


@router.post("/passkey/register/verify")
async def passkey_register_verify(body: PasskeyResponse, request: Request):
    rp_id, origin = _rp(request)
    s = _require(request, "enroll", "full")
    try:
        v = verify_registration_response(credential=body.credential, expected_challenge=base64url_to_bytes(s["challenge"] or ""),
                                         expected_rp_id=rp_id, expected_origin=origin, require_user_verification=True)
    except Exception as e:
        raise HTTPException(400, "Passkey could not be registered (%s)." % type(e).__name__)
    name = (body.name or "Passkey").strip()[:40] or "Passkey"
    transports = ",".join(body.credential.get("response", {}).get("transports", []) or [])
    with db.tx() as c:
        c.execute("INSERT INTO passkeys (user_id, cred_id, public_key, sign_count, name, transports, created) VALUES (?,?,?,?,?,?,?)",
                  (s["user_id"], bytes_to_base64url(v.credential_id), v.credential_public_key, v.sign_count, name, transports, time.time()))
    db.audit("passkey-added", s["username"], name, _ip(request))
    return _after_enroll(s, request)


@router.delete("/passkeys/{pk_id}")
async def passkey_delete(pk_id: int, request: Request):
    s = _require(request, "full")
    f = _factors(s["user_id"])
    if f["passkeys"] <= 1 and not f["totp"]:
        raise HTTPException(409, "This is your only second factor. Add another one first.")
    with db.tx() as c:
        c.execute("DELETE FROM passkeys WHERE id = ? AND user_id = ?", (pk_id, s["user_id"]))
    db.audit("passkey-removed", s["username"], str(pk_id), _ip(request))
    return {"ok": True}


# ---------------------------------------------------------------- TOTP enrollment, recovery codes

@router.post("/totp/setup")
async def totp_setup(request: Request):
    s = _require(request, "enroll", "full")
    secret = pyotp.random_base32()
    with db.tx() as c:
        c.execute("UPDATE users SET totp_pending = ? WHERE id = ?", (_enc(secret), s["user_id"]))
    uri = pyotp.TOTP(secret).provisioning_uri(name=s["username"], issuer_name=RP_NAME)
    svg = segno.make(uri, error="m").svg_inline(scale=5, dark="#000", light="#fff")
    return {"secret": secret, "uri": uri, "qr_svg": svg}


@router.post("/totp/confirm")
async def totp_confirm(body: Code, request: Request):
    s = _require(request, "enroll", "full")
    u = db.one("SELECT totp_pending FROM users WHERE id = ?", s["user_id"])
    if not u or not u["totp_pending"]:
        raise HTTPException(400, "Start the setup first.")
    secret = _dec(u["totp_pending"])
    if not pyotp.TOTP(secret).verify(body.code.replace(" ", ""), valid_window=1):
        raise HTTPException(400, "That code doesn't match. Check the time on your phone and try the next code.")
    with db.tx() as c:
        c.execute("UPDATE users SET totp_enc = totp_pending, totp_pending = NULL, totp_last = ? WHERE id = ?",
                  (int(time.time() // 30), s["user_id"]))
    db.audit("totp-added", s["username"], "", _ip(request))
    return _after_enroll(s, request)


@router.delete("/totp")
async def totp_delete(request: Request):
    s = _require(request, "full")
    if _factors(s["user_id"])["passkeys"] == 0:
        raise HTTPException(409, "The authenticator app is your only second factor. Add a passkey first.")
    with db.tx() as c:
        c.execute("UPDATE users SET totp_enc = NULL WHERE id = ?", (s["user_id"],))
    db.audit("totp-removed", s["username"], "", _ip(request))
    return {"ok": True}


def _new_recovery_codes(user_id: int) -> list[str]:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    codes = ["-".join("".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(4)) for _ in range(10)]
    with db.tx() as c:
        c.execute("DELETE FROM recovery_codes WHERE user_id = ?", (user_id,))
        c.executemany("INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)", [(user_id, _code_hash(x)) for x in codes])
    return codes


def _after_enroll(s: dict, request: Request) -> dict:
    """First factor added during setup: the session becomes full, and recovery codes are shown once."""
    out = {"stage": s["stage"]}
    if _factors(s["user_id"])["recovery_codes"] == 0:
        out["recovery_codes"] = _new_recovery_codes(s["user_id"])
    if s["stage"] == "enroll":
        _set_stage(s, "full")
        out["stage"] = "full"
        db.audit("login", s["username"], "after enrolling a second factor", _ip(request))
    return out


@router.post("/recovery/regenerate")
async def recovery_regenerate(request: Request):
    s = _require(request, "full")
    db.audit("recovery-codes-regenerated", s["username"], "", _ip(request))
    return {"recovery_codes": _new_recovery_codes(s["user_id"])}


@router.get("/factors")
async def factors(request: Request):
    s = _require(request, "enroll", "full")
    return {**_factors(s["user_id"]),
            "passkey_list": [dict(r) for r in db.query(
                "SELECT id, name, transports, created, last_used FROM passkeys WHERE user_id = ? ORDER BY created", s["user_id"])]}


class PasswordChange(BaseModel):
    current: str
    new: str


@router.post("/password")
async def password_change(body: PasswordChange, request: Request, response: Response):
    s = _require(request, "full")
    u = db.one("SELECT pw_hash FROM users WHERE id = ?", s["user_id"])
    try:
        ph.verify(u["pw_hash"], body.current)
    except VerifyMismatchError:
        raise HTTPException(403, "The current password is wrong.")
    await check_password(body.new, s["username"])
    with db.tx() as c:
        c.execute("UPDATE users SET pw_hash = ? WHERE id = ?", (ph.hash(body.new), s["user_id"]))
        c.execute("DELETE FROM sessions WHERE user_id = ? AND id != ?", (s["user_id"], s["id"]))   # log out elsewhere
    db.audit("password-changed", s["username"], "", _ip(request))
    return {"ok": True}


# ---------------------------------------------------------------- users (admin)

class NewUser(Credentials):
    role: str = "viewer"


def _admin(request: Request) -> dict:
    s = _require(request, "full")
    if s["role"] != "admin":
        raise HTTPException(403, "Only administrators can do this.")
    return s


@router.get("/users")
async def users(request: Request):
    _admin(request)
    return [dict(r) | {"factors": _factors(r["id"])} for r in db.query(
        "SELECT id, username, role, created, last_login, locked_until FROM users ORDER BY username")]


@router.post("/users")
async def user_create(body: NewUser, request: Request):
    s = _admin(request)
    if body.role not in ("admin", "viewer"):
        raise HTTPException(400, "role: admin or viewer")
    await check_password(body.password, body.username)
    try:
        with db.tx() as c:
            c.execute("INSERT INTO users (username, pw_hash, role, created) VALUES (?, ?, ?, ?)",
                      (body.username.strip(), ph.hash(body.password), body.role, time.time()))
    except Exception:
        raise HTTPException(409, "That user name exists already.")
    db.audit("user-created", s["username"], "%s (%s)" % (body.username, body.role), _ip(request))
    return {"ok": True}


@router.delete("/users/{user_id}")
async def user_delete(user_id: int, request: Request):
    s = _admin(request)
    if user_id == s["user_id"]:
        raise HTTPException(409, "You can't delete your own account.")
    target = db.one("SELECT username, role FROM users WHERE id = ?", user_id)
    if not target:
        raise HTTPException(404, "no such user")
    if target["role"] == "admin" and db.one("SELECT COUNT(*) AS n FROM users WHERE role = 'admin'")["n"] <= 1:
        raise HTTPException(409, "The last administrator can't be deleted.")
    with db.tx() as c:
        c.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.audit("user-deleted", s["username"], target["username"], _ip(request))
    return {"ok": True}


@router.post("/users/{user_id}/unlock")
async def user_unlock(user_id: int, request: Request):
    s = _admin(request)
    with db.tx() as c:
        c.execute("UPDATE users SET failed = 0, locked_until = 0 WHERE id = ?", (user_id,))
    db.audit("user-unlocked", s["username"], str(user_id), _ip(request))
    return {"ok": True}


@router.get("/audit")
async def audit_log(request: Request, limit: int = 200):
    _admin(request)
    return [dict(r) for r in db.query("SELECT * FROM audit ORDER BY id DESC LIMIT ?", min(limit, 1000))]
