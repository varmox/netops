"""Auth, MFA, roles, CSRF and vault against a throwaway database.

    docker compose exec -T backend python - < backend/tests/test_auth_vault.py

Runs the FastAPI app in-process (no lifespan: no watcher, no network jobs) with DATA_DIR in a temp dir.
"""
import os
import sys
import tempfile
import time

os.environ["DATA_DIR"] = tempfile.mkdtemp(prefix="netops-test-")
os.environ["NETOPS_HIBP"] = "false"
os.environ["NETOPS_HOSTNAME"] = "localhost"
sys.path.insert(0, "/srv")

import logging  # noqa: E402
logging.disable(logging.INFO)
import pyotp  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import auth, db, main, vault  # noqa: E402

db.init()
auth.ensure_setup_code()
H = {"X-NetOps": "1"}
ok = fail = 0


def check(name, cond, detail=""):
    global ok, fail
    if cond:
        ok += 1
        print("  ok   ", name)
    else:
        fail += 1
        print("  FAIL ", name, detail)


def client():
    return TestClient(main.app, base_url="https://localhost")


c = client()
GOOD = "correct horse battery staple 42"

print("first run")
check("state says setup required", c.get("/api/auth/state").json()["setup_required"])
check("POST without X-NetOps header is refused", c.post("/api/auth/setup", json={}).status_code == 403)
r = c.post("/api/auth/setup", headers=H, json={"code": "WRONG", "username": "admin", "password": GOOD})
check("wrong setup code refused", r.status_code == 403, r.text)
r = c.post("/api/auth/setup", headers=H, json={"code": auth._setup_code, "username": "admin", "password": "short"})
check("short password refused", r.status_code == 400, r.text)
r = c.post("/api/auth/setup", headers=H, json={"code": auth._setup_code, "username": "admin", "password": "admin " + GOOD})
check("password containing the user name refused", r.status_code == 400, r.text)
r = c.post("/api/auth/setup", headers=H, json={"code": auth._setup_code, "username": "admin", "password": GOOD})
check("setup creates admin, stage enroll", r.status_code == 200 and r.json()["stage"] == "enroll", r.text)
check("setup code gone after setup", auth._setup_code is None)
check("enroll stage is not a full session (nginx check 401)", c.get("/api/auth/check").status_code == 401)
check("enroll stage can't write elsewhere", c.post("/api/security/scan", headers=H).status_code == 401)

print("TOTP enrollment")
secret = c.post("/api/auth/totp/setup", headers=H).json()["secret"]
check("wrong first code refused", c.post("/api/auth/totp/confirm", headers=H, json={"code": "000000"}).status_code == 400)
r = c.post("/api/auth/totp/confirm", headers=H, json={"code": pyotp.TOTP(secret).now()})
codes = r.json().get("recovery_codes", [])
check("confirm -> full session + 10 recovery codes", r.json()["stage"] == "full" and len(codes) == 10, r.text)
check("full session passes nginx check", c.get("/api/auth/check").status_code == 204)

print("login + second factor")
c.post("/api/auth/logout", headers=H)
check("logged out", c.get("/api/auth/check").status_code == 401)
r = c.post("/api/auth/login", headers=H, json={"username": "admin", "password": GOOD})
check("password ok -> stage mfa with methods", r.json().get("stage") == "mfa" and "totp" in r.json()["methods"], r.text)
sc = r.headers.get("set-cookie", "").lower()
check("cookie is __Host-, HttpOnly, Secure, SameSite=Strict, Path=/",
      sc.startswith("__host-netops=") and "httponly" in sc and "secure" in sc and "samesite=strict" in sc and "path=/" in sc, sc)
check("mfa stage is not logged in", c.get("/api/auth/check").status_code == 401)
used = pyotp.TOTP(secret).now()
# the enrollment already consumed the current time step: the same code must not work again (replay)
r = c.post("/api/auth/totp/verify", headers=H, json={"code": used})
check("replayed TOTP code refused", r.status_code == 401, r.text)
db.query("UPDATE users SET failed = 0, totp_last = 0")   # reset for the next step
with db.tx() as x:
    x.execute("UPDATE users SET failed = 0, totp_last = 0")
r = c.post("/api/auth/totp/verify", headers=H, json={"code": pyotp.TOTP(secret).now()})
check("valid TOTP -> full", r.json().get("stage") == "full", r.text)

print("recovery codes")
c.post("/api/auth/logout", headers=H)
c.post("/api/auth/login", headers=H, json={"username": "admin", "password": GOOD})
check("recovery code -> full", c.post("/api/auth/recovery/verify", headers=H, json={"code": codes[0]}).json().get("stage") == "full")
c.post("/api/auth/logout", headers=H)
c.post("/api/auth/login", headers=H, json={"username": "admin", "password": GOOD})
check("same recovery code again refused", c.post("/api/auth/recovery/verify", headers=H, json={"code": codes[0]}).status_code == 401)

print("lockout")
with db.tx() as x:
    x.execute("UPDATE users SET failed = 0, locked_until = 0")
c2 = client()
codes_seen = [c2.post("/api/auth/login", headers=H, json={"username": "admin", "password": "wrong password here!!"}).status_code for _ in range(4)]
check("3 wrong passwords lock the account (4th -> 429)", codes_seen == [401, 401, 401, 429], codes_seen)
check("even the right password is refused while locked",
      c2.post("/api/auth/login", headers=H, json={"username": "admin", "password": GOOD}).status_code == 429)
check("unknown user gives the same answer as a wrong password",
      c2.post("/api/auth/login", headers=H, json={"username": "nobody", "password": GOOD}).status_code == 401)
with db.tx() as x:
    x.execute("UPDATE users SET failed = 0, locked_until = 0")

print("passkey options (WebAuthn)")
c.post("/api/auth/logout", headers=H)
r = c.post("/api/auth/passkey/login/options", headers=H)
check("passwordless options: challenge, rpId localhost, UV required",
      r.status_code == 200 and r.json().get("rpId") == "localhost" and r.json().get("userVerification") == "required", r.text)
r = client().post("/api/auth/passkey/login/options", headers={**H, "host": "evil.example"})
check("unknown host name refused for passkeys", r.status_code == 400, r.text)

print("vault")
c.post("/api/auth/login", headers=H, json={"username": "admin", "password": GOOD})
c.post("/api/auth/totp/verify", headers=H, json={"code": pyotp.TOTP(secret).at(time.time() + 30)})
check("full session again", c.get("/api/auth/check").status_code == 204)
check("status: not initialized", c.get("/api/vault/status").json()["initialized"] is False)
check("short passphrase refused", c.post("/api/vault/init", headers=H, json={"passphrase": "short"}).status_code == 400)
PASS = "my vault passphrase for testing"
check("init", c.post("/api/vault/init", headers=H, json={"passphrase": PASS}).status_code == 200)
check("store a secret", c.put("/api/vault/secrets/test-router", headers=H, json={"value": "s3cr3t-value", "kind": "password"}).status_code == 200)
listing = c.get("/api/vault/secrets").json()
check("listing has names, never values", listing and "s3cr3t-value" not in str(listing) and listing[0]["name"] == "test-router")
check("drivers can read it while unlocked", vault.get("test-router") == "s3cr3t-value")
raw = db.one("SELECT ct FROM vault WHERE name='test-router'")["ct"]
check("stored encrypted (no plaintext in the DB)", b"s3cr3t-value" not in raw)
c.post("/api/vault/lock", headers=H)
try:
    vault.get("test-router")
    check("locked vault refuses reads", False)
except vault.VaultLocked:
    check("locked vault refuses reads", True)
check("wrong passphrase refused", c.post("/api/vault/unlock", headers=H, json={"passphrase": "wrong passphrase for sure"}).status_code == 403)
check("right passphrase unlocks", c.post("/api/vault/unlock", headers=H, json={"passphrase": PASS}).status_code == 200)
NEW = "a brand new vault passphrase"
r = c.post("/api/vault/passphrase", headers=H, json={"current": PASS, "new": NEW})
check("change passphrase re-encrypts", r.status_code == 200 and r.json()["reencrypted"] == 1, r.text)
c.post("/api/vault/lock", headers=H)
check("old passphrase no longer works", c.post("/api/vault/unlock", headers=H, json={"passphrase": PASS}).status_code == 403)
check("new passphrase works, value intact",
      c.post("/api/vault/unlock", headers=H, json={"passphrase": NEW}).status_code == 200 and vault.get("test-router") == "s3cr3t-value")

print("roles")
VIEW = "a reader account passphrase 7"
check("admin creates a viewer", c.post("/api/auth/users", headers=H, json={"username": "viewer", "password": VIEW, "role": "viewer"}).status_code == 200)
v = client()
v.post("/api/auth/login", headers=H, json={"username": "viewer", "password": VIEW})
s2 = v.post("/api/auth/totp/setup", headers=H).json()["secret"]
v.post("/api/auth/totp/confirm", headers=H, json={"code": pyotp.TOTP(s2).now()})
check("viewer is logged in", v.get("/api/auth/check").status_code == 204)
check("viewer can't start a scan", v.post("/api/security/scan", headers=H).status_code == 403)
check("viewer can't use the vault", v.get("/api/vault/secrets").status_code == 403)
check("viewer can't list users", v.get("/api/auth/users").status_code == 403)
check("audit log records logins and vault actions",
      {"login", "vault-unlocked", "secret-set", "login-failed"} <= {r["action"] for r in db.query("SELECT action FROM audit")})

print("\n%d passed, %d failed" % (ok, fail))
sys.exit(1 if fail else 0)
