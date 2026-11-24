"""SQLite store (data/netops.db): accounts, sessions, MFA factors, the vault and the audit log.

One short-lived connection per call; WAL mode so readers never block the writer. The file is 0600.
"""
import contextlib
import os
import sqlite3
import time

from . import settings

DB = settings.DATA_DIR / "netops.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY,
  username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
  pw_hash       TEXT NOT NULL,
  role          TEXT NOT NULL DEFAULT 'admin' CHECK (role IN ('admin', 'viewer')),
  totp_enc      BLOB,                 -- TOTP secret, encrypted with the app key
  totp_pending  BLOB,                 -- during enrollment, until the first code is confirmed
  totp_last     INTEGER DEFAULT 0,    -- last accepted time step (replay protection)
  failed        INTEGER NOT NULL DEFAULT 0,
  locked_until  REAL NOT NULL DEFAULT 0,
  created       REAL NOT NULL,
  last_login    REAL
);
CREATE TABLE IF NOT EXISTS passkeys (
  id          INTEGER PRIMARY KEY,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  cred_id     TEXT NOT NULL UNIQUE,   -- base64url
  public_key  BLOB NOT NULL,
  sign_count  INTEGER NOT NULL DEFAULT 0,
  name        TEXT NOT NULL,
  transports  TEXT,
  created     REAL NOT NULL,
  last_used   REAL
);
CREATE TABLE IF NOT EXISTS recovery_codes (
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash  TEXT NOT NULL,
  used       REAL
);
CREATE TABLE IF NOT EXISTS sessions (
  id         TEXT PRIMARY KEY,        -- sha256 of the cookie value; the value itself is never stored
  user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,
  stage      TEXT NOT NULL,           -- passkey | mfa | enroll | full
  created    REAL NOT NULL,
  seen       REAL NOT NULL,
  ip         TEXT,
  ua         TEXT,
  challenge  TEXT                     -- pending WebAuthn challenge (base64url)
);
CREATE TABLE IF NOT EXISTS vault_meta (
  id        INTEGER PRIMARY KEY CHECK (id = 1),
  salt      BLOB NOT NULL,
  ops       INTEGER NOT NULL,
  mem       INTEGER NOT NULL,
  check_ct  BLOB NOT NULL,            -- a known value encrypted with the key: verifies the passphrase
  created   REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS vault (
  name         TEXT PRIMARY KEY,
  kind         TEXT NOT NULL,
  description  TEXT,
  ct           BLOB NOT NULL,
  updated      REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
  id      INTEGER PRIMARY KEY,
  time    REAL NOT NULL,
  user    TEXT,
  action  TEXT NOT NULL,
  detail  TEXT,
  ip      TEXT
);
CREATE INDEX IF NOT EXISTS audit_time ON audit(time);
"""


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB, timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextlib.contextmanager
def tx():
    """A write transaction (BEGIN IMMEDIATE: one writer at a time, no surprises)."""
    conn = connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        yield conn
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def query(sql: str, *args) -> list[sqlite3.Row]:
    conn = connect()
    try:
        return conn.execute(sql, args).fetchall()
    finally:
        conn.close()


def one(sql: str, *args) -> sqlite3.Row | None:
    rows = query(sql, *args)
    return rows[0] if rows else None


def init() -> None:
    settings.DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = connect()
    try:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript(SCHEMA)
    finally:
        conn.close()
    os.chmod(DB, 0o600)


def audit(action: str, user: str | None = None, detail: str = "", ip: str | None = None) -> None:
    with tx() as c:
        c.execute("INSERT INTO audit (time, user, action, detail, ip) VALUES (?, ?, ?, ?, ?)",
                  (time.time(), user, action, detail[:500], ip))
