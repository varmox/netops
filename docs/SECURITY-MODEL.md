# Security model

NetOps holds credentials for routers, firewalls and servers and can change their configuration. If it is
compromised, the network is. Everything below follows from that.

## Assets

| Asset | Where | Protection |
|---|---|---|
| Device credentials (SSH keys, API tokens, passwords) | vault in the database | encrypted at rest, key only in memory after unlock |
| Config backups (contain network layout, sometimes secrets) | `data/backups`, external disk | redaction where possible; restic encryption on the backup disk |
| Accounts, MFA secrets, passkeys | database | Argon2id hashes; TOTP secrets encrypted with the app key |
| Ability to change devices (remediation) | backend | approval by a logged-in user with MFA, audit log |
| The update channel | GHCR + updater | cosign signature verification before every update |

## Threats and answers

| Threat | Answer |
|---|---|
| Guessing or stolen passwords | Argon2id, breached-password check, MFA required (TOTP / passkeys), lockout with backoff, nginx rate limit — NIST SP 800-63B AAL2, NIST SP 800-53 AC-7, IA-2(1), IA-5 |
| Session theft (XSS, CSRF) | server-side sessions in HttpOnly/Secure/SameSite=Strict cookies, rotated at login, idle + absolute timeout; strict Content-Security-Policy; state-changing requests need a custom header — ASD STIG session management |
| Stolen Pi / SD card | vault locked after every boot (key derived from an unlock passphrase, never stored); backup disk LUKS-encrypted — SC-28 |
| Compromised IoT device attacking the box | only HTTPS (443) and SSH exposed; nftables default-deny; containers non-root, read-only, no capabilities — SC-7, CM-7 |
| Malicious or vulnerable images | own builds on minimal bases, Trivy gate in CI, cosign signatures verified on the box, weekly rebuilds — SR-4, SR-11, SI-2, RA-5 |
| Abuse of remediation (cutting off the network) | protected devices (router, modem, the box itself) can never be quarantined; every action needs approval and is audited; signed one-time links expire after 24 h — AU-2, AU-12 |
| AI assistant leaking data | opt-in, user's own key, secrets and credentials redacted before anything is sent, read-only by default — no actions without approval |

## Authentication (NIST SP 800-63B, AAL2)

- Passwords: at least 15 characters (single-factor rule of the current revision, also applied here),
  no composition rules, checked against a breached-password list, Argon2id (RFC 9106 parameters).
- Second factor required for every account: TOTP (RFC 6238) or a passkey (WebAuthn, platform or roaming).
  Passkeys can also be the only factor (phishing-resistant).
- Ten single-use recovery codes, stored hashed.
- TOTP secrets are encrypted with an app key (`data/.app_key`), not the vault: logging in must work while
  the vault is locked, because unlocking it needs a logged-in user.
- First run: the backend prints a one-time setup code to its log; only someone with access to the host can
  create the first account (prevents a drive-by takeover of a fresh install).
- Lockout: exponential backoff per account and per source address; failures are audited.

## Vault

- libsodium `crypto_secretbox` (XSalsa20-Poly1305) per secret, key from the unlock passphrase with
  Argon2id (`crypto_pwhash`, moderate limits tuned for a Pi 5).
- The key lives only in process memory. After a reboot the vault is locked: scans and backups that need
  credentials wait, the UI asks for the passphrase.
- Changing the passphrase re-encrypts all secrets; there is no recovery without it (by design).

## Update chain

GitHub Actions builds every image for arm64 and amd64 → Trivy gate (no fixable critical CVEs) → cosign
keyless signature (GitHub OIDC) → GHCR. The on-box updater checks the release manifest on a schedule,
verifies each image signature against this repository's workflow identity, pulls by digest, restarts,
runs health checks and rolls back to the previous digests if anything fails.

## Reporting

See [SECURITY.md](../SECURITY.md).
