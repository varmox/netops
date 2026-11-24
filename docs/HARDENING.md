# Hardening

Three layers: the host, the containers, and the application. For each, the baseline, how it is applied,
and how it is verified.

## Host: Ubuntu Server 24.04 LTS (arm64) on a Raspberry Pi 5

**Why Ubuntu and not Raspberry Pi OS / Debian:** DISA publishes a STIG for Ubuntu 24.04 LTS, and CIS a
benchmark for it; neither exists for Raspberry Pi OS or Debian. Ubuntu 24.04 supports the Pi 5 officially,
so the published baselines can be applied and checked as they are.

| Baseline | Applied with | Verified with |
|---|---|---|
| DISA STIG for Ubuntu 24.04 LTS | `host/ansible` playbook (rules that fit an appliance) | OpenSCAP (`ssg-ubuntu2404-ds.xml`, STIG profile) |
| CIS Ubuntu Linux 24.04 Benchmark, Level 1 Server | same playbook | OpenSCAP CIS profile, Lynis |
| NIST SP 800-123 (server security) | general guidance | — |

What the playbook does (summary):

- **Accounts:** one admin user with SSH key only; root login disabled; password aging and PAM
  faillock per STIG; sudo with logging.
- **SSH:** key-only, no root, FIPS-approved ciphers/MACs/KEX only, idle timeout, banner, `AllowUsers`.
- **Network:** nftables default-deny inbound; allow 443/tcp (UI), 22/tcp (admin, LAN only),
  8090/tcp (ntfy, LAN only), 2222/tcp (SFTP, LAN only); IPv6 same rules.
- **Kernel:** sysctl hardening (no IP forwarding, no redirects/source routing, rp_filter, kptr_restrict,
  dmesg_restrict, ptrace_scope, unprivileged BPF off), module blacklist (usb-storage except the backup
  disk's driver, firewire, rare protocols), AppArmor enforcing.
- **Logging:** auditd with STIG rules, journald persistent and size-capped, time sync with chrony.
- **Updates:** unattended-upgrades for security pockets, automatic reboot window.
- **Services:** everything not needed removed or masked (avahi, cups, bluetooth, wpa_supplicant if wired).
- **Storage:** backup disk LUKS2-encrypted, mounted `nodev,nosuid,noexec`.

Deviations from the STIG are listed in `host/ansible/DEVIATIONS.md` with a reason each (for example
FIPS mode: not available on the Pi's kernel; GUI-related rules: not applicable to a headless appliance).

## Containers: NIST SP 800-190, CIS Docker Benchmark

| Control | Setting |
|---|---|
| Least privilege | every service runs as a non-root UID; `cap_drop: [ALL]`, only needed capabilities added back (`NET_BIND_SERVICE` for nginx, `NET_RAW` for the scanner) |
| Immutable | `read_only: true` root filesystem, `tmpfs` for `/tmp` and run directories |
| No escalation | `security_opt: [no-new-privileges:true]`, default seccomp and AppArmor profiles |
| Resource limits | memory and PID limits per service (Pi-sized) |
| Network segmentation | `frontend` network (nginx ↔ backend), `internal` network without internet (database, Prometheus); only nginx publishes ports |
| Image hygiene | minimal bases (Alpine / distroless where possible), no package managers at runtime, rebuilt weekly, Trivy gate, cosign signature |
| Secrets | never in images or environment of non-backend services; device credentials only in the vault |
| Docker daemon | `userns-remap` or rootless where the drivers allow it, `live-restore`, `no-new-privileges` default, log rotation, `icc=false` |

Verified with `docker-bench-security` (report in the UI).

## Application: ASD STIG / OWASP ASVS level 2

- Authentication and session management as in the [security model](SECURITY-MODEL.md).
- Strict headers: `Content-Security-Policy` (self only, no inline script), `Strict-Transport-Security`,
  `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `frame-ancestors 'self'`.
- Input: every device identifier, file name and command argument validated or quoted (`shlex.quote`,
  allow-lists); no shell interpolation of user input on remote devices.
- Audit: logins, MFA changes, vault unlocks, credential changes and every remediation action.
- Dependencies pinned; Trivy and `npm audit` in CI.
