# Host setup (Raspberry Pi 5)

## Hardware

- Raspberry Pi 5, **8 GB** (4 GB works without the optional Grafana/Harbor add-ons)
- Official 27 W power supply, active cooler
- Boot from an **NVMe SSD** (M.2 HAT) or a high-endurance microSD card
- **External USB disk** for backups (LUKS-encrypted)
- Wired Ethernet to the main router/switch

## Operating system

Ubuntu Server 24.04 LTS (arm64), written with Raspberry Pi Imager. Then the Ansible playbook in
`host/ansible` hardens it (see [HARDENING.md](HARDENING.md)).

## Tools on the host

Only what the appliance needs. Everything else runs in containers.

| Tool | Why | Hardening |
|---|---|---|
| Docker Engine + compose plugin (from Docker's apt repo) | runs the stack | `daemon.json`: `no-new-privileges`, `icc: false`, `live-restore`, log rotation, `userland-proxy: false`; socket only for root and the updater |
| cosign | verify image signatures before updates | pinned version, checksum-verified |
| nftables | host firewall | default-deny, see HARDENING |
| cryptsetup | LUKS2 for the backup disk | keyfile not on the SD card (unlocked via the UI) |
| restic | encrypted, deduplicated backups to the external disk | runs from the backend container; host only mounts the disk |
| chrony | time sync (TOTP, logs, certificates) | NTS where available |
| auditd, AppArmor | STIG logging and confinement | rules from the playbook |
| unattended-upgrades | OS security patches | security pocket only |
| OpenSCAP (`openscap-scanner`, `ssg-*`) | STIG/CIS compliance report | run monthly, report shown in the UI |
| smartmontools | health of the SSD and backup disk | alerts via ntfy |

Not installed: GUI, avahi, cups, bluetooth stack, compilers, Python/Node on the host.

## File ownership

The backend runs as UID 10001 (non-root) on a read-only root filesystem. On the host:

```bash
sudo chown -R 10001:10001 data secrets
sudo chmod 700 data secrets
```

## First start

1. `docker compose up -d`, then `docker compose logs backend | grep "SETUP CODE"`.
2. Open `https://netops.lan` (add a static DNS entry for the Pi on your router; passkeys need a host name,
   not an IP), enter the setup code, create the administrator, add a passkey or an authenticator app,
   save the recovery codes.
3. **Vault:** set a passphrase (store it in your password manager) and add device credentials.

## Backup disk

`config/backup.yml`:

```yaml
backup:
  device: /dev/disk/by-uuid/<uuid>     # the external disk's LUKS partition
  mapper: netops-backup
  mount: /mnt/netops-backup
  schedule: "03:45"                    # daily, after the config backups
  keep: { daily: 14, weekly: 8, monthly: 12 }
  include: [data/backups, data/security, config, data/db]
```

The disk is unlocked with the vault (same unlock step after a reboot), backups are encrypted again by
restic, and a monthly restore test runs automatically.
