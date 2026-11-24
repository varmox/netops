# Host playbook (Ubuntu Server 24.04 LTS)

Turns a fresh Ubuntu Server 24.04 (Raspberry Pi 5 or any amd64/arm64 box) into the hardened NetOps appliance:
DISA STIG for Ubuntu 24.04 and CIS Level 1 Server where they fit a headless Docker host, deviations in
[DEVIATIONS.md](DEVIATIONS.md).

## Use

On your computer (Ansible ≥ 2.16, no extra collections needed):

```bash
cd host/ansible
cp inventory.example.yml inventory.yml      # the Pi's address and your admin user
ansible-playbook site.yml --ask-become-pass
```

Then reboot once (kernel parameters, audit at boot, Wi-Fi/Bluetooth overlays, immutable audit rules).

Keep an SSH session open while the `ssh` role runs the first time: if your key isn't accepted, you still
have a way in.

## Roles

Play 1 (appliance setup):

| Role | What it does |
|---|---|
| `base` | updates, removes unneeded services (avahi, cups, bluetooth, telnet, snapd…), chrony with NTS, persistent journal, banner, unattended security upgrades with a reboot window, no core dumps, Pi radios off |
| `accounts` | sudo logging and pty, root locked; checks the admin user has a password |
| `ssh` | keys only, no root, `AllowUsers`, no forwarding, verbose logging |
| `kernel` | sysctl hardening, unused filesystems/protocols blocked, AppArmor check |
| `firewall` | nftables default-deny: SSH from the LAN only; Docker-published ports (80, 443, 8090, 2222) from the LAN only; Docker's own rules untouched |
| `audit` | auditd settings, audit from early boot, watches on the stack's configuration |
| `docker` | Docker Engine from Docker's repo (signing key fingerprint pinned), hardened `daemon.json`, empty docker group |
| `tools` | restic, cryptsetup, smartmontools, OpenSCAP; cosign and the SCAP Security Guide pinned and checksum-verified |
| `netops` | `/opt/netops` with `data` and `secrets` owned by the backend's UID 10001 |

Play 2 (`compliance`): applies the **DISA STIG with SSG's remediation**, tailored as described in
[DEVIATIONS.md](DEVIATIONS.md) — password rules, faillock, PAM, AIDE, audit rules, SSH algorithms, file
permissions, timeouts — then schedules a monthly OpenSCAP scan (tailored STIG + CIS Level 1 Server) whose
HTML reports and `summary.json` land in `/opt/netops/data/compliance` for the UI.

The STIG removes passwordless sudo: the admin user needs a password (the playbook checks this first).

Tags: each role has its own (`--tags firewall`); `stig` is the remediation, `compliance-now` a new report,
`services` everything that needs a running systemd, `pi` the Raspberry Pi specifics.

## Verify

```bash
sudo /usr/local/sbin/netops-compliance-scan       # reports in /opt/netops/data/compliance
sudo nft list table inet netops
sudo sshd -T | grep -Ei 'ciphers|macs|kex|permitroot|passwordauth'
```
