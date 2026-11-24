# Deviations from the DISA STIG / CIS benchmark

The DISA STIG for Ubuntu 24.04 is applied with the SCAP Security Guide's own remediation, through a tailoring
file (`roles/compliance/templates/tailoring.xml.j2`, rule list in `roles/compliance/vars/main.yml`). The
monthly report evaluates the same tailored profile, so its result is the appliance's real STIG status.
CIS Level 1 Server is **reported only** (`cis_level1_server-latest.html`): its firewall remediation
(a default-deny `inet filter` table) would cut Docker's container networking, and several of its rules
contradict each other across firewall/time-sync choices.

## Deselected STIG rules

| Rules | Reason | What NetOps does instead |
|---|---|---|
| `package_ufw_installed`, `check_ufw_active`, `ufw_only_required_services`, `ufw_rate_limit` | UFW rewrites the ruleset Docker depends on | nftables default-deny (`firewall` role): SSH and the published ports from the LAN only, SSH rate-limited |
| smartcard, SSSD, `only_allow_dod_certs` (16 rules) | no DoD PKI / CAC on a home appliance | SSH keys only for the OS; passkeys or TOTP for the web UI |
| `is_fips_mode_enabled` | Ubuntu's FIPS kernel needs Ubuntu Pro and doesn't exist for the Raspberry Pi kernel | SSH limited to FIPS-approved algorithms by the STIG rules that remain |
| `encrypt_partitions` | can't be applied after installation; a Pi has no TPM to unlock the root disk unattended | secrets encrypted in the vault (unlocked after boot); backup disk LUKS-encrypted |
| `grub2_password`, `grub2_uefi_password` | unattended reboots after updates; the Pi doesn't use GRUB | physical security of the box |
| `auditd_audispd_configure_remote_server`, `auditd_offload_logs`, `rsyslog_remote_access_monitoring` | no central log server in a home network | local audit log, rotated; a remote target may be added later |
| `banner_etc_issue_net`, `banner_etc_profiled_ssh_confirm` | the exact DoD notice text | neutral "authorized use only" banner |
| `wireless_disable_interfaces` | the STIG fix needs NetworkManager | Wi-Fi and Bluetooth disabled in firmware (`dtoverlay=disable-wifi,disable-bt`) |

## Changed STIG values

| Value | STIG | NetOps | Reason |
|---|---|---|---|
| faillock `unlock_time` | never (admin must unlock) | 900 s (`stig_faillock_unlock_time`) | one administrator and no root login: a permanent lock needs console access. Set `0` if you have another admin path. |
| auditd `space_left_action` | email | syslog | no mail server; NetOps alerts on low disk via ntfy |

## Appliance settings outside the benchmarks

| Area | Benchmark expectation | NetOps | Reason |
|---|---|---|---|
| IP forwarding (CIS) | `net.ipv4.ip_forward = 0` | `1` | Docker routes container traffic; the firewall limits what is forwarded |
| USB storage (CIS L2) | disabled | allowed | the encrypted backup disk is a USB disk |
| Docker group | — | kept empty | membership is root-equivalent; use `sudo docker` |
| `userns-remap` (CIS Docker) | recommended | off | breaks ownership of the bind-mounted data (UID 10001); containers run non-root without capabilities instead |
| Web UI passwords | — | NIST SP 800-63B | length + breached-password check, no composition rules; OS accounts follow the STIG |
