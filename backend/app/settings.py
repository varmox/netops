"""Runtime settings, all from environment variables (see .env.example)."""
import os
from pathlib import Path

DEVICES_FILE = Path(os.environ.get("DEVICES_FILE", "/config/devices.yml"))
DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
BACKUP_DIR = DATA_DIR / "backups"
INBOX_DIR = DATA_DIR / "inbox"          # what devices or people upload over SFTP

CHECK_INTERVAL = int(os.environ.get("CHECK_INTERVAL", "60"))         # seconds
FAILS_BEFORE_DOWN = int(os.environ.get("FAILS_BEFORE_DOWN", "2"))    # consecutive failed rounds
BACKUP_TIME = os.environ.get("BACKUP_TIME", "03:15")                 # daily, local time HH:MM
BACKUP_KEEP = int(os.environ.get("BACKUP_KEEP", "60"))               # versions kept per device

NTFY_URL = os.environ.get("NTFY_URL", "http://ntfy").rstrip("/")
NTFY_TOPIC = os.environ.get("NTFY_TOPIC", "netops")
NTFY_TOKEN = os.environ.get("NTFY_TOKEN", "")

# --- Added features ---------------------------------------------------------------------------------
# Certificate / expiry monitoring (feature 3)
CERT_WARN_DAYS = int(os.environ.get("CERT_WARN_DAYS", "21"))
CERT_SCAN_TIME = os.environ.get("CERT_SCAN_TIME", "04:10")

# Firmware / OS end-of-life (feature 4). endoflife.date, cached locally; no device data leaves the box.
EOL_WARN_DAYS = int(os.environ.get("EOL_WARN_DAYS", "90"))
EOL_URL = os.environ.get("EOL_URL", "https://endoflife.date/api").rstrip("/")

# Internet exposure (feature 6): read from the MikroTik's own config (port forwards, UPnP, WAN input).
EXPOSURE_SCAN_TIME = os.environ.get("EXPOSURE_SCAN_TIME", "04:40")

# Honeypot / canary (feature 8): fake services; any connection from the LAN is suspicious.
HONEYPOT_ENABLED = os.environ.get("HONEYPOT_ENABLED", "true").lower() == "true"
HONEYPOT_PORTS = os.environ.get("HONEYPOT_PORTS", "23:telnet,2323:telnet,445:smb,3389:rdp,5555:adb")

# Default-credential audit (feature 5): OFF unless explicitly enabled; only RFC1918 targets.
CREDCHECK_ENABLED = os.environ.get("CREDCHECK_ENABLED", "false").lower() == "true"

# DNS filtering (feature 1): AdGuard Home's control API, if the optional container is running.
ADGUARD_URL = os.environ.get("ADGUARD_URL", "http://adguard:3000").rstrip("/")
ADGUARD_USER = os.environ.get("ADGUARD_USER", "")
ADGUARD_PASSWORD = os.environ.get("ADGUARD_PASSWORD", "")
ADGUARD_PUBLIC_URL = os.environ.get("ADGUARD_PUBLIC_URL", "")   # admin UI link shown in Features (blank = derive from host)

# Weekly report (feature 9)
REPORT_DAY = int(os.environ.get("REPORT_DAY", "0"))        # 0 = Monday
REPORT_TIME = os.environ.get("REPORT_TIME", "08:00")

# Compliance reports written by the host playbook (host/ansible), if present.
COMPLIANCE_DIR = Path(os.environ.get("COMPLIANCE_DIR", str(DATA_DIR / "compliance")))
