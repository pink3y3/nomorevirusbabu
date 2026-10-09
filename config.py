# config.py — single source of truth for all modules
# Paths marked [ATTACKER-VM] are only valid on the Kali attacker machine.
# Paths marked [VICTIM-VM]   are only valid on the Ubuntu victim machine.

# ── Network ───────────────────────────────────────────────────────────────────
ATTACKER_IP     = "192.168.56.10"   # Kali attacker VM (host-only NIC)
VICTIM_IP       = "192.168.56.20"   # Ubuntu victim VM (host-only NIC)
C2_PORT         = 9001              # Command-and-Control channel
TRANSFER_PORT   = 9002              # File exfiltration channel
BACKUP_PORT     = 9003              # TLS-protected backup channel

# ── Paths [VICTIM-VM] ─────────────────────────────────────────────────────────
TEST_DATA_DIR   = "/home/victim/MILITARY_DATA"
HONEYPOT_DIR    = "/home/victim/MILITARY_DATA/A_COMMAND_ARCHIVE"
BACKUP_DIR      = "/home/victim/BACKUP"      # local staging dir for TLS backup
LOG_DIR         = "/home/victim/islab-project/logs"
RESULTS_DIR     = "/home/victim/islab-project/results"

# ── Paths [ATTACKER-VM] ───────────────────────────────────────────────────────
RSA_PUB_KEY_PATH  = "/home/kali/islab-project/keys/public.pem"
RSA_PRIV_KEY_PATH = "/home/kali/islab-project/keys/private.pem"

# ── File markers ──────────────────────────────────────────────────────────────
ENCRYPTED_EXT   = ".locked"
KEY_EXT         = ".key"
RANSOM_NOTE     = "README_DECRYPT.txt"

# ── Crypto ────────────────────────────────────────────────────────────────────
BACKUP_CERT_PATH  = "/home/victim/islab-project/keys/backup.crt"
BACKUP_KEY_PATH   = "/home/victim/islab-project/keys/backup.key"
HMAC_SECRET       = b"change-this-before-demo-day"

# ── Backup / TLS (Phase 8) ────────────────────────────────────────────────────
# The TLS backup channel uses a private lab CA and mutual authentication.
# Certificate generation instructions: see README_PERSON2.md
BACKUP_HOST        = "192.168.56.10"       # IP of the backup receiver (attacker VM)
BACKUP_BIND        = "0.0.0.0"             # backup_server listens on all interfaces
BACKUP_SERVER_NAME = "backup.isllab"       # TLS SNI hostname (must match server cert CN)
TLS_CERT_DIR       = "/home/victim/islab-project/certs"
# On the attacker/backup-server side these can be overridden to the kali path:
# TLS_CERT_DIR     = "/home/kali/islab-project/certs"

# ── Honeypot / Containment (Phase 6-7) ───────────────────────────────────────
# Simulator writes its PID here at startup; monitor reads it on tripwire fire.
SIMULATOR_PID_FILE = "/home/victim/islab-project/logs/simulator.pid"
# Host-only network adapter name on the victim VM.
# Confirm with: ip link show   (common names: eth1, enp0s8, enp0s3)
NETWORK_IFACE      = "eth1"

# ── Feature flags ─────────────────────────────────────────────────────────────
AUTH_MODE         = True   # False = naive C2 (spoofable), True = HMAC-authenticated
NETWORK_ISOLATION = False  # Set True ONLY for the final demo run (brings NIC down)
