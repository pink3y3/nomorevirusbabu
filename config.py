from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
HOME_DIR = Path.home()

# ── Network ───────────────────────────────────────────────────────────────────
ATTACKER_IP     = "192.168.56.10"   # Kali attacker VM (host-only NIC)
VICTIM_IP       = "192.168.56.20"   # Ubuntu victim VM (host-only NIC)
C2_PORT         = 9001              # Command-and-Control channel
TRANSFER_PORT   = 9002              # File exfiltration channel
BACKUP_PORT     = 9003              # TLS-protected backup channel

# ── Paths (Dynamic & Environment-Independent) ─────────────────────────────────
TEST_DATA_DIR   = str(HOME_DIR / "MILITARY_DATA")
HONEYPOT_DIR    = str(HOME_DIR / "MILITARY_DATA" / "A_COMMAND_ARCHIVE")
BACKUP_DIR      = str(HOME_DIR / "BACKUP")      # local staging dir for TLS backup
LOG_DIR         = str(BASE_DIR / "logs")
RESULTS_DIR     = str(BASE_DIR / "results")

# ── Keys & Certificates ───────────────────────────────────────────────────────
RSA_PUB_KEY_PATH  = str(BASE_DIR / "keys" / "public.pem")
RSA_PRIV_KEY_PATH = str(BASE_DIR / "keys" / "private.pem")
BACKUP_CERT_PATH  = str(BASE_DIR / "keys" / "backup.crt")
BACKUP_KEY_PATH   = str(BASE_DIR / "keys" / "backup.key")
TLS_CERT_DIR       = str(BASE_DIR / "certs")

# ── File markers ──────────────────────────────────────────────────────────────
ENCRYPTED_EXT   = ".locked"
KEY_EXT         = ".key"
RANSOM_NOTE     = "README_DECRYPT.txt"

# ── Crypto ────────────────────────────────────────────────────────────────────
HMAC_SECRET       = b"change-this-before-demo-day"

# ── Backup / TLS (Phase 8) ────────────────────────────────────────────────────
BACKUP_HOST        = "192.168.56.10"       # IP of the backup receiver (attacker VM)
BACKUP_BIND        = "0.0.0.0"             # backup_server listens on all interfaces
BACKUP_SERVER_NAME = "backup.isllab"       # TLS SNI hostname (must match server cert CN)

# ── Honeypot / Containment (Phase 6-7) ───────────────────────────────────────
SIMULATOR_PID_FILE = str(BASE_DIR / "logs" / "simulator.pid")
NETWORK_IFACE      = "eth1"

# ── Feature flags ─────────────────────────────────────────────────────────────
AUTH_MODE         = True   # False = naive C2 (spoofable), True = HMAC-authenticated
NETWORK_ISOLATION = False  # Set True ONLY for the final demo run (brings NIC down)
