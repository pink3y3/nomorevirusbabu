# Ransomware Kill-Chain Simulation — IS Lab Project

> **Academic project** — all content is entirely fictional and for educational purposes only.
> No real malware, no real targets, no real data exfiltration.

---

## Overview

This repository implements a complete **Ransomware Kill-Chain Simulation** with matching defensive mechanisms, demonstrated across two isolated virtual machines:

| VM | Role | IP | OS |
|---|---|---|---|
| IS-Attacker | C2 server, file receiver, key holder | `192.168.56.10` | Kali Linux |
| IS-Victim | C2 client, file source, ransomware target | `192.168.56.20` | Ubuntu 22.04 |

Both VMs sit on a **host-only private network** — no internet access during any test run.

---

## Repository Structure

```
nomorevirusbabu/
├── config.py                  # Single source of truth for all IPs, paths, ports
├── shared/
│   └── crypto.py              # AES-256-CBC + RSA-2048-OAEP shared library
├── attacker/
│   ├── c2_server.py           # C2 server (naive + HMAC-authenticated variants)
│   ├── transfer_receiver.py   # Receives and decrypts exfiltrated files
│   ├── c2_spoof_demo.py       # Live spoofing demo against c2_server
│   └── c2_spoof_selftest.py   # Self-contained loopback spoofing demo
├── victim/
│   ├── c2_client.py           # C2 client — spawns transfer_sender and simulator
│   ├── transfer_sender.py     # Scans, AES-encrypts, and streams files to attacker
│   ├── dataset_generator.py   # Generates MILITARY_DATA/ fictional dataset
│   ├── honeypot_monitor.py    # Watchdog tripwire — detects + contains simulator
│   ├── containment.py         # kill_process(), isolate_network(), snapshot
│   └── backup.py              # TLS-protected backup and restore
├── ransomware/
│   └── simulator.py           # Ransomware simulator — alphabetical traversal + hybrid encrypt
├── analysis/
│   ├── pcap_parser.py         # PyShark/Scapy PCAP → SQLite pipeline (Person 3)
│   ├── forensic_report.py     # Timeline + IOC report generator (Person 3)
│   └── evaluate.py            # Metrics aggregation and chart generation (Person 3)
├── tests/
│   └── test_crypto.py         # Unit tests + benchmarks for shared/crypto.py
├── keys/
│   └── public.pem             # RSA-2048 public key (committed; private key attacker-side only)
├── results/
│   ├── crypto_benchmarks.json
│   ├── transfer_benchmarks.json
│   └── spoof_demo_output.txt
└── logs/
    └── c2.log.sample          # JSON-lines format reference for forensic_report.py
```

---

## Dependencies

Install on **both VMs** unless noted:

```bash
pip install cryptography watchdog psutil

# Victim VM only:
pip install python-docx openpyxl pillow   # for dataset_generator.py

# Attacker VM only (for PCAP analysis — Person 3):
pip install pyshark scapy

# System packages (Victim VM):
sudo apt install ffmpeg    # for dataset_generator.py mp3/mp4 generation
```

---

## Quick-Start: Full Demo Run Order

### Step 0 — Reset environment
```bash
# On Victim VM:
rm -rf /home/victim/MILITARY_DATA /home/victim/BACKUP
python3 victim/dataset_generator.py          # regenerate MILITARY_DATA/
python3 victim/backup.py client              # TLS-backup clean dataset to attacker
```

### Step 1 — Start services on Attacker VM (IS-Attacker)
```bash
# Terminal 1 — C2 server
python3 attacker/c2_server.py

# Terminal 2 — Exfiltration receiver
python3 attacker/transfer_receiver.py

# Terminal 3 (optional) — TLS backup server
python3 victim/backup.py server --dir /home/kali/islab-project/BACKUP
```

### Step 2 — Start honeypot monitor on Victim VM (IS-Victim)
```bash
# Terminal 1 — must be running BEFORE c2_client connects
python3 victim/honeypot_monitor.py
```

### Step 3 — Connect victim to C2 (IS-Victim)
```bash
# Terminal 2
python3 victim/c2_client.py
```

### Step 4 — Operator issues commands from Attacker VM

In the c2_server terminal, the server automatically dispatches commands to the connected victim. Edit `c2_server.py` or extend it with a CLI input loop to send:

| Command | Effect |
|---|---|
| `START_EXFIL` | Victim spawns `transfer_sender.py`, streams all targeted files to attacker |
| `START_ENCRYPT` | Victim spawns `ransomware/simulator.py`; honeypot fires when A_COMMAND_ARCHIVE is touched |
| `STOP` | Victim gracefully exits C2 loop |

### Step 5 — Spoofing demo (optional — separate terminal on Attacker VM)
```bash
# Against naive variant (AUTH_MODE=False):
python3 attacker/c2_spoof_demo.py --target 192.168.56.10 --naive

# Against authenticated variant (AUTH_MODE=True):
python3 attacker/c2_spoof_demo.py --target 192.168.56.10 --auth

# Self-contained loopback version (no live server needed):
python3 attacker/c2_spoof_selftest.py
```

---

## Running Tests

```bash
# From project root:
python3 tests/test_crypto.py

# With benchmarks:
BENCHMARK=1 python3 tests/test_crypto.py

# pytest:
python3 -m pytest tests/test_crypto.py -v

# Transfer loopback benchmark:
python3 victim/transfer_sender.py --benchmark
```

---

## Key Configuration (`config.py`)

| Variable | Default | Description |
|---|---|---|
| `ATTACKER_IP` | `192.168.56.10` | Kali VM IP |
| `VICTIM_IP` | `192.168.56.20` | Ubuntu VM IP |
| `AUTH_MODE` | `True` | `False` = naive C2, `True` = HMAC-authenticated |
| `NETWORK_ISOLATION` | `False` | Set `True` on final demo to bring NIC down on containment |
| `NETWORK_IFACE` | `eth1` | Run `ip link show` on victim to confirm correct NIC name |
| `TLS_CERT_DIR` | `/home/victim/islab-project/certs` | See `README_PERSON2.md` for cert generation |

---

## Log Files (JSON-lines format)

All modules write JSON-lines to `config.LOG_DIR` (`/home/victim/islab-project/logs/`):

| File | Written by | Key events |
|---|---|---|
| `c2.log` | `c2_server.py` + `c2_client.py` | connection, command_received (with auth field), start_encrypt_triggered |
| `transfer.log` | `transfer_sender.py` + `transfer_receiver.py` | file_sent, file_received, throughput_mbps |
| `honeypot.log` | `honeypot_monitor.py` | decoy_created, pid_read, kill_success, detect_to_kill_ms |
| `containment.log` | `containment.py` | process_terminated, network_isolated, filesystem_snapshot |
| `simulator.log` | `simulator.py` | traversal_starting, file_encrypted, ransom_note_dropped, traversal_complete |
| `backup.log` | `backup.py` | backup_completed, backup_received, restore_completed |

---

## Team Split

| Person | Phases | Key deliverables |
|---|---|---|
| Person 1 | 0, 2, 3, 4 | `shared/crypto.py`, C2 channel, transfer modules, crypto tests |
| Person 2 | 1, 5, 6, 7, 8 | Dataset generator, ransomware simulator, honeypot + containment, TLS backup |
| Person 3 | 9, 10, 12, 13 | PCAP parser, forensic report, evaluation metrics, integration |

---

## Security Notice

This is a **controlled academic simulation**. The code:
- Only operates on explicitly configured fictional data under `config.TEST_DATA_DIR`
- Contains hard path-escape guards in `simulator.py` and `backup.py`
- Does **not** execute vssadmin or any destructive OS commands (only logs the string)
- Uses `psutil` safety guards in `containment.py` to only kill processes identified as `simulator.py`
- Never commits or exposes `keys/private.pem` (blocked by `.gitignore`)