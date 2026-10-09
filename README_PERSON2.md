# README_PERSON2.md — Person 2 Setup Guide

> Phase 8 — TLS-Protected Backup Channel
> This guide creates the private lab CA and all certificates required by `victim/backup.py`.
> **Run these commands once on each VM before the first demo run.**

---

## Why Mutual TLS?

The **attack path** (C2 + exfiltration) uses plain sockets with no certificate validation,
making it vulnerable to MITM and command injection (demonstrated in the spoofing demo).
The **backup channel** uses TLS with a private certificate authority and mutual
client-certificate authentication — so only the legitimate victim client can deposit files
and only the legitimate attacker/backup server will be trusted by the client. This contrast
is the core of the Authentication and Confidentiality section of the evaluation report.

---

## Directory Layout After Setup

```
/home/victim/islab-project/certs/    (on Victim VM)
    ca.crt          ← Lab CA certificate (shared / public)
    client.crt      ← Victim's TLS client certificate
    client.key      ← Victim's TLS client private key  [DO NOT COMMIT]

/home/kali/islab-project/certs/      (on Attacker VM)
    ca.crt          ← Same Lab CA certificate (copy over)
    server.crt      ← Backup server's TLS certificate
    server.key      ← Backup server's TLS private key  [DO NOT COMMIT]
```

All private keys MUST stay on their respective VMs and never be committed to git.

---

## Step-by-Step Certificate Generation

Run the commands below **on the Victim VM** (you have access to both VMs from there via
shared folders or SCP).

### 1 — Create the certificate directory

```bash
mkdir -p /home/victim/islab-project/certs
cd /home/victim/islab-project/certs
```

### 2 — Generate the private Lab CA

```bash
# CA private key
openssl genrsa -out ca.key 2048

# Self-signed CA certificate (valid 365 days)
openssl req -x509 -new -nodes \
    -key ca.key \
    -sha256 \
    -days 365 \
    -subj "/CN=ISLab-CA/O=ISLab/C=IN" \
    -out ca.crt
```

> `ca.key` stays on Victim VM only. `ca.crt` is copied to both VMs.

### 3 — Generate the backup SERVER certificate (used by Attacker VM)

```bash
# Server private key
openssl genrsa -out server.key 2048

# Certificate Signing Request
# CN must match config.BACKUP_SERVER_NAME = "backup.isllab"
openssl req -new \
    -key server.key \
    -subj "/CN=backup.isllab/O=ISLab/C=IN" \
    -out server.csr

# Sign with the Lab CA
openssl x509 -req \
    -in server.csr \
    -CA ca.crt \
    -CAkey ca.key \
    -CAcreateserial \
    -out server.crt \
    -days 365 \
    -sha256
```

### 4 — Generate the CLIENT certificate (used by Victim VM)

```bash
# Client private key
openssl genrsa -out client.key 2048

# Certificate Signing Request
openssl req -new \
    -key client.key \
    -subj "/CN=victim/O=ISLab/C=IN" \
    -out client.csr

# Sign with the Lab CA
openssl x509 -req \
    -in client.csr \
    -CA ca.crt \
    -CAkey ca.key \
    -CAcreateserial \
    -out client.crt \
    -days 365 \
    -sha256
```

### 5 — Copy certificates to the Attacker VM

```bash
# From Victim VM, SCP the server certs and CA to Kali:
scp ca.crt server.crt server.key \
    kali@192.168.56.10:/home/kali/islab-project/certs/
```

> After this, Attacker VM has: `ca.crt`, `server.crt`, `server.key`
> Victim VM retains: `ca.crt`, `client.crt`, `client.key`

### 6 — Update config.py if needed

`config.py` already sets:
```python
TLS_CERT_DIR       = "/home/victim/islab-project/certs"
BACKUP_HOST        = "192.168.56.10"
BACKUP_SERVER_NAME = "backup.isllab"
```

On the **Attacker/backup-server** machine (`backup.py server` mode), override `TLS_CERT_DIR`
by editing config.py or passing `--cert-dir` if you add that argument to `backup.py`.
The simplest approach for the lab demo: keep a copy of the certs in the same relative path
(`certs/`) on both VMs.

### 7 — Verify the chain

```bash
openssl verify -CAfile ca.crt client.crt     # should print "client.crt: OK"
openssl verify -CAfile ca.crt server.crt     # should print "server.crt: OK"
```

---

## Running the Backup Channel

### On Attacker VM — start the backup server
```bash
cd /home/kali/islab-project
python3 victim/backup.py server --dir /home/kali/islab-project/BACKUP
```

### On Victim VM — send a backup before the attack
```bash
cd /home/victim/islab-project
python3 victim/backup.py client --dir /home/victim/MILITARY_DATA
```

### On Victim VM — restore after containment
```bash
python3 victim/backup.py restore \
    --backup /home/kali/islab-project/BACKUP \
    --dir    /home/victim/MILITARY_DATA \
    --baseline results/baseline_hashes.json
```

The restore script will print a hash-diff report comparing restored files against the
pre-attack SHA-256 baseline saved by `dataset_generator.py`.

---

## Honeypot + Containment Setup (Phase 6 & 7)

### Confirm network interface name

```bash
ip link show
# Look for the host-only adapter — usually eth1 or enp0s8
```

Update `config.NETWORK_IFACE` to match (default: `eth1`).

### Enable network isolation (optional — final demo only)

In `config.py`:
```python
NETWORK_ISOLATION = True   # Brings DOWN config.NETWORK_IFACE on tripwire fire
```

> **Warning:** Setting this to True during development will drop your SSH connection
> to the Victim VM. Test the kill_process() path separately before enabling isolation.

---

## Dataset Generation (Phase 1)

On the **Victim VM**, after cloning the repo:

```bash
# Install dependencies first:
sudo apt install -y ffmpeg
pip install python-docx openpyxl pillow

# Generate MILITARY_DATA/ (will fail if it already exists — delete manually first):
python3 victim/dataset_generator.py
# → Creates /home/victim/MILITARY_DATA/ with all fictional files
# → Saves     results/baseline_hashes.json for post-attack comparison
```

The generator uses `SEED = 20261009` so every run produces bit-identical files with
identical SHA-256 hashes — this is what makes evaluation trials repeatable.

---

## Files Created by the Simulator (for reference)

When `ransomware/simulator.py` runs, it adds:

| Created file | Description |
|---|---|
| `<name>.locked` | AES-256-CBC ciphertext of the original file |
| `<name>.key` | 16-byte IV \|\| 256-byte RSA-wrapped AES key |
| `README_DECRYPT.txt` | Ransom note in every encrypted directory |
| `logs/simulator.pid` | Own PID — read by honeypot_monitor on tripwire |
| `logs/simulator.log` | JSON-lines traversal events |

The simulator does **not** execute `vssadmin` or any OS destructive command —
it only logs the command string for forensic evidence.
