"""TLS-protected backup and restore for the lab dataset.

Uses mutual TLS: the server validates the client's certificate and the client validates
the server certificate. Generate a private lab CA and issue both certificates as described
in README_PERSON2.md. Keep private keys out of Git.
"""
from __future__ import annotations
import hashlib, json, os, socket, ssl, struct, shutil
from datetime import datetime, timezone
from pathlib import Path

try:
    import config
except ImportError:
    config = None

CHUNK = 64 * 1024
MAX_PATH = 4096
MAX_FILE = 512 * 1024 * 1024

def _now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

def _paths():
    cert_dir = Path(getattr(config, "TLS_CERT_DIR", "certs") if config else "certs")
    return cert_dir / "ca.crt", cert_dir / "server.crt", cert_dir / "server.key", cert_dir / "client.crt", cert_dir / "client.key"

def _log(event, **fields):
    log_dir = Path(getattr(config, "LOG_DIR", "logs") if config else "logs")
    log_dir.mkdir(parents=True, exist_ok=True)
    with (log_dir / "backup.log").open("a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": _now(), "module": "backup", "event": event, **fields}) + "\n")

def _recv_exact(sock, n):
    out = bytearray()
    while len(out) < n:
        part = sock.recv(n - len(out))
        if not part:
            raise ConnectionError("Peer closed connection unexpectedly")
        out.extend(part)
    return bytes(out)

def _send_file(sock, rel: str, path: Path):
    name = rel.encode("utf-8")
    size = path.stat().st_size
    if len(name) > MAX_PATH or size > MAX_FILE:
        raise ValueError(f"File/path too large: {rel}")
    sock.sendall(struct.pack("!HI", len(name), size) + name)
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(CHUNK), b""):
            sock.sendall(chunk)

def backup_client(data_dir: str, host: str | None = None, port: int | None = None):
    if config is None:
        raise RuntimeError("config.py not found")
    root = Path(data_dir).resolve()
    host = host or getattr(config, "BACKUP_HOST", "127.0.0.1")
    port = port or int(config.BACKUP_PORT)
    ca, _, _, client_crt, client_key = _paths()
    if not ca.is_file() or not client_crt.is_file() or not client_key.is_file():
        raise FileNotFoundError("TLS CA/client cert/key missing. See README_PERSON2.md.")
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca))
    ctx.load_cert_chain(certfile=str(client_crt), keyfile=str(client_key))
    sent = 0
    with socket.create_connection((host, port), timeout=10) as raw:
        with ctx.wrap_socket(raw, server_hostname=getattr(config, "BACKUP_SERVER_NAME", "localhost")) as tls:
            tls.sendall(b"ISLB1")
            paths = [p for p in sorted(root.rglob("*")) if p.is_file()]
            tls.sendall(struct.pack("!I", len(paths)))
            for p in paths:
                _send_file(tls, p.relative_to(root).as_posix(), p)
                sent += 1
            tls.sendall(struct.pack("!H", 0))  # end marker: zero-length filename
            status = _recv_exact(tls, 2)
            if status != b"OK":
                raise RuntimeError("Backup server did not acknowledge completion")
    _log("backup_completed", source=str(root), host=host, port=port, files_sent=sent)
    print(f"Backup complete: {sent} files sent over validated TLS.")

def backup_server(backup_dir: str, host: str | None = None, port: int | None = None):
    if config is None:
        raise RuntimeError("config.py not found")
    dest_root = Path(backup_dir).resolve()
    dest_root.mkdir(parents=True, exist_ok=True)
    host = host or getattr(config, "BACKUP_BIND", "127.0.0.1")
    port = port or int(config.BACKUP_PORT)
    ca, _, _, server_crt, server_key = _paths()
    if not ca.is_file() or not server_crt.is_file() or not server_key.is_file():
        raise FileNotFoundError("TLS CA/server cert/key missing. See README_PERSON2.md.")
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(certfile=str(server_crt), keyfile=str(server_key))
    ctx.load_verify_locations(cafile=str(ca))
    ctx.verify_mode = ssl.CERT_REQUIRED
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port)); server.listen(1)
        print(f"TLS backup server listening on {host}:{port}; Ctrl+C to stop.")
        while True:
            raw, addr = server.accept()
            with raw:
                try:
                    with ctx.wrap_socket(raw, server_side=True) as tls:
                        if _recv_exact(tls, 5) != b"ISLB1":
                            raise ValueError("Invalid backup protocol")
                        count = struct.unpack("!I", _recv_exact(tls, 4))[0]
                        if count > 10000:
                            raise ValueError("File count exceeds safety limit")
                        received = 0
                        for _ in range(count):
                            name_len, size = struct.unpack("!HI", _recv_exact(tls, 6))
                            if name_len == 0:
                                break
                            if name_len > MAX_PATH or size > MAX_FILE:
                                raise ValueError("Invalid file metadata")
                            rel = _recv_exact(tls, name_len).decode("utf-8")
                            rel_path = Path(rel)
                            if rel_path.is_absolute() or ".." in rel_path.parts:
                                raise ValueError("Unsafe relative path")
                            out = (dest_root / rel_path).resolve()
                            if dest_root not in out.parents:
                                raise ValueError("Path escapes backup root")
                            out.parent.mkdir(parents=True, exist_ok=True)
                            remaining = size
                            with out.open("wb") as f:
                                while remaining:
                                    chunk = _recv_exact(tls, min(CHUNK, remaining))
                                    f.write(chunk); remaining -= len(chunk)
                            received += 1
                        # The client sends an end marker after the declared files.
                        _recv_exact(tls, 2)
                        tls.sendall(b"OK")
                    _log("backup_received", peer=str(addr), destination=str(dest_root), files_received=received)
                    print(f"Received {received} files from {addr}")
                except Exception as exc:
                    _log("backup_failed", peer=str(addr), error=str(exc))
                    print(f"Backup connection failed from {addr}: {exc}")

def restore(backup_dir: str, data_dir: str, baseline_path: str | None = None) -> dict:
    """Restore from the trusted backup, then compare hashes if baseline JSON is available."""
    source, target = Path(backup_dir).resolve(), Path(data_dir).resolve()
    if not source.is_dir() or not target.is_dir():
        raise FileNotFoundError("Backup directory and target dataset must both exist.")
    copied = 0
    for p in sorted(source.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(source)
        out = (target / rel).resolve()
        if target not in out.parents:
            raise ValueError("Restore path escapes dataset root")
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(p, out)
        copied += 1
    result = {"files_restored": copied, "hash_mismatches": []}
    if baseline_path:
        baseline = json.loads(Path(baseline_path).read_text(encoding="utf-8"))
        expected = baseline.get("sha256", {})
        for rel, expected_hash in expected.items():
            p = target / rel
            if not p.is_file():
                result["hash_mismatches"].append({"file": rel, "reason": "missing"})
                continue
            h = hashlib.sha256(p.read_bytes()).hexdigest()
            if h != expected_hash:
                result["hash_mismatches"].append({"file": rel, "expected": expected_hash, "actual": h})
    _log("restore_completed", target=str(target), **result)
    print(f"Restore complete: {copied} files; mismatches: {len(result['hash_mismatches'])}")
    return result

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("server"); s.add_argument("--dir", default=getattr(config, "BACKUP_DIR", "BACKUP"))
    c = sub.add_parser("client"); c.add_argument("--dir", default=getattr(config, "TEST_DATA_DIR", "MILITARY_DATA"))
    r = sub.add_parser("restore"); r.add_argument("--backup", default=getattr(config, "BACKUP_DIR", "BACKUP")); r.add_argument("--dir", default=getattr(config, "TEST_DATA_DIR", "MILITARY_DATA")); r.add_argument("--baseline", default="results/baseline_hashes.json")
    a = parser.parse_args()
    if a.cmd == "server": backup_server(a.dir)
    elif a.cmd == "client": backup_client(a.dir)
    else: restore(a.backup, a.dir, a.baseline)
