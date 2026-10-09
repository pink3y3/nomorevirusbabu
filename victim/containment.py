"""Defensive containment helpers for the isolated IS lab."""
from __future__ import annotations
import hashlib, json, os, platform, signal, subprocess, time
from datetime import datetime, timezone
from pathlib import Path

try:
    import config
except ImportError:
    config = None

def _now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

def _log(event, **fields):
    log_dir = Path(getattr(config, "LOG_DIR", "logs") if config else "logs")
    log_dir.mkdir(parents=True, exist_ok=True)
    record = {"ts": _now(), "module": "containment", "event": event, **fields}
    with (log_dir / "containment.log").open("a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")

def kill_process(pid: int) -> bool:
    """Terminate only a verified project simulator process; never kill arbitrary PIDs."""
    import psutil
    try:
        proc = psutil.Process(int(pid))
        cmdline = " ".join(proc.cmdline()).lower()
        name = proc.name().lower()
        # Safety guard: only target an explicitly named simulator process.
        if "simulator.py" not in cmdline and "ransomware-simulator" not in name:
            _log("kill_refused", pid=int(pid), reason="PID is not identified as the lab simulator")
            return False
        started = time.perf_counter()
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except psutil.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)
        elapsed_ms = round((time.perf_counter() - started) * 1000, 3)
        ok = not proc.is_running()
        _log("process_terminated" if ok else "process_termination_failed",
             pid=int(pid), response_latency_ms=elapsed_ms)
        return ok
    except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError) as exc:
        _log("process_termination_error", pid=int(pid), error=str(exc))
        return False

def isolate_network(iface: str) -> bool:
    """Optional disruptive action. Disabled unless config.NETWORK_ISOLATION is explicitly True."""
    enabled = bool(getattr(config, "NETWORK_ISOLATION", False)) if config else False
    if not enabled:
        _log("network_isolation_skipped", interface=iface, reason="disabled in config")
        return False
    if not iface or iface.startswith("-") or not all(c.isalnum() or c in "_.-" for c in iface):
        _log("network_isolation_refused", interface=iface, reason="invalid interface name")
        return False
    if platform.system() != "Linux":
        _log("network_isolation_unsupported", interface=iface, platform=platform.system())
        return False
    try:
        result = subprocess.run(["ip", "link", "set", iface, "down"],
                                capture_output=True, text=True, timeout=5, check=False)
        ok = result.returncode == 0
        _log("network_isolated" if ok else "network_isolation_failed",
             interface=iface, returncode=result.returncode, stderr=result.stderr[-500:])
        return ok
    except (OSError, subprocess.TimeoutExpired) as exc:
        _log("network_isolation_error", interface=iface, error=str(exc))
        return False

def snapshot_filesystem(data_dir: str) -> dict:
    """Record file size, SHA-256, and .locked status under the configured dataset only."""
    root = Path(data_dir).resolve()
    allowed = Path(getattr(config, "TEST_DATA_DIR", root) if config else root).resolve()
    # Permit a root explicitly passed by tests, but refuse obvious broad roots.
    if root == Path("/") or root == Path.home().resolve():
        raise ValueError(f"Refusing to snapshot overly broad path: {root}")
    root.mkdir(parents=True, exist_ok=True)
    entries = {}
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        h = hashlib.sha256()
        with p.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        rel = str(p.relative_to(root))
        entries[rel] = {"size": p.stat().st_size, "sha256": h.hexdigest(),
                        "locked": p.name.endswith(".locked")}
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ")
    log_dir = Path(getattr(config, "LOG_DIR", "logs") if config else "logs")
    log_dir.mkdir(parents=True, exist_ok=True)
    output = log_dir / f"snapshot_{stamp}.json"
    payload = {"ts": _now(), "data_dir": str(root), "files": entries}
    output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    _log("filesystem_snapshot", data_dir=str(root), snapshot=str(output), file_count=len(entries))
    return payload
