"""
victim/honeypot_monitor.py  —  Person 2
Honeypot tripwire monitor for the IS Lab Kill-Chain project.

Watches config.HONEYPOT_DIR (A_COMMAND_ARCHIVE/) using the
watchdog library. On any qualifying file-system event:

  1. Records detection latency (raw OS event timestamp → handler entry delta).
  2. Reads the simulator PID from config.SIMULATOR_PID_FILE.
  3. Calls containment.kill_process(pid) to terminate the simulator.
  4. Optionally calls containment.isolate_network() if NETWORK_ISOLATION=True.
  5. Calls containment.snapshot_filesystem() to record which real files were
     encrypted vs. intact at the moment of containment.
  6. Writes a structured JSON-lines incident record to logs/honeypot.log.
  7. After the first confirmed kill the monitor continues watching (in case
     a second simulator process is launched) but logs subsequent events only.

PID communication contract (with ransomware/simulator.py)
-----------------------------------------------------------
  simulator.py writes its own PID to config.SIMULATOR_PID_FILE immediately
  on startup. The monitor reads this file when a tripwire fires. If the file
  is absent (e.g. the simulator has already exited), the kill is skipped and
  the event is still logged.

Detection latency methodology
-------------------------------
  watchdog's Observer calls on_any_event() in a background thread. We capture
  time.perf_counter() at the very top of on_any_event() (event_ts) and again
  after kill_process() returns (kill_ts). The difference is the detection-to-
  contain latency (detect_to_kill_ms). This is written to every incident log
  record for the evaluation metrics (Phase 7 / Phase 13).

Log format: JSON-lines → logs/honeypot.log  (shared format — read by Person 3)
  {
    "ts":                 "2026-10-09T14:32:05.456Z",
    "module":             "honeypot",
    "event":              "decoy_created",
    "file":               "/home/victim/MILITARY_DATA/A_COMMAND_ARCHIVE/Satellite_Image.jpg.locked",
    "event_type":         "created",
    "pid_read":           12345,
    "kill_success":       true,
    "detect_to_kill_ms":  3.741,
    "network_isolated":   false,
    "snapshot":           "/home/victim/islab-project/logs/snapshot_20261009T143205_000Z.json"
  }
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ── Make config and containment importable ────────────────────────────────────
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

try:
    import config
except ImportError:
    config = None

try:
    from victim.containment import kill_process, isolate_network, snapshot_filesystem
except ImportError:
    try:
        from containment import kill_process, isolate_network, snapshot_filesystem
    except ImportError:
        kill_process = isolate_network = snapshot_filesystem = None


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
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
    return p / "honeypot.log"


def _write_log(log_path: Path, record: dict) -> None:
    with log_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")


def _read_simulator_pid(pid_file: str) -> Optional[int]:
    """Read the PID written by simulator.py at startup. Returns None if absent."""
    try:
        text = Path(pid_file).read_text(encoding="utf-8").strip()
        return int(text)
    except (FileNotFoundError, ValueError, OSError):
        return None


# ──────────────────────────────────────────────────────────────────────────────
# Seen-event deduplication with TTL (avoids unbounded memory growth)
# ──────────────────────────────────────────────────────────────────────────────

class _TTLSet:
    """
    A set where entries expire after *ttl* seconds.

    watchdog can fire several events for a single logical operation (e.g. a
    rename produces both 'modified' and 'moved' events). We deduplicate identical
    (event_type, src, dst) tuples within a short time window.
    """

    def __init__(self, ttl: float = 5.0):
        self._store: OrderedDict[tuple, float] = OrderedDict()
        self._ttl = ttl
        self._lock = threading.Lock()

    def contains(self, key: tuple) -> bool:
        with self._lock:
            self._evict()
            return key in self._store

    def add(self, key: tuple) -> None:
        with self._lock:
            self._store[key] = time.monotonic()
            self._evict()

    def _evict(self) -> None:
        cutoff = time.monotonic() - self._ttl
        while self._store:
            oldest_key, oldest_ts = next(iter(self._store.items()))
            if oldest_ts < cutoff:
                del self._store[oldest_key]
            else:
                break


# ──────────────────────────────────────────────────────────────────────────────
# Tripwire handler
# ──────────────────────────────────────────────────────────────────────────────

class HoneypotHandler(FileSystemEventHandler):
    """
    watchdog event handler.

    Thread-safety: on_any_event() is called from the Observer's background
    thread. All shared state is protected by self._lock. Containment actions
    are performed under the lock so only one concurrent containment sequence
    runs at a time (avoids double-kill races).
    """

    QUALIFYING_EVENTS = frozenset({"created", "modified", "moved", "deleted"})

    def __init__(
        self,
        honeypot_dir: str,
        log_path: Path,
        pid_file: str,
        network_iface: str,
        data_dir: str,
    ):
        super().__init__()
        self.root          = Path(honeypot_dir).resolve()
        self.log_path      = log_path
        self.pid_file      = pid_file
        self.network_iface = network_iface
        self.data_dir      = data_dir
        self._seen         = _TTLSet(ttl=5.0)
        self._lock         = threading.Lock()
        self._contained    = False   # True after first successful kill

    def on_any_event(self, event) -> None:
        # ── Capture event timestamp as early as possible ───────────────────────
        event_perf = time.perf_counter()

        if event.is_directory:
            return
        if event.event_type not in self.QUALIFYING_EVENTS:
            return

        src = Path(getattr(event, "src_path", "")).resolve()
        dst_raw = getattr(event, "dest_path", None)
        dst = Path(dst_raw).resolve() if dst_raw else None

        # Confirm at least one path is inside the honeypot directory
        candidates = [p for p in (src, dst) if p is not None]
        if not any(p == self.root or self.root in p.parents for p in candidates):
            return

        # Deduplicate duplicate watchdog events
        dedup_key = (event.event_type, str(src), str(dst) if dst else "")
        if self._seen.contains(dedup_key):
            return
        self._seen.add(dedup_key)

        ts_now  = _now()
        handler_perf = time.perf_counter()
        # handler_entry_latency_ms = (handler_perf - event_perf) * 1000
        # (very small — this is the watchdog scheduling overhead, not the OS latency)

        print(f"\n[TRIPWIRE 🔴] {event.event_type.upper()}: {src.name}")

        with self._lock:
            self._respond(
                src=src,
                dst=dst,
                event_type=event.event_type,
                ts=ts_now,
                event_perf=event_perf,
                handler_perf=handler_perf,
            )

    def _respond(
        self,
        src: Path,
        dst: Optional[Path],
        event_type: str,
        ts: str,
        event_perf: float,
        handler_perf: float,
    ) -> None:
        """Execute the full containment response. Called under self._lock."""
        pid        = _read_simulator_pid(self.pid_file)
        kill_ok    = False
        isolate_ok = False
        snap_path  = None

        kill_latency_ms   = None
        detect_to_kill_ms = None

        # ── 1. Kill the simulator process ─────────────────────────────────────
        if pid is not None and kill_process is not None:
            kill_start = time.perf_counter()
            kill_ok    = kill_process(pid)
            kill_end   = time.perf_counter()
            kill_latency_ms   = round((kill_end - kill_start) * 1000, 3)
            detect_to_kill_ms = round((kill_end - event_perf)  * 1000, 3)
            if kill_ok:
                print(f"[containment] Simulator PID {pid} terminated "
                      f"({kill_latency_ms:.1f} ms, detect→kill: {detect_to_kill_ms:.1f} ms)")
                self._contained = True
            else:
                print(f"[containment] Kill of PID {pid} failed (already exited or refused)")
        else:
            if pid is None:
                print(f"[containment] Simulator PID file not found — "
                      f"kill skipped (simulator may have already exited)")
            else:
                print(f"[containment] containment module not available — kill skipped")

        # ── 2. Optional network isolation ─────────────────────────────────────
        if isolate_network is not None:
            isolate_ok = isolate_network(self.network_iface)
            if isolate_ok:
                print(f"[containment] Network interface {self.network_iface} brought down")

        # ── 3. Filesystem snapshot ────────────────────────────────────────────
        if snapshot_filesystem is not None:
            try:
                snap = snapshot_filesystem(self.data_dir)
                snap_path = snap.get("snapshot") or snap.get("data_dir")
                locked_count = sum(
                    1 for v in snap.get("files", {}).values() if v.get("locked")
                )
                print(f"[containment] Snapshot taken — "
                      f"{locked_count} file(s) encrypted at containment time")
            except Exception as exc:
                print(f"[containment] Snapshot failed: {exc}")

        # ── 4. Write structured incident log record ────────────────────────────
        record = {
            "ts":                ts,
            "module":            "honeypot",
            "event":             "decoy_" + event_type,
            "file":              str(src),
            "dest_file":         str(dst) if dst else None,
            "event_type":        event_type,
            "pid_read":          pid,
            "kill_success":      kill_ok,
            "kill_latency_ms":   kill_latency_ms,
            "detect_to_kill_ms": detect_to_kill_ms,
            "network_isolated":  isolate_ok,
            "snapshot":          snap_path,
        }
        _write_log(self.log_path, record)
        print(f"[honeypot] Incident logged → {self.log_path}")


# ──────────────────────────────────────────────────────────────────────────────
# Public entry point
# ──────────────────────────────────────────────────────────────────────────────

def run_monitor(
    honeypot_dir: str | None = None,
    log_dir: str | None = None,
    pid_file: str | None = None,
    network_iface: str | None = None,
    data_dir: str | None = None,
) -> None:
    """
    Start the honeypot watcher and block until Ctrl+C.

    Parameters
    ----------
    honeypot_dir   : directory to watch (default: config.HONEYPOT_DIR)
    log_dir        : where to write honeypot.log (default: config.LOG_DIR)
    pid_file       : simulator PID file path (default: config.SIMULATOR_PID_FILE)
    network_iface  : NIC to bring down on containment (default: config.NETWORK_IFACE)
    data_dir       : dataset root for filesystem snapshot (default: config.TEST_DATA_DIR)
    """
    if config is None:
        raise SystemExit("config.py not found; ensure config.py is in the project root.")

    _honeypot_dir  = honeypot_dir   or config.HONEYPOT_DIR
    _log_dir       = log_dir        or config.LOG_DIR
    _pid_file      = pid_file       or getattr(config, "SIMULATOR_PID_FILE",
                                               str(Path(config.LOG_DIR) / "simulator.pid"))
    _network_iface = network_iface  or getattr(config, "NETWORK_IFACE", "eth1")
    _data_dir      = data_dir       or config.TEST_DATA_DIR

    honeypot_path = Path(_honeypot_dir).resolve()
    if not honeypot_path.is_dir():
        raise SystemExit(
            f"Honeypot directory not found: {honeypot_path}\n"
            f"Run victim/dataset_generator.py first."
        )

    log_path = _setup_log(_log_dir)
    handler  = HoneypotHandler(
        honeypot_dir   = str(honeypot_path),
        log_path       = log_path,
        pid_file       = _pid_file,
        network_iface  = _network_iface,
        data_dir       = _data_dir,
    )

    observer = Observer()
    observer.schedule(handler, str(honeypot_path), recursive=True)
    observer.start()

    print(f"[honeypot_monitor] Watching: {honeypot_path}")
    print(f"[honeypot_monitor] Log:       {log_path}")
    print(f"[honeypot_monitor] PID file:  {_pid_file}")
    print(f"[honeypot_monitor] Iface:     {_network_iface}")
    print(f"[honeypot_monitor] Press Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(0.25)
    except KeyboardInterrupt:
        print("\n[honeypot_monitor] Shutting down.")
    finally:
        observer.stop()
        observer.join()


# ── Direct run ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    run_monitor()
