"""Watch the decoy directory and log tripwire events.

Note: watchdog events do not provide a reliable originating PID. This module logs the
event and can identify a likely process only when the platform audit source is available.
For safe integration, it terminates only a PID explicitly supplied by the simulator
through a future agreed event contract; it does not guess and kill unrelated processes.
"""
from __future__ import annotations
import json, time
from datetime import datetime, timezone
from pathlib import Path
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

try:
    import config
except ImportError:
    config = None

def _now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

class HoneypotHandler(FileSystemEventHandler):
    def __init__(self, honeypot_dir, log_path):
        self.root = Path(honeypot_dir).resolve()
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.seen = set()

    def on_any_event(self, event):
        if event.is_directory or event.event_type not in {"created", "modified", "moved", "deleted"}:
            return
        src = Path(getattr(event, "src_path", "")).resolve()
        dst_raw = getattr(event, "dest_path", None)
        dst = Path(dst_raw).resolve() if dst_raw else None
        candidates = [p for p in (src, dst) if p is not None]
        if not any(p == self.root or self.root in p.parents for p in candidates):
            return
        # Watchdog may emit duplicate modify events; deduplicate bursts per path/event.
        key = (event.event_type, str(src), str(dst) if dst else "")
        now = time.monotonic()
        if key in self.seen:
            return
        self.seen.add(key)
        record = {"ts": _now(), "module": "honeypot", "event": "decoy_" + event.event_type,
                  "pid": None, "process_name": None, "file": str(src),
                  "dest_file": str(dst) if dst else None,
                  "note": "watchdog does not expose a reliable originating PID"}
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
        print(f"[TRIPWIRE] {record['event']}: {src}")

def main():
    if config is None:
        raise SystemExit("config.py not found; run from the repository root.")
    honeypot = Path(config.HONEYPOT_DIR).resolve()
    if not honeypot.is_dir():
        raise SystemExit(f"Honeypot directory not found: {honeypot}. Run dataset_generator.py first.")
    log_dir = Path(getattr(config, "LOG_DIR", "logs"))
    handler = HoneypotHandler(honeypot, log_dir / "honeypot.log")
    observer = Observer()
    observer.schedule(handler, str(honeypot), recursive=True)
    observer.start()
    print(f"Monitoring {honeypot}. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    main()
