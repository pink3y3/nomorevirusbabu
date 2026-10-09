"""
analysis/forensic_report.py  —  Person 3
Phase 10 — Forensic incident report and IOC extraction.

Reads all JSON-lines logs produced during a trial and assembles:
  1. A timestamped attack timeline
  2. IOCs in four categories: network, filesystem, process, cryptographic
  3. A detection-method comparison table (honeypot vs. traffic analysis)

Outputs:
  results/forensic_report.txt          — human-readable incident report
  results/forensic_report.json         — machine-readable IOC/timeline export

Usage:
    python3 analysis/forensic_report.py [--log-dir /path/to/logs]
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

try:
    import config
    _LOG_DIR     = Path(config.LOG_DIR)
    _RESULTS_DIR = Path(config.RESULTS_DIR)
    _ATTACKER_IP = getattr(config, "ATTACKER_IP", "192.168.56.10")
    _C2_PORT     = getattr(config, "C2_PORT", 9001)
    _XFER_PORT   = getattr(config, "TRANSFER_PORT", 9002)
    _ENC_EXT     = getattr(config, "ENCRYPTED_EXT", ".locked")
    _KEY_EXT     = getattr(config, "KEY_EXT", ".key")
    _RANSOM_NOTE = getattr(config, "RANSOM_NOTE", "README_DECRYPT.txt")
except ImportError:
    _LOG_DIR     = _ROOT / "logs"
    _RESULTS_DIR = _ROOT / "results"
    _ATTACKER_IP = "192.168.56.10"
    _C2_PORT     = 9001
    _XFER_PORT   = 9002
    _ENC_EXT     = ".locked"
    _KEY_EXT     = ".key"
    _RANSOM_NOTE = "README_DECRYPT.txt"


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _read_jsonlines(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return records


def _ts(record: dict) -> str:
    return record.get("ts", "?")


def _h(title: str, width: int = 65) -> str:
    return f"\n{'─' * width}\n  {title}\n{'─' * width}"


# ──────────────────────────────────────────────────────────────────────────────
# Timeline builder
# ──────────────────────────────────────────────────────────────────────────────

def _build_timeline(log_dir: Path) -> list[dict]:
    """Merge all log events into a single chronological timeline."""
    events: list[dict] = []

    for log_file, label in [
        ("c2.log",          "c2"),
        ("transfer.log",    "transfer"),
        ("simulator.log",   "simulator"),
        ("honeypot.log",    "honeypot"),
        ("containment.log", "containment"),
        ("backup.log",      "backup"),
    ]:
        for r in _read_jsonlines(log_dir / log_file):
            events.append({
                "ts":     _ts(r),
                "source": label,
                "event":  r.get("event", "?"),
                "detail": {k: v for k, v in r.items()
                           if k not in ("ts", "module", "event")},
            })

    events.sort(key=lambda e: e["ts"])
    return events


# ──────────────────────────────────────────────────────────────────────────────
# IOC extractor
# ──────────────────────────────────────────────────────────────────────────────

def _extract_iocs(log_dir: Path, results_dir: Path) -> dict:
    iocs: dict[str, Any] = {
        "network": [],
        "filesystem": [],
        "process": [],
        "cryptographic": [],
    }

    # ── Network IOCs ────────────────────────────────────────────────────────
    iocs["network"].append({
        "type": "attacker_ip",
        "value": _ATTACKER_IP,
        "ports": {"c2": _C2_PORT, "exfil": _XFER_PORT},
        "note": "Host-only network; no internet exposure in this simulation",
    })
    for r in _read_jsonlines(log_dir / "transfer.log"):
        if r.get("event") == "file_sent":
            iocs["network"].append({
                "type": "exfiltration_event",
                "ts": _ts(r),
                "file": r.get("file"),
                "bytes": r.get("ciphertext_bytes"),
                "throughput_mbps": r.get("throughput_mbps"),
            })

    # ── Filesystem IOCs ─────────────────────────────────────────────────────
    iocs["filesystem"].append({
        "type": "encrypted_extension",
        "value": _ENC_EXT,
    })
    iocs["filesystem"].append({
        "type": "key_sidecar_extension",
        "value": _KEY_EXT,
        "note": "16-byte IV || 256-byte RSA-wrapped AES key",
    })
    iocs["filesystem"].append({
        "type": "ransom_note_filename",
        "value": _RANSOM_NOTE,
    })
    for r in _read_jsonlines(log_dir / "simulator.log"):
        if r.get("event") == "shadow_copy_deletion_logged":
            iocs["filesystem"].append({
                "type": "shadow_copy_command_logged",
                "command": r.get("command"),
                "ts": _ts(r),
                "note": "NOT executed — logged for forensic evidence only",
            })

    # ── Process IOCs ─────────────────────────────────────────────────────────
    for r in _read_jsonlines(log_dir / "containment.log"):
        if r.get("event") in ("process_terminated", "process_termination_failed",
                               "kill_refused", "process_termination_error"):
            iocs["process"].append({
                "type": "simulator_process",
                "event": r.get("event"),
                "pid": r.get("pid"),
                "response_latency_ms": r.get("response_latency_ms"),
                "ts": _ts(r),
            })
    for r in _read_jsonlines(log_dir / "honeypot.log"):
        if r.get("pid_read") is not None:
            iocs["process"].append({
                "type": "pid_read_from_tripwire",
                "pid": r.get("pid_read"),
                "kill_success": r.get("kill_success"),
                "ts": _ts(r),
            })

    # ── Cryptographic IOCs ───────────────────────────────────────────────────
    pub_key_path = _ROOT / "keys" / "public.pem"
    if pub_key_path.is_file():
        import hashlib
        fingerprint = hashlib.sha256(pub_key_path.read_bytes()).hexdigest()[:16]
        iocs["cryptographic"].append({
            "type": "rsa_public_key_fingerprint_sha256_prefix",
            "value": fingerprint,
            "path": str(pub_key_path),
            "note": "RSA-2048-OAEP; private key is attacker-side only",
        })
    for r in _read_jsonlines(log_dir / "c2.log"):
        if r.get("event") == "push_key_received":
            iocs["cryptographic"].append({
                "type": "push_key_event",
                "ts": _ts(r),
                "key_path": r.get("key_path"),
            })

    return iocs


# ──────────────────────────────────────────────────────────────────────────────
# Detection comparison table
# ──────────────────────────────────────────────────────────────────────────────

def _detection_comparison(iocs: dict, timeline: list[dict]) -> list[dict]:
    # Pull honeypot latency from IOC/timeline data
    honeypot_latencies = []
    for e in timeline:
        if e["source"] == "honeypot":
            lat = e["detail"].get("detect_to_kill_ms")
            if isinstance(lat, (int, float)):
                honeypot_latencies.append(lat)

    hp_lat_str = (
        f"{min(honeypot_latencies):.1f}–{max(honeypot_latencies):.1f} ms"
        if honeypot_latencies else "N/A (no events in logs)"
    )

    table = [
        {
            "method": "Honeypot Tripwire (A_COMMAND_ARCHIVE/)",
            "latency": hp_lat_str,
            "false_positive_rate": "Very low (only fires on honeypot directory access)",
            "catches": "Ransomware traversal order; any file-system event in decoy dir",
            "misses": "Ransomware that skips or is aware of the honeypot dir",
            "response_action": "Automatic SIGKILL of simulator + optional NIC isolation",
        },
        {
            "method": "Traffic Analysis (PCAP / exfiltration heuristic)",
            "latency": "Seconds–minutes (post-capture analysis)",
            "false_positive_rate": "Medium (large encrypted transfers may legitimately occur)",
            "catches": "Data exfiltration before encryption; C2 channel IPs/ports",
            "misses": "Local-only encryption with no exfiltration",
            "response_action": "Manual investigation; no automatic containment in this simulation",
        },
    ]
    return table


# ──────────────────────────────────────────────────────────────────────────────
# Report formatter
# ──────────────────────────────────────────────────────────────────────────────

def _format_report(
    timeline: list[dict],
    iocs: dict,
    detection_table: list[dict],
    generated_at: str,
) -> str:
    lines = [
        "=" * 65,
        "  IS Lab Ransomware Kill-Chain — Forensic Incident Report",
        f"  Generated : {generated_at}",
        "=" * 65,
    ]

    # Timeline
    lines.append(_h("1. Attack Timeline"))
    if timeline:
        for e in timeline:
            lines.append(f"  {e['ts']}  [{e['source']:12s}]  {e['event']}")
            for k, v in e.get("detail", {}).items():
                if v is not None:
                    lines.append(f"      {k}: {v}")
    else:
        lines.append("  No log events found — run a trial first.")

    # IOCs
    lines.append(_h("2. Indicators of Compromise (IOCs)"))

    for category, items in iocs.items():
        lines.append(f"\n  [{category.upper()}]")
        for item in items:
            for k, v in item.items():
                lines.append(f"    {k}: {v}")
            lines.append("")

    # Detection comparison
    lines.append(_h("3. Detection Method Comparison"))
    col_w = 30
    for entry in detection_table:
        lines.append(f"\n  Method: {entry['method']}")
        for k, v in entry.items():
            if k != "method":
                lines.append(f"    {k:<24}: {v}")

    lines += ["", "=" * 65, "  END OF REPORT", "=" * 65]
    return "\n".join(lines)


# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────────

def run_forensic_report(log_dir: Path | None = None, results_dir: Path | None = None) -> dict:
    log_dir     = log_dir     or _LOG_DIR
    results_dir = results_dir or _RESULTS_DIR
    results_dir.mkdir(parents=True, exist_ok=True)

    generated_at = (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )

    timeline        = _build_timeline(log_dir)
    iocs            = _extract_iocs(log_dir, results_dir)
    detection_table = _detection_comparison(iocs, timeline)

    report_text = _format_report(timeline, iocs, detection_table, generated_at)

    payload = {
        "generated_at_utc": generated_at,
        "log_dir": str(log_dir),
        "timeline": timeline,
        "iocs": iocs,
        "detection_comparison": detection_table,
    }

    out_json = results_dir / "forensic_report.json"
    out_txt  = results_dir / "forensic_report.txt"
    out_json.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    out_txt.write_text(report_text, encoding="utf-8")

    print(report_text)
    print(f"\n[forensic_report] JSON   → {out_json}")
    print(f"[forensic_report] Report → {out_txt}")
    return payload


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="IS Lab Forensic Incident Report Generator")
    parser.add_argument("--log-dir",     default=str(_LOG_DIR),     help="Directory containing JSON-lines log files")
    parser.add_argument("--results-dir", default=str(_RESULTS_DIR), help="Output directory for reports")
    args = parser.parse_args()
    run_forensic_report(Path(args.log_dir), Path(args.results_dir))
