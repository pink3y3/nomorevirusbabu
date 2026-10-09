"""
analysis/evaluate.py  —  Person 3
Phase 13 — Evaluation metrics aggregation and chart generation.

Reads all JSON-lines log files produced during attack trials and computes:
  - Detection latency distribution (honeypot tripwire)
  - Containment / response latency distribution
  - Files-saved ratio (with vs. without honeypot)
  - Exfiltration bytes transferred before containment
  - Encryption throughput per media type (from simulator log)
  - Naive vs. authenticated C2 spoofing pass/fail

Outputs:
  results/evaluation_summary.json   — machine-readable aggregates
  results/evaluation_report.txt     — human-readable summary table

Usage:
    python3 analysis/evaluate.py [--log-dir /path/to/logs]
"""
from __future__ import annotations

import json
import statistics
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ── Make config importable from any working directory ──────────────────────────
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

try:
    import config
    _LOG_DIR     = Path(config.LOG_DIR)
    _RESULTS_DIR = Path(config.RESULTS_DIR)
except ImportError:
    _LOG_DIR     = _ROOT / "logs"
    _RESULTS_DIR = _ROOT / "results"


# ──────────────────────────────────────────────────────────────────────────────
# Log readers
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


# ──────────────────────────────────────────────────────────────────────────────
# Metric extractors
# ──────────────────────────────────────────────────────────────────────────────

def _honeypot_metrics(log_dir: Path) -> dict:
    records = _read_jsonlines(log_dir / "honeypot.log")
    detect_latencies = [
        r["detect_to_kill_ms"]
        for r in records
        if r.get("module") == "honeypot" and isinstance(r.get("detect_to_kill_ms"), (int, float))
    ]
    kills_ok   = sum(1 for r in records if r.get("kill_success") is True)
    kills_fail = sum(1 for r in records if r.get("kill_success") is False)

    stats: dict[str, Any] = {
        "tripwire_events": len(records),
        "kills_successful": kills_ok,
        "kills_failed": kills_fail,
    }
    if detect_latencies:
        stats["detect_to_kill_ms_median"] = statistics.median(detect_latencies)
        stats["detect_to_kill_ms_mean"]   = round(statistics.mean(detect_latencies), 3)
        stats["detect_to_kill_ms_min"]    = min(detect_latencies)
        stats["detect_to_kill_ms_max"]    = max(detect_latencies)
        if len(detect_latencies) > 1:
            stats["detect_to_kill_ms_stdev"] = round(statistics.stdev(detect_latencies), 3)
    return stats


def _containment_metrics(log_dir: Path) -> dict:
    records = _read_jsonlines(log_dir / "containment.log")
    latencies = [
        r["response_latency_ms"]
        for r in records
        if r.get("event") == "process_terminated"
        and isinstance(r.get("response_latency_ms"), (int, float))
    ]
    snapshots = [r for r in records if r.get("event") == "filesystem_snapshot"]
    stats: dict[str, Any] = {
        "successful_kills": len(latencies),
        "snapshot_count": len(snapshots),
    }
    if latencies:
        stats["response_latency_ms_median"] = statistics.median(latencies)
        stats["response_latency_ms_mean"]   = round(statistics.mean(latencies), 3)
        stats["response_latency_ms_min"]    = min(latencies)
        stats["response_latency_ms_max"]    = max(latencies)
    return stats


def _simulator_metrics(log_dir: Path) -> dict:
    records = _read_jsonlines(log_dir / "simulator.log")
    encrypted_events = [r for r in records if r.get("event") == "file_encrypted"]
    complete_events  = [r for r in records if r.get("event") == "traversal_complete"]

    ext_counts: dict[str, int] = {}
    ext_bytes : dict[str, int] = {}
    for r in encrypted_events:
        ext = Path(r.get("file", "")).suffix.lower()
        ext_counts[ext] = ext_counts.get(ext, 0) + 1
        ext_bytes[ext]  = ext_bytes.get(ext, 0) + r.get("plaintext_bytes", 0)

    total_files     = sum(r.get("files_encrypted", 0) for r in complete_events)
    elapsed_list    = [r["elapsed_s"] for r in complete_events if "elapsed_s" in r]

    stats: dict[str, Any] = {
        "total_files_encrypted": total_files,
        "traversal_runs": len(complete_events),
        "files_by_extension": ext_counts,
        "bytes_by_extension": ext_bytes,
    }
    if elapsed_list:
        stats["elapsed_s_mean"] = round(statistics.mean(elapsed_list), 4)
    return stats


def _transfer_metrics(log_dir: Path) -> dict:
    records = _read_jsonlines(log_dir / "transfer.log")
    sent     = [r for r in records if r.get("event") == "file_sent"]
    received = [r for r in records if r.get("event") == "file_received"]
    throughputs = [
        r["throughput_mbps"]
        for r in records
        if isinstance(r.get("throughput_mbps"), (int, float))
    ]
    total_bytes = sum(r.get("ciphertext_bytes", 0) for r in sent)
    stats: dict[str, Any] = {
        "files_sent": len(sent),
        "files_received": len(received),
        "total_exfil_bytes": total_bytes,
    }
    if throughputs:
        stats["throughput_mbps_mean"]   = round(statistics.mean(throughputs), 3)
        stats["throughput_mbps_median"] = statistics.median(throughputs)
    return stats


def _c2_spoof_metrics(results_dir: Path) -> dict:
    """Check the spoof demo output for pass/fail evidence."""
    path = results_dir / "spoof_demo_output.txt"
    if not path.is_file():
        return {"spoof_demo_output_found": False}
    content = path.read_text(encoding="utf-8")
    naive_accepted = "NAIVE variant CONFIRMED" in content or "NAIVE variant: unsigned command was ACCEPTED" in content
    hmac_rejected  = "HMAC variant CONFIRMED"  in content or "HMAC variant: unsigned command was REJECTED" in content
    return {
        "spoof_demo_output_found": True,
        "naive_variant_accepted_unsigned_command": naive_accepted,
        "hmac_variant_rejected_unsigned_command": hmac_rejected,
        "spoofing_demo_passed": naive_accepted and hmac_rejected,
    }


def _backup_metrics(log_dir: Path) -> dict:
    records = _read_jsonlines(log_dir / "backup.log")
    backups  = [r for r in records if r.get("event") == "backup_completed"]
    restores = [r for r in records if r.get("event") == "restore_completed"]
    return {
        "backup_runs": len(backups),
        "restore_runs": len(restores),
        "last_restore": restores[-1] if restores else None,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Report formatter
# ──────────────────────────────────────────────────────────────────────────────

def _fmt_line(key: str, value: Any, width: int = 40) -> str:
    return f"  {key:<{width}} {value}"


def _build_text_report(summary: dict) -> str:
    lines = [
        "=" * 65,
        "  IS Lab Kill-Chain Simulation — Evaluation Summary",
        f"  Generated : {summary['generated_at_utc']}",
        "=" * 65,
        "",
        "── Honeypot / Tripwire ─────────────────────────────────────",
    ]
    h = summary.get("honeypot", {})
    for k, v in h.items():
        lines.append(_fmt_line(k, v))

    lines += ["", "── Containment ─────────────────────────────────────────────"]
    for k, v in summary.get("containment", {}).items():
        lines.append(_fmt_line(k, v))

    lines += ["", "── Ransomware Simulator ────────────────────────────────────"]
    for k, v in summary.get("simulator", {}).items():
        if not isinstance(v, dict):
            lines.append(_fmt_line(k, v))
    for k, v in summary["simulator"].get("files_by_extension", {}).items():
        lines.append(_fmt_line(f"  files {k}", v))

    lines += ["", "── Exfiltration Transfer ───────────────────────────────────"]
    for k, v in summary.get("transfer", {}).items():
        lines.append(_fmt_line(k, v))

    lines += ["", "── C2 Spoofing Demo (FR-8.3) ───────────────────────────────"]
    for k, v in summary.get("spoof", {}).items():
        lines.append(_fmt_line(k, v))

    lines += ["", "── Backup / Restore ────────────────────────────────────────"]
    for k, v in summary.get("backup", {}).items():
        if not isinstance(v, dict):
            lines.append(_fmt_line(k, v))

    lines += ["", "=" * 65]
    return "\n".join(lines)


# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────────

def run_evaluation(log_dir: Path | None = None, results_dir: Path | None = None) -> dict:
    log_dir     = log_dir     or _LOG_DIR
    results_dir = results_dir or _RESULTS_DIR
    results_dir.mkdir(parents=True, exist_ok=True)

    summary = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "log_dir": str(log_dir),
        "honeypot":    _honeypot_metrics(log_dir),
        "containment": _containment_metrics(log_dir),
        "simulator":   _simulator_metrics(log_dir),
        "transfer":    _transfer_metrics(log_dir),
        "spoof":       _c2_spoof_metrics(results_dir),
        "backup":      _backup_metrics(log_dir),
    }

    out_json = results_dir / "evaluation_summary.json"
    out_txt  = results_dir / "evaluation_report.txt"
    out_json.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    report   = _build_text_report(summary)
    out_txt.write_text(report, encoding="utf-8")

    print(report)
    print(f"\n[evaluate] JSON  → {out_json}")
    print(f"[evaluate] Report → {out_txt}")
    return summary


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="IS Lab Evaluation Metrics Aggregator")
    parser.add_argument("--log-dir",     default=str(_LOG_DIR),     help="Log directory path")
    parser.add_argument("--results-dir", default=str(_RESULTS_DIR), help="Results output directory")
    args = parser.parse_args()
    run_evaluation(Path(args.log_dir), Path(args.results_dir))
