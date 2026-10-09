"""
analysis/pcap_parser.py  —  Person 3
Phase 9 — Network capture and PCAP analysis.

Parses a captured PCAP file (from tcpdump or Wireshark) and:
  1. Extracts flows: src_ip, dst_ip, src_port, dst_port, protocol,
     packet_count, total_bytes, start_time, end_time.
  2. Loads the flow data into a local SQLite database (results/capture.db).
  3. Runs a built-in exfiltration heuristic that flags large encrypted
     outbound bursts to the attacker IP as anomalous.
  4. Saves the flagged flows to results/anomalous_flows.json.

Dependencies:
    pip install pyshark   (Wireshark must be installed for pyshark)
    OR
    pip install scapy     (pure-Python alternative, no Wireshark required)

Usage:
    python3 analysis/pcap_parser.py --pcap capture.pcap [--db results/capture.db]

Without a real PCAP (e.g. to test the pipeline structure):
    python3 analysis/pcap_parser.py --dummy
"""
from __future__ import annotations

import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

try:
    import config
    _ATTACKER_IP = getattr(config, "ATTACKER_IP", "192.168.56.10")
    _XFER_PORT   = int(getattr(config, "TRANSFER_PORT", 9002))
    _C2_PORT     = int(getattr(config, "C2_PORT", 9001))
    _RESULTS_DIR = Path(config.RESULTS_DIR)
except ImportError:
    _ATTACKER_IP = "192.168.56.10"
    _XFER_PORT   = 9002
    _C2_PORT     = 9001
    _RESULTS_DIR = _ROOT / "results"

# Minimum bytes in a flow to be considered a candidate exfiltration burst.
EXFIL_BYTE_THRESHOLD = 50_000   # 50 KB


# ──────────────────────────────────────────────────────────────────────────────
# Database helpers
# ──────────────────────────────────────────────────────────────────────────────

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS flows (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    src_ip       TEXT,
    dst_ip       TEXT,
    src_port     INTEGER,
    dst_port     INTEGER,
    protocol     TEXT,
    packet_count INTEGER,
    total_bytes  INTEGER,
    start_time   TEXT,
    end_time     TEXT,
    flagged      INTEGER DEFAULT 0
);
"""


def _open_db(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.execute(_CREATE_TABLE)
    conn.commit()
    return conn


def _insert_flows(conn: sqlite3.Connection, flows: list[dict]) -> None:
    conn.executemany(
        """INSERT INTO flows
           (src_ip, dst_ip, src_port, dst_port, protocol, packet_count,
            total_bytes, start_time, end_time, flagged)
           VALUES (:src_ip, :dst_ip, :src_port, :dst_port, :protocol,
                   :packet_count, :total_bytes, :start_time, :end_time, :flagged)""",
        flows,
    )
    conn.commit()


# ──────────────────────────────────────────────────────────────────────────────
# Exfiltration heuristic
# ──────────────────────────────────────────────────────────────────────────────

def _is_exfil(flow: dict) -> bool:
    """
    Flag a flow as a suspected exfiltration event if it matches ALL of:
      - destination is config.ATTACKER_IP
      - destination port is config.TRANSFER_PORT
      - total payload bytes exceed EXFIL_BYTE_THRESHOLD
    """
    return (
        flow.get("dst_ip") == _ATTACKER_IP
        and flow.get("dst_port") == _XFER_PORT
        and int(flow.get("total_bytes", 0)) >= EXFIL_BYTE_THRESHOLD
    )


# ──────────────────────────────────────────────────────────────────────────────
# PyShark parser
# ──────────────────────────────────────────────────────────────────────────────

def _parse_with_pyshark(pcap_path: Path) -> list[dict]:
    """Parse a PCAP using PyShark and aggregate into per-connection flows."""
    try:
        import pyshark
    except ImportError:
        raise RuntimeError("pyshark not installed. Run: pip install pyshark")

    cap = pyshark.FileCapture(str(pcap_path), display_filter="tcp or udp")

    flow_map: dict[tuple, dict] = {}
    for pkt in cap:
        try:
            proto = "TCP" if hasattr(pkt, "tcp") else ("UDP" if hasattr(pkt, "udp") else "OTHER")
            src_ip   = str(pkt.ip.src)   if hasattr(pkt, "ip") else "?"
            dst_ip   = str(pkt.ip.dst)   if hasattr(pkt, "ip") else "?"
            src_port = int(pkt[proto.lower()].srcport) if proto in ("TCP", "UDP") else 0
            dst_port = int(pkt[proto.lower()].dstport) if proto in ("TCP", "UDP") else 0
            length   = int(pkt.length) if hasattr(pkt, "length") else 0
            ts_str   = str(pkt.sniff_time.isoformat())

            key = (src_ip, dst_ip, src_port, dst_port, proto)
            if key not in flow_map:
                flow_map[key] = {
                    "src_ip": src_ip, "dst_ip": dst_ip,
                    "src_port": src_port, "dst_port": dst_port,
                    "protocol": proto,
                    "packet_count": 0, "total_bytes": 0,
                    "start_time": ts_str, "end_time": ts_str,
                }
            f = flow_map[key]
            f["packet_count"] += 1
            f["total_bytes"]  += length
            f["end_time"]      = ts_str
        except Exception:
            continue

    cap.close()
    flows = list(flow_map.values())
    for f in flows:
        f["flagged"] = 1 if _is_exfil(f) else 0
    return flows


# ──────────────────────────────────────────────────────────────────────────────
# Scapy fallback parser
# ──────────────────────────────────────────────────────────────────────────────

def _parse_with_scapy(pcap_path: Path) -> list[dict]:
    """Parse a PCAP using Scapy — no Wireshark dependency."""
    try:
        from scapy.all import rdpcap, IP, TCP, UDP
    except ImportError:
        raise RuntimeError("scapy not installed. Run: pip install scapy")

    packets = rdpcap(str(pcap_path))
    flow_map: dict[tuple, dict] = {}

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto  = "TCP" if pkt.haslayer(TCP) else ("UDP" if pkt.haslayer(UDP) else "OTHER")
        src_port = int(pkt[TCP].sport) if pkt.haslayer(TCP) else (int(pkt[UDP].sport) if pkt.haslayer(UDP) else 0)
        dst_port = int(pkt[TCP].dport) if pkt.haslayer(TCP) else (int(pkt[UDP].dport) if pkt.haslayer(UDP) else 0)
        length   = len(pkt)
        ts_str   = datetime.fromtimestamp(float(pkt.time), tz=timezone.utc).isoformat()

        key = (src_ip, dst_ip, src_port, dst_port, proto)
        if key not in flow_map:
            flow_map[key] = {
                "src_ip": src_ip, "dst_ip": dst_ip,
                "src_port": src_port, "dst_port": dst_port,
                "protocol": proto,
                "packet_count": 0, "total_bytes": 0,
                "start_time": ts_str, "end_time": ts_str,
            }
        f = flow_map[key]
        f["packet_count"] += 1
        f["total_bytes"]  += length
        f["end_time"]      = ts_str

    flows = list(flow_map.values())
    for f in flows:
        f["flagged"] = 1 if _is_exfil(f) else 0
    return flows


# ──────────────────────────────────────────────────────────────────────────────
# Dummy flow generator (for pipeline testing without a real PCAP)
# ──────────────────────────────────────────────────────────────────────────────

def _dummy_flows() -> list[dict]:
    """Return synthetic flows that exercise the heuristic."""
    now = datetime.now(timezone.utc).isoformat()
    return [
        {   # Should be flagged — exfiltration burst
            "src_ip": "192.168.56.20", "dst_ip": _ATTACKER_IP,
            "src_port": 54321, "dst_port": _XFER_PORT,
            "protocol": "TCP", "packet_count": 120, "total_bytes": 4_200_000,
            "start_time": now, "end_time": now, "flagged": 0,
        },
        {   # C2 channel — small packets, not flagged by exfil heuristic
            "src_ip": "192.168.56.20", "dst_ip": _ATTACKER_IP,
            "src_port": 44444, "dst_port": _C2_PORT,
            "protocol": "TCP", "packet_count": 15, "total_bytes": 1_800,
            "start_time": now, "end_time": now, "flagged": 0,
        },
        {   # Background noise
            "src_ip": "192.168.56.20", "dst_ip": "192.168.56.10",
            "src_port": 55555, "dst_port": 80,
            "protocol": "TCP", "packet_count": 5, "total_bytes": 500,
            "start_time": now, "end_time": now, "flagged": 0,
        },
    ]


# ──────────────────────────────────────────────────────────────────────────────
# Main pipeline
# ──────────────────────────────────────────────────────────────────────────────

def run_pcap_analysis(
    pcap_path: Path | None = None,
    db_path: Path | None = None,
    results_dir: Path | None = None,
    dummy: bool = False,
) -> dict:
    results_dir = results_dir or _RESULTS_DIR
    results_dir.mkdir(parents=True, exist_ok=True)
    db_path = db_path or (results_dir / "capture.db")

    if dummy:
        print("[pcap_parser] DUMMY mode — generating synthetic flows.")
        flows = _dummy_flows()
        for f in flows:
            f["flagged"] = 1 if _is_exfil(f) else 0
    elif pcap_path is not None:
        print(f"[pcap_parser] Parsing {pcap_path} …")
        try:
            flows = _parse_with_pyshark(pcap_path)
            print(f"[pcap_parser] PyShark: {len(flows)} flows extracted.")
        except (RuntimeError, Exception) as e1:
            print(f"[pcap_parser] PyShark failed ({e1}); trying Scapy…")
            flows = _parse_with_scapy(pcap_path)
            print(f"[pcap_parser] Scapy: {len(flows)} flows extracted.")
    else:
        raise ValueError("Provide --pcap <file> or --dummy")

    conn = _open_db(db_path)
    _insert_flows(conn, flows)

    # Query flagged flows
    cursor = conn.execute("SELECT * FROM flows WHERE flagged = 1")
    cols   = [d[0] for d in cursor.description]
    anomalous = [dict(zip(cols, row)) for row in cursor.fetchall()]
    conn.close()

    out_json = results_dir / "anomalous_flows.json"
    out_json.write_text(
        json.dumps({"attacker_ip": _ATTACKER_IP, "exfil_port": _XFER_PORT,
                    "threshold_bytes": EXFIL_BYTE_THRESHOLD, "anomalous_flows": anomalous},
                   indent=2),
        encoding="utf-8",
    )

    print(f"\n[pcap_parser] Total flows: {len(flows)}")
    print(f"[pcap_parser] Anomalous  : {len(anomalous)}")
    for af in anomalous:
        print(f"  FLAGGED: {af['src_ip']}:{af['src_port']} → "
              f"{af['dst_ip']}:{af['dst_port']}  "
              f"({af['total_bytes']:,} bytes, {af['packet_count']} pkts)")

    print(f"\n[pcap_parser] DB           → {db_path}")
    print(f"[pcap_parser] Anomalies    → {out_json}")

    return {"total_flows": len(flows), "anomalous_flows": len(anomalous),
            "db": str(db_path), "anomalies_json": str(out_json)}


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="IS Lab PCAP Parser and Exfiltration Detector")
    parser.add_argument("--pcap",    type=Path, help="Path to .pcap or .pcapng file")
    parser.add_argument("--db",      type=Path, help="SQLite DB output path (default: results/capture.db)")
    parser.add_argument("--results-dir", type=Path, default=_RESULTS_DIR, help="Results output directory")
    parser.add_argument("--dummy",   action="store_true",
                        help="Skip PCAP; generate synthetic flows to test the pipeline")
    args = parser.parse_args()

    if not args.dummy and args.pcap is None:
        parser.error("Provide --pcap <file> or --dummy")

    run_pcap_analysis(
        pcap_path   = args.pcap,
        db_path     = args.db,
        results_dir = args.results_dir,
        dummy       = args.dummy,
    )
