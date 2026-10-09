
import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from scapy.all import IP, IPv6, TCP, UDP, rdpcap


def analyze_pcap(pcap_path):
    """Extract basic packet and connection information from a capture."""
    path = Path(pcap_path)

    if not path.is_file():
        raise FileNotFoundError(f"Capture file not found: {path}")

    packets = rdpcap(str(path))

    protocol_counts = Counter()
    connections = Counter()
    packet_records = []

    for packet in packets:
        timestamp = datetime.fromtimestamp(
            float(packet.time), tz=timezone.utc
        ).isoformat()

        src_ip = None
        dst_ip = None
        src_port = None
        dst_port = None
        protocol = "OTHER"

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
        elif IPv6 in packet:
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst

        if TCP in packet:
            protocol = "TCP"
            src_port = int(packet[TCP].sport)
            dst_port = int(packet[TCP].dport)
        elif UDP in packet:
            protocol = "UDP"
            src_port = int(packet[UDP].sport)
            dst_port = int(packet[UDP].dport)
        elif IP in packet:
            protocol = str(packet[IP].proto)
        elif IPv6 in packet:
            protocol = "IPv6"

        protocol_counts[protocol] += 1

        if src_ip and dst_ip:
            connections[
                (src_ip, dst_ip, src_port, dst_port, protocol)
            ] += 1

        packet_records.append({
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "packet_length": len(packet),
        })

    return {
        "capture_file": path.name,
        "total_packets": len(packets),
        "protocol_counts": dict(protocol_counts),
        "connections": [
            {
                "src_ip": src,
                "dst_ip": dst,
                "src_port": sport,
                "dst_port": dport,
                "protocol": proto,
                "packet_count": count,
            }
            for (src, dst, sport, dport, proto), count
            in connections.most_common()
        ],
        "packets": packet_records,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Extract basic forensic metadata from a PCAP/PCAPNG file."
    )
    parser.add_argument("pcap", help="Path to the capture file")
    parser.add_argument(
        "--output",
        default="person3/outputs/pcap_analysis.json",
        help="Path for the JSON output",
    )
    args = parser.parse_args()

    try:
        result = analyze_pcap(args.pcap)
    except (OSError, ValueError, EOFError) as exc:
        parser.error(str(exc))
    except Exception as exc:
        parser.error(f"Could not read capture: {exc}")

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, indent=2), encoding="utf-8")

    print(f"Packets analyzed: {result['total_packets']}")
    print(f"Protocols: {result['protocol_counts']}")
    print(f"Results saved to: {output_path}")


if __name__ == "__main__":
    main()