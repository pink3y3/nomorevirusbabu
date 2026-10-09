import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scapy.all import Ether, IP, TCP, UDP, wrpcap

from analysis.pcap_parser import analyze_pcap


class TestPcapAnalyzer(unittest.TestCase):
    def test_protocol_counts_and_connections(self):
        with TemporaryDirectory() as temp_dir:
            capture = Path(temp_dir) / "test.pcap"

            packets = [
                Ether() / IP(src="192.168.56.10", dst="192.168.56.20")
                / TCP(sport=45000, dport=80),
                Ether() / IP(src="192.168.56.20", dst="192.168.56.10")
                / TCP(sport=80, dport=45000),
                Ether() / IP(src="192.168.56.10", dst="192.168.56.20")
                / UDP(sport=53000, dport=53),
            ]
            wrpcap(str(capture), packets)

            result = analyze_pcap(capture)

            self.assertEqual(result["total_packets"], 3)
            self.assertEqual(result["protocol_counts"]["TCP"], 2)
            self.assertEqual(result["protocol_counts"]["UDP"], 1)
            self.assertEqual(len(result["connections"]), 3)

    def test_missing_capture_raises_error(self):
        with self.assertRaises(FileNotFoundError):
            analyze_pcap("this_capture_does_not_exist.pcap")


if __name__ == "__main__":
    unittest.main()
