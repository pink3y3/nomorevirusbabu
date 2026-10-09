"""
attacker/c2_spoof_demo.py  —  Person 1
Demonstrates FR-8.3: command injection attack against the naive and authenticated C2.

This script plays the role of an attacker-simulator or a third party that:
  1. Connects to the C2 port
  2. Injects a forged/unsigned command (e.g., a fake STOP to halt the real attack)

Expected results
----------------
  Naive variant   (AUTH_MODE = False): forged STOP is *accepted* → attack halted by spoofing.
  HMAC variant    (AUTH_MODE = True ): forged STOP is *rejected* → attack continues.

Run against the server with AUTH_MODE=False first, then AUTH_MODE=True:
    # On attacker VM (server window):
    python3 attacker/c2_server.py
    # On a third machine / second terminal:
    python3 attacker/c2_spoof_demo.py --target 192.168.56.10 --naive
    python3 attacker/c2_spoof_demo.py --target 192.168.56.10 --auth
"""

import sys
import socket
import argparse
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import config

GREEN = "\033[92m"
RED   = "\033[91m"
RESET = "\033[0m"
BOLD  = "\033[1m"


def _readline(sock: socket.socket) -> str:
    buf = b""
    sock.settimeout(5.0)
    try:
        while b"\n" not in buf:
            chunk = sock.recv(1024)
            if not chunk:
                break
            buf += chunk
    except socket.timeout:
        pass
    return buf.decode(errors="replace").strip()


def inject_command(host: str, port: int, raw_cmd: str, force_unsigned: bool) -> None:
    """
    Connect to *host*:*port* and inject *raw_cmd* without any HMAC signature.

    Parameters
    ----------
    host         : str  — C2 server IP
    port         : int  — C2 server port
    raw_cmd      : str  — command to inject (e.g. "STOP")
    force_unsigned: bool — if True always send without HMAC (the demo point)
    """
    print(f"\n{BOLD}=== C2 Command Injection Demo ==={RESET}")
    print(f"Target  : {host}:{port}")
    print(f"Command : {raw_cmd}")
    print(f"Signed  : {'No (unsigned/forged)' if force_unsigned else 'N/A'}")
    print()

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((host, port))
            banner = _readline(sock)
            print(f"Server banner : {banner}")

            # Always send unsigned — the whole point of the demo
            payload = raw_cmd.encode() + b"\n"
            sock.sendall(payload)

            response = _readline(sock)
            print(f"Server response: {response}")

            if response.startswith("ACK"):
                print(f"\n{RED}{BOLD}[RESULT] NAIVE variant: unsigned command was ACCEPTED ✓{RESET}")
                print(f"{RED}→ An attacker/third-party successfully injected '{raw_cmd}' without authentication.{RESET}")
            elif "authentication failed" in response.lower() or "ERR" in response:
                print(f"\n{GREEN}{BOLD}[RESULT] AUTHENTICATED variant: unsigned command was REJECTED ✓{RESET}")
                print(f"{GREEN}→ HMAC authentication prevented the spoofed command from executing.{RESET}")
            else:
                print(f"[RESULT] Unexpected response: {response}")

    except Exception as exc:
        print(f"{RED}Connection error: {exc}{RESET}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="C2 Command Injection Demo — FR-8.3"
    )
    parser.add_argument("--target", default=config.ATTACKER_IP,
                        help="C2 server IP (default: config.ATTACKER_IP)")
    parser.add_argument("--port",   type=int, default=config.C2_PORT,
                        help="C2 server port (default: config.C2_PORT)")
    parser.add_argument("--cmd",    default="STOP",
                        help="Command to inject (default: STOP)")
    parser.add_argument("--naive",  action="store_true",
                        help="Describe expected result for naive variant")
    parser.add_argument("--auth",   action="store_true",
                        help="Describe expected result for authenticated variant")
    args = parser.parse_args()

    print(f"\n{BOLD}FR-8.3 — C2 Spoofing Demo{RESET}")
    if args.naive:
        print("Mode: NAIVE — expect command to be ACCEPTED (server running with AUTH_MODE=False)")
    elif args.auth:
        print("Mode: AUTHENTICATED — expect command to be REJECTED (server running with AUTH_MODE=True)")
    else:
        print("Mode: unspecified — just injecting and showing response")

    inject_command(args.target, args.port, args.cmd, force_unsigned=True)


if __name__ == "__main__":
    main()
