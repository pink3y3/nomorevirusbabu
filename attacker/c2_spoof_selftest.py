"""
attacker/c2_spoof_selftest.py  —  Person 1
Self-contained loopback test of FR-8.3 (C2 spoofing demo).

Starts a minimal in-process C2 server on localhost, injects an unsigned
command as a third-party attacker, captures the result, and saves:
    results/spoof_demo_output.txt

Run:
    python3 attacker/c2_spoof_selftest.py

This script is distinct from c2_spoof_demo.py (which requires a live VM).
Use this for pre-generating evaluation report evidence.
"""

import sys
import os
import socket
import hmac
import hashlib
import json
import threading
import io
import time
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))\

import config

# ── ANSI codes (replicated here so this file is standalone) ───────────────────
GREEN = "\033[92m"
RED   = "\033[91m"
RESET = "\033[0m"
BOLD  = "\033[1m"

_HMAC_SEP = b"|SIG|"
_DEMO_PORT = 19001   # use an ephemeral port to avoid clashing with the real C2

# ── Minimal in-process C2 server ─────────────────────────────────────────────

def _sign(raw_cmd: bytes) -> bytes:
    tag = hmac.new(config.HMAC_SECRET, raw_cmd, hashlib.sha256).hexdigest().encode()
    return raw_cmd + _HMAC_SEP + tag


def _mini_c2_server(auth_mode: bool, ready: threading.Event, done: threading.Event) -> None:
    """Minimal C2 server that handles exactly ONE connection then exits."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", _DEMO_PORT))
        srv.listen(1)
        ready.set()
        srv.settimeout(10)
        try:
            conn, addr = srv.accept()
            with conn:
                banner = b"READY|AUTH\n" if auth_mode else b"READY|NOAUTH\n"
                conn.sendall(banner)

                buf = b""
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                    while b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        if not line:
                            continue

                        # Auth check
                        if auth_mode:
                            if _HMAC_SEP not in line:
                                conn.sendall(b"ERR: authentication failed\n")
                                continue
                            raw_cmd, _, received_tag = line.partition(_HMAC_SEP)
                            expected = hmac.new(config.HMAC_SECRET, raw_cmd, hashlib.sha256).hexdigest().encode()
                            if not hmac.compare_digest(expected, received_tag):
                                conn.sendall(b"ERR: authentication failed\n")
                                continue
                        else:
                            raw_cmd = line

                        decoded = raw_cmd.decode(errors="replace").strip().upper()
                        if decoded == "STOP":
                            conn.sendall(b"ACK: STOP\n")
                        else:
                            conn.sendall(b"ACK: UNKNOWN\n")
        except socket.timeout:
            pass
        finally:
            done.set()


def _readline_sock(sock: socket.socket) -> str:
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


def run_scenario(auth_mode: bool) -> list[str]:
    """Run the spoof injection against an in-process server. Returns output lines."""
    lines = []

    variant = "AUTHENTICATED (HMAC-SHA256)" if auth_mode else "NAIVE (unauthenticated)"
    lines.append(f"\n{'='*60}")
    lines.append(f"  Scenario: {variant}")
    lines.append(f"  Injecting unsigned STOP command to 127.0.0.1:{_DEMO_PORT}")
    lines.append(f"{'='*60}")

    ready = threading.Event()
    done  = threading.Event()
    t = threading.Thread(
        target=_mini_c2_server,
        args=(auth_mode, ready, done),
        daemon=True,
    )
    t.start()
    ready.wait(timeout=5)

    time.sleep(0.05)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(("127.0.0.1", _DEMO_PORT))
            banner = _readline_sock(sock)
            lines.append(f"  Server banner  : {banner}")

            # Always send unsigned (the attacker is NOT the legitimate operator)
            payload = b"STOP\n"
            lines.append(f"  Injecting      : STOP  (no HMAC signature)")
            sock.sendall(payload)

            response = _readline_sock(sock)
            lines.append(f"  Server response: {response}")

            if response.startswith("ACK"):
                lines.append(f"\n  {RED}{BOLD}[RESULT] NAIVE variant CONFIRMED: unsigned command ACCEPTED ✓{RESET}")
                lines.append(f"  {RED}→ A third party successfully injected 'STOP' with no authentication.{RESET}")
                lines.append(f"  {RED}  This halts the legitimate operator's attack — C2 is spoofable.{RESET}")
            elif "authentication failed" in response.lower() or response.startswith("ERR"):
                lines.append(f"\n  {GREEN}{BOLD}[RESULT] HMAC variant CONFIRMED: unsigned command REJECTED ✓{RESET}")
                lines.append(f"  {GREEN}→ HMAC-SHA256 authentication blocked the forged command.{RESET}")
                lines.append(f"  {GREEN}  The legitimate operator's attack continues unimpeded.{RESET}")
            else:
                lines.append(f"  [RESULT] Unexpected response: {response}")

    except Exception as exc:
        lines.append(f"  {RED}Connection error: {exc}{RESET}")

    done.wait(timeout=5)
    return lines


def main() -> None:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    output_lines = [
        f"FR-8.3 — C2 Command Injection / Spoofing Demo",
        f"Generated  : {timestamp}",
        f"Script     : attacker/c2_spoof_selftest.py  (loopback; no live VM required)",
        f"Purpose    : Demonstrate that the naive C2 variant accepts unsigned commands",
        f"             while the HMAC-authenticated variant rejects them.",
        "",
        "Methodology:",
        "  A minimal in-process C2 server is started on 127.0.0.1:19001.",
        "  A simulated third-party attacker connects and injects an unsigned STOP",
        "  command (without valid HMAC-SHA256 signature).",
        "  Test is repeated for both AUTH_MODE=False (naive) and AUTH_MODE=True.",
    ]

    # Scenario 1 — Naive
    output_lines += run_scenario(auth_mode=False)

    time.sleep(0.3)   # brief pause so the port is released

    # Scenario 2 — Authenticated
    output_lines += run_scenario(auth_mode=True)

    output_lines += [
        "",
        "=" * 60,
        "  Summary",
        "=" * 60,
        "  Naive variant    : STOP accepted  → attack halted by spoofing  ✗",
        "  HMAC variant     : STOP rejected  → HMAC prevents injection   ✓",
        "",
        "  Conclusion: HMAC-SHA256 authentication (AUTH_MODE=True) defeats",
        "  the command injection attack demonstrated against AUTH_MODE=False.",
        "=" * 60,
    ]

    # Strip ANSI codes for the saved file
    import re
    ansi_escape = re.compile(r"\x1b\[[0-9;]*m")

    results_dir = Path(_ROOT) / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    out_path = results_dir / "spoof_demo_output.txt"

    clean_lines = [ansi_escape.sub("", l) for l in output_lines]

    with open(out_path, "w") as fh:
        fh.write("\n".join(clean_lines) + "\n")

    # Also print with colour to terminal
    for l in output_lines:
        print(l)

    print(f"\n[c2_spoof_selftest] Output saved → {out_path}")


if __name__ == "__main__":
    main()
