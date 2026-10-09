"""
tests/test_attacker_vm.py  —  Attacker VM integration test scripts
=======================================================================
Run these DIRECTLY ON THE ATTACKER VM (Kali, 192.168.56.10).

All tests are self-contained and safe:
  - No real encryption of system files
  - No outbound internet connections
  - Uses only the private lab subnet (192.168.56.x) or loopback

Tests included
--------------
  1. test_c2_server_loopback     — C2 server + client on loopback (no victim needed)
  2. test_hmac_auth              — HMAC sign/verify round-trip
  3. test_spoof_demo             — FR-8.3 naive vs authenticated spoofing (loopback)
  4. test_transfer_receiver      — Loopback file receive + decrypt round-trip
  5. test_rsa_keys_loaded        — Verify keys/public.pem and keys/private.pem are present
  6. test_c2_reach_victim        — Ping Victim VM and confirm C2 port is reachable (needs live victim)

Usage (from project root on Attacker VM):
    python3 tests/test_attacker_vm.py
    python3 tests/test_attacker_vm.py --live    # includes live victim connectivity check
"""
from __future__ import annotations

import argparse
import hashlib
import hmac as _hmac_module
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

# ── Make project importable ───────────────────────────────────────────────────
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import config
from shared.crypto import (
    aes_encrypt, aes_decrypt,
    generate_aes_key, generate_iv,
    rsa_wrap_key, rsa_unwrap_key,
    generate_rsa_keypair,
)

# ──────────────────────────────────────────────────────────────────────────────
# Test runner
# ──────────────────────────────────────────────────────────────────────────────

PASS = "\033[92m[PASS]\033[0m"
FAIL = "\033[91m[FAIL]\033[0m"
INFO = "\033[94m[INFO]\033[0m"

_results: list[dict] = []


def _run(name: str, fn):
    print(f"\n{'─'*55}\n  {name}")
    try:
        msg = fn()
        print(f"  {PASS} {msg or ''}")
        _results.append({"test": name, "status": "PASS", "detail": msg or ""})
    except AssertionError as exc:
        print(f"  {FAIL} Assertion: {exc}")
        _results.append({"test": name, "status": "FAIL", "detail": str(exc)})
    except Exception as exc:
        print(f"  {FAIL} Exception: {exc}")
        _results.append({"test": name, "status": "ERROR", "detail": str(exc)})


# ──────────────────────────────────────────────────────────────────────────────
# Test 1 — RSA key files present
# ──────────────────────────────────────────────────────────────────────────────

def test_rsa_keys_loaded():
    pub  = Path(config.RSA_PUB_KEY_PATH)
    priv = Path(config.RSA_PRIV_KEY_PATH)
    assert pub.is_file(),  f"Public key missing: {pub}"
    assert priv.is_file(), f"Private key missing: {priv}"
    pub_sz  = pub.stat().st_size
    priv_sz = priv.stat().st_size
    return f"public.pem {pub_sz}B, private.pem {priv_sz}B"


# ──────────────────────────────────────────────────────────────────────────────
# Test 2 — HMAC sign/verify
# ──────────────────────────────────────────────────────────────────────────────

_HMAC_SEP = b"|SIG|"


def _sign(raw_cmd: bytes) -> bytes:
    tag = _hmac_module.new(config.HMAC_SECRET, raw_cmd, hashlib.sha256).hexdigest().encode()
    return raw_cmd + _HMAC_SEP + tag


def _verify(message: bytes) -> tuple[bytes, bool]:
    if _HMAC_SEP not in message:
        return message, False
    raw_cmd, _, received_tag = message.partition(_HMAC_SEP)
    expected = _hmac_module.new(config.HMAC_SECRET, raw_cmd, hashlib.sha256).hexdigest().encode()
    return raw_cmd, _hmac_module.compare_digest(expected, received_tag)


def test_hmac_auth():
    # Valid signed command
    cmd = b"START_EXFIL"
    signed = _sign(cmd)
    raw, ok = _verify(signed)
    assert ok, "Valid signed command was rejected"
    assert raw == cmd, "Command payload corrupted after sign/verify"

    # Tampered command must be rejected
    tampered = signed[:-4] + b"XXXX"  # corrupt the last 4 bytes of the HMAC tag
    _, ok2 = _verify(tampered)
    assert not ok2, "Tampered command was incorrectly accepted"

    # Unsigned command must be rejected
    _, ok3 = _verify(b"STOP")
    assert not ok3, "Unsigned command was incorrectly accepted"

    return "sign/verify round-trip OK; tamper and unsigned both rejected"


# ──────────────────────────────────────────────────────────────────────────────
# Test 3 — AES round-trip (crypto sanity)
# ──────────────────────────────────────────────────────────────────────────────

def test_aes_roundtrip():
    plaintext = b"IS Lab simulated payload " * 100
    key = generate_aes_key()
    iv  = generate_iv()
    ct  = aes_encrypt(plaintext, iv, key)
    assert ct != plaintext, "Ciphertext must differ from plaintext"
    pt  = aes_decrypt(ct, iv, key)
    assert pt == plaintext, "AES decrypt did not recover original plaintext"
    return f"AES-256-CBC encrypt/decrypt OK, {len(plaintext)} → {len(ct)} bytes"


# ──────────────────────────────────────────────────────────────────────────────
# Test 4 — RSA hybrid wrap/unwrap (using existing key pair)
# ──────────────────────────────────────────────────────────────────────────────

def test_rsa_hybrid():
    aes_key  = generate_aes_key()
    wrapped  = rsa_wrap_key(aes_key, config.RSA_PUB_KEY_PATH)
    assert len(wrapped) == 256, f"RSA-2048 wrapped key should be 256 bytes, got {len(wrapped)}"
    unwrapped = rsa_unwrap_key(wrapped, config.RSA_PRIV_KEY_PATH)
    assert unwrapped == aes_key, "RSA unwrapped key does not match original"
    return "RSA-2048-OAEP wrap/unwrap round-trip OK"


# ──────────────────────────────────────────────────────────────────────────────
# Test 5 — C2 server loopback (no victim needed)
# ──────────────────────────────────────────────────────────────────────────────

_C2_TEST_PORT = 19001  # ephemeral port, avoids clash with real C2


def _mini_c2_server(auth_mode: bool, ready: threading.Event, stop: threading.Event):
    """Minimal in-process C2 server for loopback testing."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", _C2_TEST_PORT))
        srv.listen(1)
        ready.set()
        srv.settimeout(8)
        try:
            conn, _ = srv.accept()
            with conn:
                conn.sendall(b"READY|AUTH\n" if auth_mode else b"READY|NOAUTH\n")
                conn.settimeout(5)
                data = conn.recv(4096)
                if not data:
                    return
                line = data.strip()
                if auth_mode:
                    if _HMAC_SEP not in line:
                        conn.sendall(b"ERR: authentication failed\n")
                        return
                    raw, _, tag = line.partition(_HMAC_SEP)
                    expected = _hmac_module.new(config.HMAC_SECRET, raw, hashlib.sha256).hexdigest().encode()
                    if not _hmac_module.compare_digest(expected, tag):
                        conn.sendall(b"ERR: authentication failed\n")
                        return
                    cmd = raw.decode(errors="replace").strip().upper()
                else:
                    cmd = line.decode(errors="replace").strip().upper()
                if cmd == "STOP":
                    conn.sendall(b"ACK: STOP\n")
        except socket.timeout:
            pass
        finally:
            stop.set()


def _readline_sock(sock: socket.socket, timeout: float = 5.0) -> str:
    buf = b""
    sock.settimeout(timeout)
    try:
        while b"\n" not in buf:
            chunk = sock.recv(1024)
            if not chunk:
                break
            buf += chunk
    except socket.timeout:
        pass
    return buf.decode(errors="replace").strip()


def _c2_loopback(auth_mode: bool) -> bool:
    """
    Start a mini C2 server, connect as a client, send the appropriate STOP
    command, and verify the server's response.
    """
    ready = threading.Event()
    stop  = threading.Event()
    t = threading.Thread(target=_mini_c2_server, args=(auth_mode, ready, stop), daemon=True)
    t.start()
    assert ready.wait(timeout=5), "Mini C2 server did not start in time"
    time.sleep(0.05)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect(("127.0.0.1", _C2_TEST_PORT))
        banner = _readline_sock(sock)
        assert ("AUTH" in banner if auth_mode else "NOAUTH" in banner), \
            f"Unexpected banner: {banner!r}"

        if auth_mode:
            payload = _sign(b"STOP") + b"\n"
        else:
            payload = b"STOP\n"
        sock.sendall(payload)
        response = _readline_sock(sock)

    stop.wait(timeout=5)
    return response.startswith("ACK")


def test_c2_loopback_naive():
    ok = _c2_loopback(auth_mode=False)
    assert ok, "Naive C2: STOP command was not acknowledged"
    return "Naive C2 loopback received ACK: STOP"


def test_c2_loopback_auth():
    time.sleep(0.3)   # let the OS release the ephemeral port
    ok = _c2_loopback(auth_mode=True)
    assert ok, "Authenticated C2: signed STOP was not acknowledged"
    return "Authenticated C2 loopback received ACK: STOP (signed command)"


# ──────────────────────────────────────────────────────────────────────────────
# Test 6 — FR-8.3 Spoofing demo (loopback, no live victim/server)
# ──────────────────────────────────────────────────────────────────────────────

def test_spoof_demo():
    """
    Run the self-contained c2_spoof_selftest.py and confirm the output file
    shows both expected results (naive accepted, HMAC rejected).
    """
    script = _ROOT / "attacker" / "c2_spoof_selftest.py"
    assert script.is_file(), f"c2_spoof_selftest.py not found at {script}"

    result = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True, text=True, timeout=30, cwd=str(_ROOT),
    )
    out_path = _ROOT / "results" / "spoof_demo_output.txt"
    assert out_path.is_file(), "spoof_demo_output.txt was not created"
    content = out_path.read_text(encoding="utf-8")

    naive_ok = "NAIVE variant CONFIRMED" in content or "unsigned command ACCEPTED" in content
    hmac_ok  = "HMAC variant CONFIRMED"  in content or "unsigned command REJECTED" in content

    assert naive_ok, "Naive variant: expected 'command ACCEPTED' evidence in output"
    assert hmac_ok,  "HMAC variant:  expected 'command REJECTED' evidence in output"

    return "FR-8.3 spoofing demo: naive=ACCEPTED, HMAC=REJECTED ✓"


# ──────────────────────────────────────────────────────────────────────────────
# Test 7 — Transfer receiver loopback (no victim needed)
# ──────────────────────────────────────────────────────────────────────────────

_XFER_TEST_PORT = 19002


def _loopback_sender(files: dict[str, bytes], done: threading.Event):
    """
    Mimics transfer_sender's actual wire protocol per transfer_receiver.py:
      [4B fname_len BE] [N fname bytes] [8B filesize BE uint64]
      [16B IV] [32B AES key] [filesize encrypted bytes]
    Sentinel: 4B zero fname_len.
    """
    import struct
    time.sleep(0.15)  # wait for receiver to bind
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(10)
        sock.connect(("127.0.0.1", _XFER_TEST_PORT))
        for filename, data in files.items():
            aes_key = generate_aes_key()
            iv      = generate_iv()
            enc     = aes_encrypt(data, iv, aes_key)
            name_bytes = filename.encode("utf-8")
            sock.sendall(struct.pack(">I", len(name_bytes)))
            sock.sendall(name_bytes)
            sock.sendall(struct.pack(">Q", len(enc)))
            sock.sendall(iv)
            sock.sendall(aes_key)
            sock.sendall(enc)
        # Sentinel
        sock.sendall(struct.pack(">I", 0))
    done.set()


def test_transfer_receiver_loopback():
    files = {
        "doc_test.txt": b"Fictional briefing content " * 80,
        "img_test.jpg": bytes(range(256)) * 20,
    }
    done = threading.Event()

    with tempfile.TemporaryDirectory() as tmp_dir:
        output = Path(tmp_dir)

        # Start receiver in a background thread
        recv_error: list[str] = []

        def _run_receiver():
            try:
                from attacker.transfer_receiver import run_receiver as _recv
                _recv(
                    host="127.0.0.1",
                    port=_XFER_TEST_PORT,
                    output_dir=str(output),
                    log_dir=str(output / "logs"),
                    benchmark_path=str(output / "bench.json"),
                )
            except Exception as exc:
                recv_error.append(str(exc))

        recv_thread = threading.Thread(target=_run_receiver, daemon=True)
        recv_thread.start()

        send_thread = threading.Thread(target=_loopback_sender, args=(files, done), daemon=True)
        send_thread.start()

        done.wait(timeout=15)
        time.sleep(0.5)  # let receiver finish writing

        if recv_error:
            raise AssertionError(f"Receiver error: {recv_error[0]}")

        for fname, original in files.items():
            written = output / fname
            assert written.is_file(), f"{fname} not written by receiver"
            assert written.read_bytes() == original, f"{fname}: byte mismatch"

        return f"Loopback: {len(files)} files sent + verified byte-for-byte (correct protocol)"


# ──────────────────────────────────────────────────────────────────────────────
# Test 8 — Live victim VM connectivity (optional, --live flag)
# ──────────────────────────────────────────────────────────────────────────────

def test_victim_connectivity_live():
    victim_ip = config.VICTIM_IP
    # 1 — ICMP ping
    ping = subprocess.run(
        ["ping", "-c", "2", "-W", "2", victim_ip],
        capture_output=True, text=True,
    )
    assert ping.returncode == 0, f"Ping to {victim_ip} failed: {ping.stderr}"

    # 2 — TCP connect to C2 port (victim must have c2_client.py running)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)
        try:
            sock.connect((victim_ip, config.C2_PORT))
            banner = _readline_sock(sock)
            assert banner, "Connected but received empty banner from victim"
        except ConnectionRefusedError:
            raise AssertionError(
                f"C2 port {config.C2_PORT} refused on {victim_ip}. "
                "Start victim/c2_client.py on the Victim VM first."
            )

    return (
        f"Ping OK; C2 port {config.C2_PORT} open on {victim_ip}. "
        f"Banner: {banner!r}"
    )


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Attacker VM — IS Lab test suite")
    parser.add_argument(
        "--live", action="store_true",
        help="Also run test_victim_connectivity_live (requires victim VM to be running)",
    )
    args = parser.parse_args()

    print(f"\n{'='*55}")
    print(f"  IS Lab — Attacker VM Test Suite")
    print(f"  Time: {datetime.now(timezone.utc).isoformat(timespec='milliseconds')}Z")
    print(f"{'='*55}")

    _run("1. RSA key files present",            test_rsa_keys_loaded)
    _run("2. HMAC sign/verify round-trip",      test_hmac_auth)
    _run("3. AES-256-CBC encrypt/decrypt",      test_aes_roundtrip)
    _run("4. RSA-2048-OAEP wrap/unwrap",        test_rsa_hybrid)
    _run("5. C2 loopback — naive variant",      test_c2_loopback_naive)
    _run("6. C2 loopback — authenticated",      test_c2_loopback_auth)
    _run("7. FR-8.3 spoofing self-test",        test_spoof_demo)

    try:
        _run("8. Transfer receiver loopback",   test_transfer_receiver_loopback)
    except ImportError as e:
        print(f"\n  {INFO} Transfer receiver loopback skipped: {e}")
        _results.append({"test": "8. transfer receiver loopback", "status": "SKIP", "detail": str(e)})

    if args.live:
        _run("9. Live victim VM connectivity",  test_victim_connectivity_live)
    else:
        print(f"\n  {INFO} Skipping live connectivity test (pass --live to enable).")

    # Summary
    passed = sum(1 for r in _results if r["status"] == "PASS")
    failed = sum(1 for r in _results if r["status"] in ("FAIL", "ERROR"))
    skipped = sum(1 for r in _results if r["status"] == "SKIP")

    print(f"\n{'='*55}")
    print(f"  RESULTS  —  passed: {passed}  failed: {failed}  skipped: {skipped}")
    print(f"{'='*55}\n")

    # Save results JSON
    out = _ROOT / "results" / "attacker_vm_test_results.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "results": _results,
    }, indent=2), encoding="utf-8")
    print(f"  Results saved → {out}")

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
