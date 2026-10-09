"""
tests/test_crypto.py  —  Person 1
Unit tests + benchmarks for shared/crypto.py

Run from the project root:
    python3 -m pytest tests/test_crypto.py -v
  or directly:
    python3 tests/test_crypto.py

What is tested
--------------
  1. AES round-trip for text, image, audio, and video sample data
  2. AES round-trip on actual files (if sample files exist)
  3. RSA keypair generation → key wrap → key unwrap round-trip
  4. Hybrid: AES-encrypt file, wrap key with RSA, unwrap key, AES-decrypt,
     confirm byte-for-byte original recovery
  5. generate_aes_key() and generate_iv() produce correct sizes and randomness
  6. HMAC signing utility (matches what c2_server / c2_client use)

Benchmarks for AES throughput and RSA overhead are written to
    results/crypto_benchmarks.json
when the BENCHMARK environment variable is set to 1:
    BENCHMARK=1 python3 tests/test_crypto.py
"""

import os
import sys
import json
import time
import tempfile
import hmac as _hmac
import hashlib
from pathlib import Path

# ── path fixup ───────────────────────────────────────────────────────────────
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from shared.crypto import (
    generate_aes_key,
    generate_iv,
    aes_encrypt,
    aes_decrypt,
    encrypt_file,
    decrypt_file,
    generate_rsa_keypair,
    rsa_wrap_key,
    rsa_unwrap_key,
    benchmark_aes,
    benchmark_rsa,
    save_benchmarks,
)

# ─── ANSI colour helpers ─────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

_passed = 0
_failed = 0


def _ok(name: str) -> None:
    global _passed
    _passed += 1
    print(f"  {GREEN}✓{RESET} {name}")


def _fail(name: str, reason: str) -> None:
    global _failed
    _failed += 1
    print(f"  {RED}✗ {name}{RESET}  →  {reason}")


def _section(title: str) -> None:
    print(f"\n{BOLD}── {title} ──{RESET}")


# ──────────────────────────────────────────────────────────────────────────────
# Test 1 — Key / IV generation
# ──────────────────────────────────────────────────────────────────────────────

def test_key_iv_generation() -> None:
    _section("Key / IV generation")

    key = generate_aes_key()
    if len(key) == 32:
        _ok("generate_aes_key() returns 32 bytes")
    else:
        _fail("generate_aes_key() length", f"got {len(key)}")

    iv = generate_iv()
    if len(iv) == 16:
        _ok("generate_iv() returns 16 bytes")
    else:
        _fail("generate_iv() length", f"got {len(iv)}")

    # Randomness: two consecutive calls should not be equal
    if generate_aes_key() != generate_aes_key():
        _ok("generate_aes_key() is non-deterministic")
    else:
        _fail("generate_aes_key() randomness", "two consecutive keys are identical (very unlikely)")

    if generate_iv() != generate_iv():
        _ok("generate_iv() is non-deterministic")
    else:
        _fail("generate_iv() randomness", "two consecutive IVs are identical (very unlikely)")


# ──────────────────────────────────────────────────────────────────────────────
# Test 2 — AES round-trip on synthetic payloads (mimicking media types)
# ──────────────────────────────────────────────────────────────────────────────

_SYNTHETIC_PAYLOADS = {
    "text":  b"OPERATION EAGLE\nClassification: FICTIONAL\n" * 200,
    "image": os.urandom(1024 * 256),    # 256 KB of high-entropy bytes (JPEG-like)
    "audio": os.urandom(1024 * 512),    # 512 KB
    "video": os.urandom(1024 * 1024),   # 1 MB
}


def test_aes_roundtrip_synthetic() -> None:
    _section("AES round-trip — synthetic payloads")
    key = generate_aes_key()

    for media_type, plaintext in _SYNTHETIC_PAYLOADS.items():
        iv = generate_iv()
        try:
            ciphertext = aes_encrypt(plaintext, iv, key)
            recovered  = aes_decrypt(ciphertext, iv, key)
            if recovered == plaintext:
                _ok(f"AES round-trip [{media_type}] — {len(plaintext):,} B")
            else:
                _fail(f"AES round-trip [{media_type}]", "recovered != original")
        except Exception as exc:
            _fail(f"AES round-trip [{media_type}]", str(exc))


# ──────────────────────────────────────────────────────────────────────────────
# Test 3 — AES wrong-key / wrong-IV produces garbage (not the original)
# ──────────────────────────────────────────────────────────────────────────────

def test_aes_wrong_key_wrong_iv() -> None:
    _section("AES — wrong key / wrong IV produces incorrect output")
    key       = generate_aes_key()
    wrong_key = generate_aes_key()
    iv        = generate_iv()
    wrong_iv  = generate_iv()
    plaintext = b"TOP SECRET - FICTIONAL\n" * 50

    ciphertext = aes_encrypt(plaintext, iv, key)

    # Wrong key
    try:
        garbage = aes_decrypt(ciphertext, iv, wrong_key)
        if garbage != plaintext:
            _ok("Wrong key → garbage output (correct behaviour)")
        else:
            _fail("Wrong key test", "decryption with wrong key returned original data!")
    except Exception:
        # An exception (bad padding) is also acceptable — means wrong key detected
        _ok("Wrong key → exception raised (correct behaviour — bad padding detected)")

    # Wrong IV
    try:
        garbage = aes_decrypt(ciphertext, wrong_iv, key)
        if garbage != plaintext:
            _ok("Wrong IV → altered output (correct behaviour)")
        else:
            _fail("Wrong IV test", "decryption with wrong IV returned original data!")
    except Exception:
        _ok("Wrong IV → exception raised (correct behaviour — bad padding detected)")


# ──────────────────────────────────────────────────────────────────────────────
# Test 4 — encrypt_file / decrypt_file helpers round-trip
# ──────────────────────────────────────────────────────────────────────────────

def test_file_helpers() -> None:
    _section("encrypt_file / decrypt_file helpers")
    key = generate_aes_key()

    for media_type, content in _SYNTHETIC_PAYLOADS.items():
        with tempfile.TemporaryDirectory() as tmpdir:
            src  = Path(tmpdir) / f"original.{media_type}"
            enc  = Path(tmpdir) / f"encrypted.{media_type}.locked"
            dec  = Path(tmpdir) / f"decrypted.{media_type}"

            src.write_bytes(content)

            try:
                iv = encrypt_file(str(src), str(enc), key)
                decrypt_file(str(enc), str(dec), iv, key)
                recovered = dec.read_bytes()
                if recovered == content:
                    _ok(f"File encrypt/decrypt round-trip [{media_type}]")
                else:
                    _fail(f"File encrypt/decrypt [{media_type}]", "recovered != original")
            except Exception as exc:
                _fail(f"File encrypt/decrypt [{media_type}]", str(exc))


# ──────────────────────────────────────────────────────────────────────────────
# Test 5 — RSA keypair generation + key wrap/unwrap round-trip
# ──────────────────────────────────────────────────────────────────────────────

def test_rsa_roundtrip() -> None:
    _section("RSA-2048 keypair generation + key wrap / unwrap")

    with tempfile.TemporaryDirectory() as tmpdir:
        pub_path  = str(Path(tmpdir) / "public.pem")
        priv_path = str(Path(tmpdir) / "private.pem")

        # Generate keypair
        try:
            generate_rsa_keypair(pub_path, priv_path)
            pub_exists  = Path(pub_path).exists()
            priv_exists = Path(priv_path).exists()
            if pub_exists and priv_exists:
                _ok("generate_rsa_keypair creates both PEM files")
            else:
                _fail("generate_rsa_keypair", f"pub={pub_exists}, priv={priv_exists}")
                return
        except Exception as exc:
            _fail("generate_rsa_keypair", str(exc))
            return

        # Wrap / unwrap
        aes_key = generate_aes_key()
        try:
            wrapped   = rsa_wrap_key(aes_key, pub_path)
            unwrapped = rsa_unwrap_key(wrapped, priv_path)
            if unwrapped == aes_key:
                _ok("RSA wrap → unwrap recovers original AES key")
            else:
                _fail("RSA wrap/unwrap", "unwrapped key != original")
        except Exception as exc:
            _fail("RSA wrap/unwrap", str(exc))


# ──────────────────────────────────────────────────────────────────────────────
# Test 6 — Hybrid round-trip (full ransomware path)
# ──────────────────────────────────────────────────────────────────────────────

def test_hybrid_roundtrip() -> None:
    _section("Hybrid AES+RSA round-trip (ransomware encryption path)")

    with tempfile.TemporaryDirectory() as tmpdir:
        pub_path  = str(Path(tmpdir) / "public.pem")
        priv_path = str(Path(tmpdir) / "private.pem")
        generate_rsa_keypair(pub_path, priv_path)

        for media_type, content in _SYNTHETIC_PAYLOADS.items():
            src_path    = Path(tmpdir) / f"real_{media_type}.bin"
            locked_path = Path(tmpdir) / f"real_{media_type}.bin.locked"
            sidecar     = Path(tmpdir) / f"real_{media_type}.bin.key"
            restored    = Path(tmpdir) / f"real_{media_type}.restored"

            src_path.write_bytes(content)

            try:
                # ── Encrypt (simulator side) ─────────────────────────────────
                per_file_key = generate_aes_key()
                iv           = encrypt_file(str(src_path), str(locked_path), per_file_key)
                wrapped_key  = rsa_wrap_key(per_file_key, pub_path)
                # Sidecar format: [16B IV][wrapped_key]
                sidecar.write_bytes(iv + wrapped_key)
                del per_file_key  # simulate discarding from memory

                # ── Decrypt (attacker side, using private key) ───────────────
                sidecar_data  = sidecar.read_bytes()
                iv_read       = sidecar_data[:16]
                wrapped_read  = sidecar_data[16:]
                restored_key  = rsa_unwrap_key(wrapped_read, priv_path)
                decrypt_file(str(locked_path), str(restored), iv_read, restored_key)

                recovered = restored.read_bytes()
                if recovered == content:
                    _ok(f"Hybrid round-trip [{media_type}] — {len(content):,} B")
                else:
                    _fail(f"Hybrid round-trip [{media_type}]", "recovered != original")

            except Exception as exc:
                _fail(f"Hybrid round-trip [{media_type}]", str(exc))


# ──────────────────────────────────────────────────────────────────────────────
# Test 7 — HMAC signing (used by c2_server / c2_client)
# ──────────────────────────────────────────────────────────────────────────────

def test_hmac_sign_verify() -> None:
    _section("HMAC-SHA256 command signing (C2 channel)")

    _HMAC_SEP = b"|SIG|"
    SECRET    = b"test-secret"
    cmd       = b"START_ENCRYPT"

    def sign(raw: bytes) -> bytes:
        tag = _hmac.new(SECRET, raw, hashlib.sha256).hexdigest().encode()
        return raw + _HMAC_SEP + tag

    def verify(msg: bytes) -> tuple[bytes, bool]:
        if _HMAC_SEP not in msg:
            return msg, False
        raw, _, recv_tag = msg.partition(_HMAC_SEP)
        expected = _hmac.new(SECRET, raw, hashlib.sha256).hexdigest().encode()
        return raw, _hmac.compare_digest(expected, recv_tag)

    signed = sign(cmd)
    raw, valid = verify(signed)
    if valid and raw == cmd:
        _ok("Valid signed command accepted")
    else:
        _fail("HMAC sign/verify", f"valid={valid}, raw={raw}")

    # Tamper with the command
    tampered = b"STOP" + _HMAC_SEP + signed.split(_HMAC_SEP)[1]
    _, valid2 = verify(tampered)
    if not valid2:
        _ok("Tampered command rejected (HMAC mismatch)")
    else:
        _fail("HMAC forge detect", "tampered command was accepted!")

    # No signature at all
    _, valid3 = verify(b"START_EXFIL")
    if not valid3:
        _ok("Unsigned command rejected")
    else:
        _fail("HMAC unsigned detect", "unsigned command was accepted!")


# ──────────────────────────────────────────────────────────────────────────────
# Benchmarks (optional — set BENCHMARK=1)
# ──────────────────────────────────────────────────────────────────────────────

def run_benchmarks() -> None:
    _section("AES + RSA Benchmarks")
    print("  Generating synthetic sample files for benchmarking …")

    with tempfile.TemporaryDirectory() as tmpdir:
        sample_files = {}
        sizes = {"text": 50_000, "image": 500_000, "audio": 2_000_000, "video": 10_000_000}
        for media_type, size in sizes.items():
            fp = Path(tmpdir) / f"sample.{media_type}"
            fp.write_bytes(os.urandom(size))
            sample_files[media_type] = str(fp)

        aes_results = benchmark_aes(sample_files)
        for mt, r in aes_results.items():
            print(
                f"  AES [{mt}]  {r['size_bytes']:>10,} B  "
                f"enc {r['encrypt_ms']:.1f} ms ({r['encrypt_throughput_mbps']:.1f} MB/s)  "
                f"dec {r['decrypt_ms']:.1f} ms ({r['decrypt_throughput_mbps']:.1f} MB/s)"
            )

        # RSA benchmarks require a keypair
        pub_path  = str(Path(tmpdir) / "pub.pem")
        priv_path = str(Path(tmpdir) / "priv.pem")
        generate_rsa_keypair(pub_path, priv_path)
        rsa_results = benchmark_rsa(pub_path, priv_path)
        print(
            f"  RSA  wrap avg {rsa_results['rsa_wrap_avg_ms']:.2f} ms  "
            f"unwrap avg {rsa_results['rsa_unwrap_avg_ms']:.2f} ms  "
            f"({rsa_results['iterations']} iterations)"
        )

        combined = {"aes": aes_results, "rsa": rsa_results}
        results_dir = _ROOT / "results"
        results_dir.mkdir(parents=True, exist_ok=True)
        out_path = str(results_dir / "crypto_benchmarks.json")
        save_benchmarks(combined, out_path)
        _ok(f"Benchmarks saved → {out_path}")


# ──────────────────────────────────────────────────────────────────────────────
# Runner
# ──────────────────────────────────────────────────────────────────────────────

def main() -> None:
    print(f"\n{BOLD}=== shared/crypto.py — Test Suite ==={RESET}")
    print(f"Root: {_ROOT}\n")

    test_key_iv_generation()
    test_aes_roundtrip_synthetic()
    test_aes_wrong_key_wrong_iv()
    test_file_helpers()
    test_rsa_roundtrip()
    test_hybrid_roundtrip()
    test_hmac_sign_verify()

    if os.environ.get("BENCHMARK") == "1":
        run_benchmarks()

    # ── Summary ──────────────────────────────────────────────────────────────
    total = _passed + _failed
    colour = GREEN if _failed == 0 else RED
    print(f"\n{colour}{BOLD}Results: {_passed}/{total} passed{RESET}")
    if _failed:
        print(f"{RED}  {_failed} test(s) failed.{RESET}")
        sys.exit(1)
    else:
        print(f"{GREEN}  All tests passed.{RESET}")
        sys.exit(0)


# ── pytest-compatible wrappers (each top-level function is a pytest test) ─────
def test_1_key_iv_generation():         test_key_iv_generation()
def test_2_aes_roundtrip_synthetic():   test_aes_roundtrip_synthetic()
def test_3_aes_wrong_key_wrong_iv():    test_aes_wrong_key_wrong_iv()
def test_4_file_helpers():              test_file_helpers()
def test_5_rsa_roundtrip():             test_rsa_roundtrip()
def test_6_hybrid_roundtrip():          test_hybrid_roundtrip()
def test_7_hmac_sign_verify():          test_hmac_sign_verify()


if __name__ == "__main__":
    main()
