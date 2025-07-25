"""
=========================================================
Adaptive Hashing Encryption (AHE) SDK - Full Test Suite
=========================================================

Covers:
- Unit Tests for Utilities, AES, PQC, Metadata
- Integration Tests for Full AHE Workflow
- Edge Cases (Wrong Password, Tampered Data)
- Performance Timings & Security Checks
"""

import os
import json
import base64
import pytest
from core.core import (
    encrypt_message,
    decrypt_latest,
    calculate_entropy,
    derive_key,
    encrypt_metadata,
    decrypt_metadata,
    STORAGE_DIR,
    AES_KEY_SIZE
)

# === Test Constants ===
TEST_MESSAGE = "This is a secret test message for AHE."
TEST_PASSWORD = "StrongPassword123"
WRONG_PASSWORD = "WrongPass"
META_EXT = ".meta"
ENC_EXT = ".ahe"


# === Utility Tests ===
def test_entropy_calculation():
    data = b"abcdef"
    entropy = calculate_entropy(data)
    assert entropy > 0, "Entropy should be positive for non-empty data"


def test_key_derivation():
    key = derive_key(b"pass", b"pubkey", b"cipher")
    assert len(key) == AES_KEY_SIZE, "Derived key length mismatch"


def test_metadata_encrypt_decrypt():
    metadata = {"nonce": "123", "tag": "abc", "kem": "Kyber"}
    encrypted = encrypt_metadata(metadata, TEST_PASSWORD)
    decrypted = decrypt_metadata(encrypted, TEST_PASSWORD)
    assert decrypted == metadata, "Metadata encryption/decryption failed"


# === Integration Tests ===
def test_full_encryption_decryption_flow():
    # Clean storage
    for f in os.listdir(STORAGE_DIR):
        os.remove(os.path.join(STORAGE_DIR, f))

    # Encrypt
    encrypt_message(TEST_MESSAGE, TEST_PASSWORD)

    # Verify files exist
    files = [f for f in os.listdir(STORAGE_DIR) if f.endswith(ENC_EXT)]
    metas = [f for f in os.listdir(STORAGE_DIR) if f.endswith(META_EXT)]
    assert files and metas, "Ciphertext and metadata files not created"

    # Decrypt
    try:
        decrypt_latest(TEST_PASSWORD)
    except Exception as e:
        pytest.fail(f"Decryption failed with error: {e}")


def test_decrypt_with_wrong_password():
    # Should raise exception or fail integrity
    with pytest.raises(Exception):
        decrypt_latest(WRONG_PASSWORD)


def test_metadata_tampering_detection():
    metas = sorted([f for f in os.listdir(STORAGE_DIR) if f.endswith(META_EXT)])
    meta_path = os.path.join(STORAGE_DIR, metas[-1])

    with open(meta_path, "r+") as f:
        content = json.load(f)
        content["nonce"] = base64.b64encode(b"fake_nonce").decode()
        f.seek(0)
        json.dump(content, f)
        f.truncate()

    with pytest.raises(Exception):
        decrypt_latest(TEST_PASSWORD)


def test_ciphertext_tampering_detection():
    files = sorted([f for f in os.listdir(STORAGE_DIR) if f.endswith(ENC_EXT)])
    enc_path = os.path.join(STORAGE_DIR, files[-1])

    with open(enc_path, "r+b") as f:
        f.seek(0)
        f.write(b"corrupt")

    with pytest.raises(Exception):
        decrypt_latest(TEST_PASSWORD)


def test_performance_benchmark():
    import time
    start = time.time()
    encrypt_message("Performance test message", TEST_PASSWORD)
    elapsed = time.time() - start
    assert elapsed < 10, "Encryption took too long (>10s)"


# === Anomaly & Security Checks ===
def test_entropy_and_anomaly_reporting(caplog):
    encrypt_message("1234567890////", TEST_PASSWORD)
    logs = caplog.text
    assert "Entropy" in logs or "Anomaly" in logs, "Anomaly detection log missing"