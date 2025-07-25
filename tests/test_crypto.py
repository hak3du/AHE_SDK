import os
import pytest
import time
from crypto.crypto import aes_encrypt, aes_decrypt

# Test 1: Basic AES Encryption-Decryption
def test_aes_encrypt_and_decrypt():
    key = os.urandom(32)  # AES-256 key
    plaintext = b"Adaptive Hashing Encryption - AES Test"

    ciphertext, nonce, tag = aes_encrypt(plaintext, key)
    decrypted = aes_decrypt(ciphertext, key, nonce, tag)

    assert decrypted == plaintext

# Test 2: Empty Message
def test_aes_encrypt_decrypt_empty_message():
    key = os.urandom(32)
    plaintext = b""

    ciphertext, nonce, tag = aes_encrypt(plaintext, key)
    decrypted = aes_decrypt(ciphertext, key, nonce, tag)

    assert decrypted == plaintext

# Test 3: Large Data (1 MB)
def test_aes_encrypt_decrypt_large_data():
    key = os.urandom(32)
    plaintext = os.urandom(1024 * 1024)  # 1 MB random data

    start = time.time()
    ciphertext, nonce, tag = aes_encrypt(plaintext, key)
    decrypted = aes_decrypt(ciphertext, key, nonce, tag)
    duration = time.time() - start

    assert decrypted == plaintext
    print(f"\n[PERF] 1MB AES-GCM Encrypt+Decrypt took {duration:.4f} seconds")

# Test 4: Wrong Key
def test_aes_decrypt_with_wrong_key():
    key = os.urandom(32)
    wrong_key = os.urandom(32)
    plaintext = b"Testing wrong key behavior"

    ciphertext, nonce, tag = aes_encrypt(plaintext, key)

    with pytest.raises(ValueError):
        aes_decrypt(ciphertext, wrong_key, nonce, tag)

# Test 5: Tampered Ciphertext
def test_aes_decrypt_with_tampered_ciphertext():
    key = os.urandom(32)
    plaintext = b"Testing tampered ciphertext"

    ciphertext, nonce, tag = aes_encrypt(plaintext, key)

    # Modify ciphertext
    tampered_ciphertext = bytearray(ciphertext)
    tampered_ciphertext[0] ^= 0x01  # Flip a bit

    with pytest.raises(ValueError):
        aes_decrypt(bytes(tampered_ciphertext), key, nonce, tag)