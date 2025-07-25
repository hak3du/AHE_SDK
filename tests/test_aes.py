import os
import pytest
from aes.aes import aes_encrypt, aes_decrypt

def test_aes_encrypt_and_decrypt():
    key = os.urandom(32)  # AES-256 key
    plaintext = "Adaptive Hashing Encryption - AES Test"

    # Encrypt
    bundle = aes_encrypt(plaintext, key)
    assert "ciphertext" in bundle
    assert "nonce" in bundle
    assert "tag" in bundle

    # Decrypt
    decrypted = aes_decrypt(bundle, key)
    assert decrypted == plaintext

def test_aes_encrypt_decrypt_empty_data():
    key = os.urandom(32)
    plaintext = ""

    bundle = aes_encrypt(plaintext, key)
    decrypted = aes_decrypt(bundle, key)
    assert decrypted == plaintext

def test_aes_encrypt_decrypt_large_data():
    key = os.urandom(32)
    plaintext = "A" * (1024 * 1024)  # 1 MB string

    bundle = aes_encrypt(plaintext, key)
    decrypted = aes_decrypt(bundle, key)
    assert decrypted == plaintext

def test_aes_decrypt_with_wrong_key():
    key = os.urandom(32)
    wrong_key = os.urandom(32)
    plaintext = "Testing wrong key behavior"

    bundle = aes_encrypt(plaintext, key)

    with pytest.raises(Exception):
        aes_decrypt(bundle, wrong_key)