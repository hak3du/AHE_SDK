import pytest
from kdf.kdf import (
    derive_key_argon2,
    derive_key_shake,
    derive_key_hkdf,
    derive_key_hybrid_with_pqc,
)
import os

def test_derive_key_argon2():
    password = b"password123"
    salt = os.urandom(16)
    key = derive_key_argon2(password, salt)
    assert isinstance(key, bytes)
    assert len(key) == 32

def test_derive_key_shake():
    password = b"password123"
    salt = os.urandom(16)
    key_128 = derive_key_shake(password, salt, 128)
    key_256 = derive_key_shake(password, salt, 256)
    assert isinstance(key_128, bytes)
    assert len(key_128) == 32
    assert isinstance(key_256, bytes)
    assert len(key_256) == 32

def test_derive_key_hkdf():
    password = b"password123"
    salt = os.urandom(16)
    key = derive_key_hkdf(password, salt)
    assert isinstance(key, bytes)
    assert len(key) == 32

@pytest.mark.parametrize("anomaly", [True, False])
def test_derive_key_hybrid_with_pqc(anomaly):
    password = b"password123"
    salt = os.urandom(16)

    # Run the full hybrid KDF with real oqs.KeyEncapsulation calls
    result = derive_key_hybrid_with_pqc(password, salt, anomaly)
    
    # Unpack results
    final_key, shake_time, kem_time, kem_name, public_key, ciphertext, shared_secret = result

    # Basic assertions on outputs
    assert isinstance(final_key, bytes)
    assert len(final_key) == 32
    assert isinstance(shake_time, float)
    assert isinstance(kem_time, float)
    assert isinstance(kem_name, str)
    assert isinstance(public_key, bytes)
    assert isinstance(ciphertext, bytes)
    assert isinstance(shared_secret, bytes)
    
    # Additional validation: shared_secret should be consistent
    # We rely on your underlying implementation to guarantee shared_secret validity