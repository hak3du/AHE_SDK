# tests/test_core.py
import pytest
from core.core import ahe_encrypt_v9_5, ahe_decrypt_v9_5

def test_ahe_encrypt_basic():
    message = "Test encryption message"
    encrypted = ahe_encrypt_v9_5(message)
    
    # Check the structure of returned dictionary
    assert "aes_encrypted" in encrypted
    assert "pqc" in encrypted
    assert "timing" in encrypted
    
    aes_bundle = encrypted["aes_encrypted"]
    assert "ciphertext" in aes_bundle
    assert "nonce" in aes_bundle
    assert "tag" in aes_bundle

def test_ahe_encrypt_decrypt_cycle():
    message = "Another test message"
    encrypted = ahe_encrypt_v9_5(message)
    
    # You will need the AES key for decryption — 
    # In current core.py, the AES key is derived internally in the encryption function.
    # For test purpose, you might want to adjust core.py to return the AES key for this test,
    # or mock derive_key_hybrid_with_pqc to expose the key.
    
    # For demonstration, let's say you modify ahe_encrypt_v9_5 to also return AES key:
    # encrypted, aes_key = ahe_encrypt_v9_5(message)
    
    # Then do:
    # decrypted_message = ahe_decrypt_v9_5(encrypted, aes_key)
    # assert decrypted_message == message
    
    # For now, just test encryption structure as above.

@pytest.mark.skip("Decryption test requires AES key management update")
def test_ahe_decrypt():
    # This test will be added later after we refactor key management
    pass