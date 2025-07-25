# tests/test_integration.py
import unittest
from core.core import ahe_encrypt_v9_5

class TestAHEPipeline(unittest.TestCase):
    def test_encryption_pipeline(self):
        message = "Hello Adaptive Hashing Encryption!"  # Test input
        result = ahe_encrypt_v9_5(message)

        # Validate result structure
        self.assertIn("aes_encrypted", result)
        self.assertIn("pqc", result)
        self.assertIn("timing", result)

        # Check AES structure
        aes_bundle = result["aes_encrypted"]
        self.assertIn("ciphertext", aes_bundle)
        self.assertIn("nonce", aes_bundle)
        self.assertIn("tag", aes_bundle)

        # Check PQC structure
        pqc_data = result["pqc"]
        self.assertIn("kem_name", pqc_data)
        self.assertIn("public_key", pqc_data)
        self.assertIn("ciphertext", pqc_data)
        self.assertIn("shared_secret", pqc_data)

        print("\n✅ Encryption pipeline test completed successfully.")
        print(f"AES Ciphertext: {aes_bundle['ciphertext'][:20]}...")
        print(f"PQC KEM: {pqc_data['kem_name']}")

if __name__ == "__main__":
    unittest.main()