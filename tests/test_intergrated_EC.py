import unittest
import time
from core.core import ahe_encrypt_v9_5

class TestIntegratedEC(unittest.TestCase):
    """Integration Test: Full AHE Encryption Pipeline Only"""

    def test_full_encryption_pipeline(self):
        message = "The future of cryptography is adaptive and quantum-secure."
        print("\n=== Running AHE v9.5 Encryption Pipeline Test ===")
        print(f"🔹 Input Message: {message}")

        start_time = time.time()
        result = ahe_encrypt_v9_5(message)
        elapsed_time = time.time() - start_time

        # ✅ Basic Structure Checks
        self.assertIsInstance(result, dict)
        self.assertIn("aes_encrypted", result)
        self.assertIn("ciphertext", result["aes_encrypted"])
        self.assertIn("nonce", result["aes_encrypted"])
        self.assertIn("tag", result["aes_encrypted"])
        self.assertIn("pqc", result)

        # ✅ Print Results for Demonstration
        print("\n--- Encryption Output ---")
        print(f"AES Ciphertext: {result['aes_encrypted']['ciphertext'][:40]}...")
        print(f"Nonce: {result['aes_encrypted']['nonce']}")
        print(f"Tag: {result['aes_encrypted']['tag']}")
        print("\n--- PQC Metadata ---")
        print(f"KEM: {result['pqc']['kem_name']}")
        print(f"Public Key (short): {result['pqc']['public_key']}")
        print(f"Ciphertext (short): {result['pqc']['ciphertext']}")
        print(f"Shared Secret (short): {result['pqc']['shared_secret']}")
        print(f"\n✅ Encryption pipeline executed successfully in {elapsed_time:.4f}s")

if __name__ == "__main__":
    unittest.main(verbosity=2)