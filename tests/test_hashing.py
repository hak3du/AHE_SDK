"""
================================================================================
Adaptive Hashing Module for AHE (Adaptive Hashing Encryption)
================================================================================

PURPOSE:
--------
This module provides secure, multi-stage, and randomized hashing operations 
used in the Adaptive Hashing Encryption (AHE) framework. It introduces 
unpredictability and adaptive behavior to strengthen against modern attack vectors.

WHAT MAKES THIS DIFFERENT:
--------------------------
1. *Multi-Stage Hashing with Randomized Algorithm Order*
   - Unlike traditional hashing which uses a fixed algorithm, this approach 
     applies multiple hash algorithms in random order for each encryption event.
   - Algorithms include SHA-256, SHA-512, SHA3-256, and SHA3-512.
   - This randomness ensures that even if the same input is hashed twice, 
     the resulting digest differs, adding unpredictability.

2. *Entropy Fusion*
   - Before hashing, additional entropy (e.g., environment-based entropy or 
     dynamic system values) can be mixed into the data, reducing predictability 
     and increasing resistance to preimage and collision attacks.

3. *Variable Final Digest Length*
   - The final digest size is *non-deterministic* because it depends on the 
     last algorithm in the random sequence. For example:
       - If sha256 is last → 32 bytes
       - If sha512 is last → 64 bytes
       - If sha3_256 is last → 32 bytes
       - If sha3_512 is last → 64 bytes
   - This unpredictability further strengthens security, as attackers cannot 
     infer algorithm usage based on digest length patterns.

4. *Determinism Achieved Through Reproducibility*
   - In production, determinism between sender and receiver does NOT rely on 
     fixed lengths. Instead, both parties execute the exact same algorithm 
     order (synchronized by shared randomness or a KDF process), guaranteeing 
     matching results without exposing internal sequences.

SECURITY BENEFITS:
-------------------
- Eliminates predictability of fixed hash chains.
- Adds layers of protection against quantum and classical attacks.
- Resistant to rainbow tables and dictionary attacks because output space 
  expands exponentially due to random permutations of algorithms.

FUNCTIONS:
----------
- hash_stage(data: bytes, algo: str) -> bytes
    Performs a single hash using the specified algorithm.

- multi_stage_hash(data: bytes, extra_entropy: bytes) -> bytes
    Applies multiple hashing stages in random order, mixing entropy each time.

NOTES:
------
- Logging is enabled for debugging but should be disabled or minimized in 
  production to avoid leaking cryptographic process details.
- The randomness is sourced from Python's random module; for cryptographic 
  randomness, consider secrets for key material.
"""

import unittest
import hashlib
import random
from unittest.mock import patch
from utils.hashing import hash_stage, multi_stage_hash, HASH_ALGORITHMS

class TestHashingFunctions(unittest.TestCase):

    def test_hash_stage_sha256(self):
        data = b"test"
        result = hash_stage(data, "sha256")
        self.assertEqual(len(result), hashlib.sha256().digest_size)
        self.assertIsInstance(result, bytes)

    def test_hash_stage_sha512(self):
        data = b"test"
        result = hash_stage(data, "sha512")
        self.assertEqual(len(result), hashlib.sha512().digest_size)
        self.assertIsInstance(result, bytes)

    def test_hash_stage_invalid_algorithm(self):
        data = b"test"
        result = hash_stage(data, "invalid_algo")
        self.assertEqual(result, b"", "Invalid algorithm should return empty bytes")

    def test_multi_stage_hash_empty_data(self):
        extra_entropy = b"entropy"
        result = multi_stage_hash(b"", extra_entropy)
        self.assertNotEqual(result, b"", "Result should not be empty even if data is empty")

    def test_multi_stage_hash_empty_entropy(self):
        data = b"test"
        result = multi_stage_hash(data, b"")
        self.assertNotEqual(result, b"", "Result should not be empty even if entropy is empty")

    def test_multi_stage_hash_length(self):
        data = b"test"
        extra_entropy = b"entropy"
        result = multi_stage_hash(data, extra_entropy)

        # Valid lengths based on supported algorithms
        valid_lengths = [hashlib.new(algo).digest_size for algo in HASH_ALGORITHMS]
        self.assertIn(len(result), valid_lengths, f"Unexpected digest length: {len(result)}")

    def test_multi_stage_hash_deterministic_order(self):
        # Force deterministic order using patch
        fixed_order = HASH_ALGORITHMS[:]  # Original order
        data = b"test"
        extra_entropy = b"entropy"

        with patch("random.sample", return_value=fixed_order):
            result1 = multi_stage_hash(data, extra_entropy)
            result2 = multi_stage_hash(data, extra_entropy)
            self.assertEqual(result1, result2, "Results should be identical when algorithm order is fixed")

if __name__ == "__main__":
    unittest.main()