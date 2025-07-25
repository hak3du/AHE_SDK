import unittest
from unittest.mock import patch
from utils import entropy
import os

class TestEntropyFunctions(unittest.TestCase):

    def test_calculate_shannon_entropy_normal(self):
        data = b"aaaabbbbccccdddd"
        entropy_val = entropy.calculate_shannon_entropy(data)
        self.assertGreater(entropy_val, 0)
        self.assertLessEqual(entropy_val, 4)

    def test_calculate_shannon_entropy_empty(self):
        data = b""
        entropy_val = entropy.calculate_shannon_entropy(data)
        self.assertEqual(entropy_val, 0)

    def test_calculate_shannon_entropy_uniform(self):
        data = b"aaaaaaaaaaaaaaa"
        entropy_val = entropy.calculate_shannon_entropy(data)
        self.assertEqual(entropy_val, 0)

    def test_calculate_shannon_entropy_high_entropy(self):
        data = os.urandom(1024)
        entropy_val = entropy.calculate_shannon_entropy(data)
        self.assertGreater(entropy_val, 7)

    def test_get_environment_entropy_length(self):
        env_entropy = entropy.get_environment_entropy()
        self.assertIsInstance(env_entropy, bytes)
        self.assertEqual(len(env_entropy), 64)

    @patch('utils.entropy.hashlib.sha3_512')
    def test_get_environment_entropy_exception(self, mock_sha3):
        mock_sha3.side_effect = Exception("Hash failure")
        result = entropy.get_environment_entropy()
        self.assertEqual(result, b"")

    @patch('utils.entropy.math.log2')
    def test_calculate_shannon_entropy_exception(self, mock_log2):
        mock_log2.side_effect = Exception("Math error")
        result = entropy.calculate_shannon_entropy(b"testdata")
        self.assertEqual(result, 0.0)

if __name__ == "__main__":
    unittest.main()