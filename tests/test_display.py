"""
================================================================================
Test Suite for Display Utilities
================================================================================

This module tests the shorten_bytes_for_display function in display.py.

PURPOSE:
--------
Ensure that byte data is safely and correctly shortened for display purposes 
without altering the core integrity of the original data, and that edge cases 
and error handling work as intended.

TEST COVERAGE:
--------------
1. Display full hex when data length ≤ limit.
2. Display truncated hex when data length > limit.
3. Handle empty byte input gracefully.
4. Handle invalid input type without crashing.
5. Validate proper truncation behavior for exact boundary cases.
"""

import unittest
from utils.display import shorten_bytes_for_display

class TestDisplayUtils(unittest.TestCase):

    def test_full_display_when_length_is_small(self):
        data = b"\x01\x02\x03"
        result = shorten_bytes_for_display(data, length=10)
        self.assertEqual(result, data.hex())

    def test_truncated_display_when_length_is_large(self):
        data = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C"
        result = shorten_bytes_for_display(data, length=5)
        expected_prefix = data[:5].hex() + "..."
        self.assertEqual(result, expected_prefix)

    def test_empty_bytes(self):
        data = b""
        result = shorten_bytes_for_display(data, length=10)
        self.assertEqual(result, "")

    def test_invalid_input_type(self):
        result = shorten_bytes_for_display("not_bytes", length=5)
        self.assertEqual(result, "")

    def test_exact_boundary_behavior(self):
        data = b"\x01\x02\x03\x04\x05"
        result = shorten_bytes_for_display(data, length=5)
        # Since length == data length, should return full hex (no truncation)
        self.assertEqual(result, data.hex())

if __name__ == "__main__":
    unittest.main()