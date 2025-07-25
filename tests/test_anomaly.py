import unittest
from utils.anomaly import detect_anomaly, ENTROPY_WARN_THRESHOLD_LOW, ENTROPY_WARN_THRESHOLD_HIGH

class TestAnomalyDetection(unittest.TestCase):

    def test_no_anomaly_normal_entropy(self):
        # No suspicious chars, entropy in normal range
        input_str = "HelloWorld"
        entropy = (ENTROPY_WARN_THRESHOLD_LOW + ENTROPY_WARN_THRESHOLD_HIGH) / 2
        anomaly, reasons = detect_anomaly(input_str, entropy)
        self.assertFalse(anomaly)
        self.assertEqual(reasons, [])

    def test_suspicious_characters_only(self):
        # Suspicious chars present, entropy normal
        input_str = "Hello+World="
        entropy = (ENTROPY_WARN_THRESHOLD_LOW + ENTROPY_WARN_THRESHOLD_HIGH) / 2
        anomaly, reasons = detect_anomaly(input_str, entropy)
        self.assertTrue(anomaly)
        self.assertIn("Suspicious characters detected", reasons)
        self.assertNotIn("Entropy out of range", reasons)

    def test_entropy_too_low_only(self):
        # No suspicious chars, entropy too low
        input_str = "NormalText"
        entropy = ENTROPY_WARN_THRESHOLD_LOW - 0.1
        anomaly, reasons = detect_anomaly(input_str, entropy)
        self.assertTrue(anomaly)
        self.assertIn("Entropy out of range", reasons)
        self.assertNotIn("Suspicious characters detected", reasons)

    def test_entropy_too_high_only(self):
        # No suspicious chars, entropy too high
        input_str = "NormalText"
        entropy = ENTROPY_WARN_THRESHOLD_HIGH + 0.1
        anomaly, reasons = detect_anomaly(input_str, entropy)
        self.assertTrue(anomaly)
        self.assertIn("Entropy out of range", reasons)
        self.assertNotIn("Suspicious characters detected", reasons)

    def test_both_suspicious_chars_and_entropy_out_of_range(self):
        # Both conditions true
        input_str = "Bad+Text/=="
        entropy = ENTROPY_WARN_THRESHOLD_HIGH + 1.0
        anomaly, reasons = detect_anomaly(input_str, entropy)
        self.assertTrue(anomaly)
        self.assertIn("Suspicious characters detected", reasons)
        self.assertIn("Entropy out of range", reasons)

    def test_empty_input(self):
        # Empty string should not detect suspicious chars but entropy is 0 so out of range
        input_str = ""
        entropy = 0.0
        anomaly, reasons = detect_anomaly(input_str, entropy)
        self.assertTrue(anomaly)
        self.assertNotIn("Suspicious characters detected", reasons)
        self.assertIn("Entropy out of range", reasons)

    def test_exception_handling(self):
        # Simulate exception by passing wrong input type (int)
        anomaly, reasons = detect_anomaly(12345, 4.0)
        # Should handle exception and return False, []
        self.assertFalse(anomaly)
        self.assertEqual(reasons, [])

if __name__ == "__main__":
    unittest.main()