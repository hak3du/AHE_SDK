from logger import logger

ENTROPY_WARN_THRESHOLD_LOW = 3.5
ENTROPY_WARN_THRESHOLD_HIGH = 4.75

def detect_anomaly(input_data: str, entropy_score: float) -> tuple:
    try:
        suspicious_chars = "0123456789+/=\n"
        reasons = []

        if any(c in input_data for c in suspicious_chars):
            reasons.append("Suspicious characters detected")
            logger.info("Anomaly check: Suspicious characters detected.")

        if entropy_score < ENTROPY_WARN_THRESHOLD_LOW or entropy_score > ENTROPY_WARN_THRESHOLD_HIGH:
            reasons.append("Entropy out of range")
            logger.info(f"Anomaly check: Entropy score {entropy_score} out of range.")

        anomaly_detected = len(reasons) > 0
        logger.info(f"Anomaly detection result: {anomaly_detected} with reasons: {reasons}")

        return anomaly_detected, reasons

    except Exception as e:
        logger.error(f"Error during anomaly detection: {e}", exc_info=True)
        # On error, return no anomaly but log error
        return False, []