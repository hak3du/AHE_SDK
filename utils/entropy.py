import hashlib
import uuid
import platform
import os
import time
import socket
import math
from logger import logger

def calculate_shannon_entropy(data: bytes) -> float:
    try:
        if not data:
            logger.warning("Empty data passed to calculate_shannon_entropy")
            return 0.0
        freq = {b: data.count(b)/len(data) for b in set(data)}
        entropy = -sum(p * math.log2(p) for p in freq.values())
        logger.info(f"Calculated Shannon entropy: {entropy:.4f}")
        return entropy
    except Exception as e:
        logger.error(f"Error calculating Shannon entropy: {e}", exc_info=True)
        return 0.0

def get_environment_entropy() -> bytes:
    try:
        raw = (
            str(uuid.getnode()) +
            str(platform.system()) +
            str(platform.release()) +
            str(os.cpu_count()) +
            str(os.getpid()) +
            str(time.time()) +
            str(socket.gethostname())
        ).encode()
        entropy_bytes = hashlib.sha3_512(raw).digest()
        logger.info("Generated environment entropy bytes")
        return entropy_bytes
    except Exception as e:
        logger.error(f"Error generating environment entropy: {e}", exc_info=True)
        return b""