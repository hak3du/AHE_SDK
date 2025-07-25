import hashlib
import random
from logger import logger

HASH_ALGORITHMS = [
    "sha256",
    "sha512",
    "sha3_256",
    "sha3_512"
]

def hash_stage(data: bytes, algo: str) -> bytes:
    try:
        h = hashlib.new(algo)
        h.update(data)
        logger.info(f"Hashed data using {algo}")
        return h.digest()
    except Exception as e:
        logger.error(f"Error hashing data with {algo}: {e}", exc_info=True)
        return b""

def multi_stage_hash(data: bytes, extra_entropy: bytes) -> bytes:
    try:
        output = data
        shuffled_algos = random.sample(HASH_ALGORITHMS, len(HASH_ALGORITHMS))
        logger.info(f"Hash algorithms order: {shuffled_algos}")
        for algo in shuffled_algos:
            output = hash_stage(output + extra_entropy, algo)
        logger.info("Completed multi-stage hashing")
        return output
    except Exception as e:
        logger.error(f"Error in multi_stage_hash: {e}", exc_info=True)
        return b""