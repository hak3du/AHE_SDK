import oqs
import time
import random
from logger import logger

# PQC KEM groups for selection
PQC_FAST_KEMS = ["Kyber512", "Kyber768", "ML-KEM-512", "ML-KEM-768"]
PQC_STRONG_KEMS = ["Kyber1024", "sntrup761", "ML-KEM-1024"]

def pqc_keypair(kem_name: str):
    logger.info(f"Generating keypair for PQC KEM: {kem_name}")
    kem = oqs.KeyEncapsulation(kem_name)
    public_key = kem.generate_keypair()
    logger.info(f"Keypair generated for PQC KEM: {kem_name}")
    return kem, public_key

def pqc_encapsulate(kem, public_key: bytes):
    logger.info("Starting PQC encapsulation")
    ct, ss = kem.encap_secret(public_key)
    logger.info("PQC encapsulation completed")
    return ct, ss

def pqc_decapsulate(kem, ciphertext: bytes):
    logger.info("Starting PQC decapsulation")
    ss = kem.decap_secret(ciphertext)
    logger.info("PQC decapsulation completed")
    return ss

def pqc_select_and_run(anomaly: bool):
    pqc_candidates = PQC_STRONG_KEMS.copy() if anomaly else PQC_FAST_KEMS.copy()
    random.shuffle(pqc_candidates)

    for kem_name in pqc_candidates:
        try:
            logger.info(f"Trying PQC KEM: {kem_name}")
            start = time.time()
            kem, public_key = pqc_keypair(kem_name)
            ciphertext, shared_secret = pqc_encapsulate(kem, public_key)
            shared_secret_check = pqc_decapsulate(kem, ciphertext)
            elapsed = time.time() - start

            if shared_secret != shared_secret_check:
                raise ValueError("Shared secrets do not match.")

            logger.info(f"PQC KEM {kem_name} success in {elapsed:.6f}s")
            return kem_name, public_key, ciphertext, shared_secret

        except Exception as e:
            logger.error(f"PQC KEM {kem_name} failed: {e}", exc_info=True)

    logger.error("All PQC KEM attempts failed.")
    raise RuntimeError("All PQC KEM attempts failed.")