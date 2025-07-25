import hashlib
import hmac
import random
import time
import oqs
from argon2.low_level import hash_secret_raw, Type
from logger import logger

AES_KEY_SIZE = 32

# === Key Derivation Functions ===

def derive_key_argon2(password: bytes, salt: bytes) -> bytes:
    logger.info("Starting Argon2id key derivation")
    try:
        key = hash_secret_raw(
            secret=password,
            salt=salt,
            time_cost=4,
            memory_cost=102400,
            parallelism=8,
            hash_len=AES_KEY_SIZE,
            type=Type.ID
        )
        logger.info("Argon2id key derivation completed")
        return key
    except Exception as e:
        logger.error(f"Argon2id derivation failed: {e}", exc_info=True)
        raise

def derive_key_shake(password: bytes, salt: bytes, bits: int=256) -> bytes:
    logger.info(f"Starting SHAKE-{bits} key derivation")
    try:
        shake = hashlib.shake_128() if bits == 128 else hashlib.shake_256()
        shake.update(password + salt)
        key = shake.digest(AES_KEY_SIZE)
        logger.info(f"SHAKE-{bits} key derivation completed")
        return key
    except Exception as e:
        logger.error(f"SHAKE-{bits} derivation failed: {e}", exc_info=True)
        raise

def hkdf_extract(salt: bytes, input_key_material: bytes, hash_algo=hashlib.sha256) -> bytes:
    return hmac.new(salt, input_key_material, hash_algo).digest()

def hkdf_expand(prk: bytes, info: bytes, length: int, hash_algo=hashlib.sha256) -> bytes:
    hash_len = hash_algo().digest_size
    blocks_needed = (length + hash_len - 1) // hash_len
    okm = b""
    output_block = b""
    for counter in range(1, blocks_needed + 1):
        output_block = hmac.new(prk, output_block + info + bytes([counter]), hash_algo).digest()
        okm += output_block
    return okm[:length]

def derive_key_hkdf(password: bytes, salt: bytes) -> bytes:
    logger.info("Starting HKDF key derivation")
    try:
        prk = hkdf_extract(salt, password)
        key = hkdf_expand(prk, b"AHE-HKDF", AES_KEY_SIZE)
        logger.info("HKDF key derivation completed")
        return key
    except Exception as e:
        logger.error(f"HKDF derivation failed: {e}", exc_info=True)
        raise

# === Hybrid Key Derivation with PQC Integration ===

def derive_key_hybrid_with_pqc(password: bytes, salt: bytes, anomaly: bool) -> tuple:
    PQC_FAST_KEMS = ["Kyber512", "Kyber768", "ML-KEM-512", "ML-KEM-768"]
    PQC_STRONG_KEMS = ["Kyber1024", "sntrup761", "ML-KEM-1024"]

    if anomaly:
        pqc_candidates = PQC_STRONG_KEMS.copy()
    else:
        pqc_candidates = PQC_FAST_KEMS.copy()

    random.shuffle(pqc_candidates)

    try:
        if anomaly:
            if random.choice([True, False]):
                logger.info("Anomaly detected: Using Argon2id for initial KDF")
                intermediate_key = derive_key_argon2(password, salt)
            else:
                bits = random.choice([128, 256])
                logger.info(f"Anomaly detected: Using SHAKE-{bits} for initial KDF")
                intermediate_key = derive_key_shake(password, salt, bits)
        else:
            logger.info("No anomaly: Using HKDF for initial KDF")
            intermediate_key = derive_key_hkdf(password, salt)

        start_shake_final = time.time()
        final_key = hashlib.shake_256(intermediate_key).digest(AES_KEY_SIZE)
        shake_final_time = time.time() - start_shake_final
        logger.info(f"Final SHAKE-256 encapsulation completed in {shake_final_time:.6f}s")

        for kem_name in pqc_candidates:
            try:
                logger.info(f"Trying PQC KEM: {kem_name}")
                start_kem = time.time()
                kem = oqs.KeyEncapsulation(kem_name)
                public_key = kem.generate_keypair()
                ciphertext, shared_secret = kem.encap_secret(public_key)
                shared_secret_check = kem.decap_secret(ciphertext)
                kem_time = time.time() - start_kem

                if shared_secret != shared_secret_check:
                    raise ValueError("Shared secrets do not match.")

                logger.info(f"PQC KEM {kem_name} success in {kem_time:.6f}s")
                return final_key, shake_final_time, kem_time, kem_name, public_key, ciphertext, shared_secret

            except Exception as e:
                logger.error(f"PQC KEM {kem_name} failed: {e}", exc_info=True)

        raise RuntimeError("All PQC KEM attempts failed")

    except Exception as e:
        logger.error(f"Hybrid KDF with PQC failed: {e}", exc_info=True)
        raise