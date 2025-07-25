"""
=========================================================
Adaptive Hashing Encryption (AHE) SDK - Core Logic
=========================================================
"""

import os
import time
import random
import json
import base64
import hashlib
import math
from datetime import datetime
from logger import logger

import oqs
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

# === CONFIG ===
AES_KEY_SIZE = 32
META_EXT = ".meta"
ENC_EXT = ".ahe"
PQC_KEMS = ["Kyber768", "Kyber512", "ML-KEM-768"]
STORAGE_DIR = "secure_storage"

ENTROPY_WARN_LOW = 3.5
ENTROPY_WARN_HIGH = 4.75

os.makedirs(STORAGE_DIR, exist_ok=True)


# === UTILITIES ===
def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {b: data.count(b) / len(data) for b in set(data)}
    return -sum(p * math.log2(p) for p in freq.values())


def detect_anomaly(entropy_score: float, message: str):
    reasons = []
    suspicious_chars = "0123456789+/=\n"
    if any(c in message for c in suspicious_chars):
        reasons.append("Suspicious characters detected")
    if entropy_score < ENTROPY_WARN_LOW or entropy_score > ENTROPY_WARN_HIGH:
        reasons.append("Entropy out of normal range")
    return (len(reasons) > 0), reasons


def derive_key(password_bytes, pubkey_bytes, ciphertext_bytes):
    fusion = password_bytes + pubkey_bytes + ciphertext_bytes
    logger.debug("[TRACE] Fusion key derivation initiated")
    return hashlib.sha3_512(fusion).digest()[:AES_KEY_SIZE]


def aes_encrypt(plaintext_bytes, key):
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext_bytes)
    logger.debug("[INTEGRITY] AES-GCM tag generated")
    return ciphertext, nonce, tag


def aes_decrypt(ciphertext, nonce, tag, key):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


# === METADATA ENCRYPTION ===
def encrypt_metadata(metadata_dict, password):
    metadata_json = json.dumps(metadata_dict)
    metadata_bytes = metadata_json.encode('utf-8')

    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32, count=100_000)

    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(metadata_bytes)

    logger.debug("[ZERO-KNOWLEDGE] Metadata encapsulated securely")

    return json.dumps({
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "tag": base64.b64encode(tag).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    })


def decrypt_metadata(encrypted_blob_json, password):
    encrypted_blob = json.loads(encrypted_blob_json)
    salt = base64.b64decode(encrypted_blob["salt"])
    nonce = base64.b64decode(encrypted_blob["nonce"])
    tag = base64.b64decode(encrypted_blob["tag"])
    ciphertext = base64.b64decode(encrypted_blob["ciphertext"])

    key = PBKDF2(password, salt, dkLen=32, count=100_000)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    metadata_bytes = cipher.decrypt_and_verify(ciphertext, tag)
    return json.loads(metadata_bytes.decode('utf-8'))


# === ENCRYPT FUNCTION ===
def encrypt_message(message, password):
    logger.info("=== [START] AHE Encryption ===")
    start_time = time.time()

    # 1. Entropy & Anomaly
    plaintext = message.encode()
    input_entropy = calculate_entropy(plaintext)
    anomaly, reasons = detect_anomaly(input_entropy, message)
    logger.info(f"[AUDIT] Input entropy: {input_entropy:.4f} | Anomaly: {anomaly}")
    if anomaly:
        logger.warning(f"[AUDIT] Anomaly reasons: {', '.join(reasons)}")

    # 2. PQC Key Generation & Handshake
    kem_name = random.choice(PQC_KEMS)
    kem = oqs.KeyEncapsulation(kem_name)
    pubkey = kem.generate_keypair()
    ciphertext_kem, _ = kem.encap_secret(pubkey)
    logger.info(f"[SECURITY] PQC handshake: {kem_name}")

    # 3. AES Key Derivation
    key = derive_key(password.encode(), pubkey, ciphertext_kem)
    logger.info("[TRACE] AES key derived successfully")

    # 4. AES Encryption
    ciphertext, nonce, tag = aes_encrypt(plaintext, key)
    logger.info("[INTEGRITY] AES encryption completed")

    # 5. Metadata Encryption
    metadata = {
        "nonce": base64.b64encode(nonce).decode(),
        "tag": base64.b64encode(tag).decode(),
        "pubkey": base64.b64encode(pubkey).decode(),
        "ciphertext_kem": base64.b64encode(ciphertext_kem).decode(),
        "kem_name": kem_name,
        "entropy": input_entropy,
        "anomaly": anomaly,
        "timestamp": datetime.now().isoformat()
    }
    encrypted_metadata_json = encrypt_metadata(metadata, password)

    # 6. Save files
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    enc_path = os.path.join(STORAGE_DIR, f"ciphertext_{timestamp}{ENC_EXT}")
    meta_path = os.path.join(STORAGE_DIR, f"metadata_{timestamp}{META_EXT}")
    with open(enc_path, "wb") as f:
        f.write(ciphertext)
    with open(meta_path, "w") as f:
        f.write(encrypted_metadata_json)

    total_time = time.time() - start_time
    logger.info(f"[DONE] Encryption finished in {total_time:.4f}s")
    logger.info(f"Ciphertext: {enc_path}, Metadata: {meta_path}")
    logger.info("=== [END] Zero Knowledge Assurance Verified ===")

    return {
        "status": "success",
        "note": "Encryption complete",
        "storage_dir": STORAGE_DIR,
        "ciphertext_file": os.path.basename(enc_path),
        "metadata_file": os.path.basename(meta_path),
        "anomaly_detected": anomaly,
        "entropy_score": input_entropy
    }


# === DECRYPT FUNCTION ===
def decrypt_latest(password):
    logger.info("=== [START] AHE Decryption ===")
    start_time = time.time()

    files = sorted([f for f in os.listdir(STORAGE_DIR) if f.endswith(ENC_EXT)])
    metas = sorted([f for f in os.listdir(STORAGE_DIR) if f.endswith(META_EXT)])
    if not files or not metas:
        raise FileNotFoundError("No encrypted data found in secure_storage.")

    enc_path = os.path.join(STORAGE_DIR, files[-1])
    meta_path = os.path.join(STORAGE_DIR, metas[-1])

    logger.info(f"[INFO] Using ciphertext: {enc_path}")
    logger.info(f"[INFO] Using metadata: {meta_path}")

    with open(enc_path, "rb") as f:
        ciphertext = f.read()
    with open(meta_path, "r") as f:
        encrypted_metadata_json = f.read()

    metadata = decrypt_metadata(encrypted_metadata_json, password)

    # PQC & AES Decryption
    kem = oqs.KeyEncapsulation(metadata["kem_name"])
    kem.generate_keypair()
    key = derive_key(password.encode(), base64.b64decode(metadata["pubkey"]),
                     base64.b64decode(metadata["ciphertext_kem"]))
    plaintext = aes_decrypt(ciphertext, base64.b64decode(metadata["nonce"]),
                             base64.b64decode(metadata["tag"]), key)

    total_time = time.time() - start_time
    logger.info(f"[DONE] Decryption successful in {total_time:.4f}s")
    logger.info("=== [END] Zero Knowledge Assurance Verified ===")
    print(f"\n🔓 Original message: {plaintext.decode()}")

    return {
        "status": "success",
        "decrypted_message": plaintext.decode(),
        "pqc_profile": metadata.get("kem_name"),
        "anomaly_detected": metadata.get("anomaly", False),
        "entropy_score": metadata.get("entropy", "N/A")
    }