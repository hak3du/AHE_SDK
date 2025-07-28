import os

# === Folder structure ===
folders = [
    "AHE_SDK/core",
    "AHE_SDK/utils",
    "AHE_SDK/pqc",
    "AHE_SDK/kdf",
    "AHE_SDK/aes",
]

# === Files and their content ===
files_content = {
    "AHE_SDK/core/main.py": """\
from core.crypto import ahe_encrypt_v9_5
import sys

def main():
    print("=== Adaptive Hashing Encryption (AHE) v9.5 SDK ===")
    message = input("Enter message to encrypt: ")
    encrypted = ahe_encrypt_v9_5(message)
    print("\\n--- Encrypted Output ---")
    print(encrypted)

if _name_ == "_main_":
    main()
""",

    "AHE_SDK/core/crypto.py": """\
# === Adaptive Hashing Encryption (AHE) v9.5 ===
import hashlib
import secrets
import time
import math
import random
import os
import platform
import socket
import uuid
import hmac
from base64 import urlsafe_b64encode, urlsafe_b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from argon2.low_level import hash_secret_raw, Type
import oqs

ENTROPY_WARN_THRESHOLD_LOW = 3.5
ENTROPY_WARN_THRESHOLD_HIGH = 4.75
AES_KEY_SIZE = 32

HASH_ALGORITHMS = ["sha256", "sha512", "sha3_256", "sha3_512"]
PQC_FAST_KEMS = ["Kyber512", "Kyber768", "ML-KEM-512", "ML-KEM-768"]
PQC_STRONG_KEMS = ["Kyber1024", "sntrup761", "ML-KEM-1024"]

def calculate_shannon_entropy(data: bytes) -> float:
    if not data: return 0.0
    freq = {b: data.count(b)/len(data) for b in set(data)}
    return -sum(p * math.log2(p) for p in freq.values())

def get_environment_entropy() -> bytes:
    raw = (str(uuid.getnode())+str(platform.system())+str(platform.release())+
           str(os.cpu_count())+str(os.getpid())+str(time.time())+
           str(socket.gethostname())).encode()
    return hashlib.sha3_512(raw).digest()

def detect_anomaly(input_data: str, entropy_score: float) -> tuple:
    suspicious_chars = "0123456789+/=\\n"
    reasons = []
    if any(c in input_data for c in suspicious_chars):
        reasons.append("suspicious characters detected")
    if entropy_score < ENTROPY_WARN_THRESHOLD_LOW or entropy_score > ENTROPY_WARN_THRESHOLD_HIGH:
        reasons.append("entropy out of range")
    return (len(reasons) > 0), reasons

def hash_stage(data: bytes, algo: str) -> bytes:
    h = hashlib.new(algo)
    h.update(data)
    return h.digest()

def aes_encrypt(message: str, key: bytes) -> dict:
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return {
        "ciphertext": urlsafe_b64encode(ciphertext).decode(),
        "nonce": urlsafe_b64encode(nonce).decode(),
        "tag": urlsafe_b64encode(tag).decode()
    }

def aes_decrypt(bundle: dict, key: bytes) -> str:
    nonce = urlsafe_b64decode(bundle["nonce"])
    tag = urlsafe_b64decode(bundle["tag"])
    ciphertext = urlsafe_b64decode(bundle["ciphertext"])
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

def derive_key_argon2(password: bytes, salt: bytes) -> bytes:
    return hash_secret_raw(secret=password, salt=salt, time_cost=4, memory_cost=102400,
                           parallelism=8, hash_len=AES_KEY_SIZE, type=Type.ID)

def derive_key_shake(password: bytes, salt: bytes, bits: int=256) -> bytes:
    shake = hashlib.shake_128() if bits == 128 else hashlib.shake_256()
    shake.update(password + salt)
    return shake.digest(AES_KEY_SIZE)

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
    prk = hkdf_extract(salt, password)
    return hkdf_expand(prk, b"AHE-HKDF", AES_KEY_SIZE)

def pqc_keypair(kem_name: str):
    kem = oqs.KeyEncapsulation(kem_name)
    public_key = kem.generate_keypair()
    return kem, public_key

def pqc_encapsulate(kem, public_key: bytes):
    return kem.encap_secret(public_key)

def pqc_decapsulate(kem, ciphertext: bytes):
    return kem.decap_secret(ciphertext)

def derive_key_hybrid_with_pqc(password: bytes, salt: bytes, anomaly: bool) -> tuple:
    pqc_candidates = PQC_STRONG_KEMS.copy() if anomaly else PQC_FAST_KEMS.copy()
    random.shuffle(pqc_candidates)
    if anomaly:
        if random.choice([True, False]):
            intermediate_key = derive_key_argon2(password, salt)
        else:
            intermediate_key = derive_key_shake(password, salt, random.choice([128,256]))
    else:
        intermediate_key = derive_key_hkdf(password, salt)
    final_key = hashlib.shake_256(intermediate_key).digest(AES_KEY_SIZE)
    for kem_name in pqc_candidates:
        try:
            kem, public_key = pqc_keypair(kem_name)
            ciphertext, shared_secret = pqc_encapsulate(kem, public_key)
            shared_secret_check = pqc_decapsulate(kem, ciphertext)
            if shared_secret != shared_secret_check:
                raise ValueError("Shared secrets do not match.")
            return final_key, kem_name
        except Exception as e:
            continue
    raise RuntimeError("All PQC KEM attempts failed")

def ahe_encrypt_v9_5(message: str) -> dict:
    input_bytes = message.encode()
    input_entropy = calculate_shannon_entropy(input_bytes)
    system_entropy = get_environment_entropy()
    fused_input = bytes(a ^ b for a, b in zip(input_bytes, system_entropy[:len(input_bytes)]))
    anomaly, reasons = detect_anomaly(message, input_entropy)
    output = fused_input
    for algo in random.sample(HASH_ALGORITHMS, len(HASH_ALGORITHMS)):
        output = hash_stage(output + system_entropy, algo)
    salt = system_entropy[:16]
    password = output[:32]
    aes_key, kem_name = derive_key_hybrid_with_pqc(password, salt, anomaly)
    aes_bundle = aes_encrypt(message, aes_key)
    return {
        "aes_encrypted": aes_bundle,
        "kem": kem_name,
        "anomaly": anomaly,
        "reasons": reasons if anomaly else []
    }
"""
}

# === Create structure and write files ===
for folder in folders:
    os.makedirs(folder, exist_ok=True)

for file_path, content in files_content.items():
    with open(file_path, "w") as f:
        f.write(content)

print("✅ AHE_SDK fully built with complete logic!")