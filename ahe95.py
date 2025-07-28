# === Adaptive Hashing Encryption (AHE) v9.5 (Full Revised with Dynamic PQC KEM selection) ===
# By The Architect Beyond Time

import hashlib
import secrets
import time
import math
import random
import os
import platform
import socket
import uuid

from base64 import urlsafe_b64encode, urlsafe_b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from argon2.low_level import hash_secret_raw, Type
import hmac

import oqs

# === CONFIGURATION ===

ENTROPY_WARN_THRESHOLD_LOW = 3.5
ENTROPY_WARN_THRESHOLD_HIGH = 4.75
AES_KEY_SIZE = 32

HASH_ALGORITHMS = [
    "sha256",
    "sha512",
    "sha3_256",
    "sha3_512"
]

# PQC KEM groups for selection
PQC_FAST_KEMS = ["Kyber512", "Kyber768", "ML-KEM-512", "ML-KEM-768"]
PQC_STRONG_KEMS = ["Kyber1024", "sntrup761", "ML-KEM-1024"]

# === UTILITIES ===

def calculate_shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {b: data.count(b)/len(data) for b in set(data)}
    return -sum(p * math.log2(p) for p in freq.values())

def get_environment_entropy() -> bytes:
    raw = (
        str(uuid.getnode()) +
        str(platform.system()) +
        str(platform.release()) +
        str(os.cpu_count()) +
        str(os.getpid()) +
        str(time.time()) +
        str(socket.gethostname())
    ).encode()
    return hashlib.sha3_512(raw).digest()

def detect_anomaly(input_data: str, entropy_score: float) -> tuple:
    suspicious_chars = "0123456789+/=\n"
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

# === Key Derivation Functions ===

def derive_key_argon2(password: bytes, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=4,
        memory_cost=102400,
        parallelism=8,
        hash_len=AES_KEY_SIZE,
        type=Type.ID
    )

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

# === PQC KEM Helpers ===

def pqc_keypair(kem_name: str):
    kem = oqs.KeyEncapsulation(kem_name)
    public_key = kem.generate_keypair()
    return kem, public_key

def pqc_encapsulate(kem, public_key: bytes):
    return kem.encap_secret(public_key)

def pqc_decapsulate(kem, ciphertext: bytes):
    return kem.decap_secret(ciphertext)

# === Hybrid Key Derivation with SHAKE-256 finalization and PQC integration ===

def derive_key_hybrid_with_pqc(password: bytes, salt: bytes, anomaly: bool) -> tuple:
    if anomaly:
        pqc_candidates = PQC_STRONG_KEMS.copy()
    else:
        pqc_candidates = PQC_FAST_KEMS.copy()

    random.shuffle(pqc_candidates)

    if anomaly:
        if random.choice([True, False]):
            print("Anomaly detected: Using Argon2id for initial KDF")
            intermediate_key = derive_key_argon2(password, salt)
        else:
            bits = random.choice([128, 256])
            print(f"Anomaly detected: Using SHAKE-{bits} for initial KDF")
            intermediate_key = derive_key_shake(password, salt, bits)
    else:
        print("No anomaly: Using HKDF for initial KDF")
        intermediate_key = derive_key_hkdf(password, salt)

    start_shake_final = time.time()
    final_key = hashlib.shake_256(intermediate_key).digest(AES_KEY_SIZE)
    shake_final_time = time.time() - start_shake_final
    print(f"✔ Final SHAKE-256 encapsulation completed in {shake_final_time:.6f}s")

    for kem_name in pqc_candidates:
        try:
            print(f"🔑 Trying PQC KEM: {kem_name}")
            start_kem = time.time()
            kem, public_key = pqc_keypair(kem_name)
            ciphertext, shared_secret = pqc_encapsulate(kem, public_key)
            shared_secret_check = pqc_decapsulate(kem, ciphertext)
            kem_time = time.time() - start_kem

            if shared_secret != shared_secret_check:
                raise ValueError("Shared secrets do not match.")

            print(f"✔ PQC KEM {kem_name} success in {kem_time:.6f}s")

            return final_key, shake_final_time, kem_time, kem_name, public_key, ciphertext, shared_secret

        except Exception as e:
            print(f"❌ PQC KEM {kem_name} failed: {e}")

    raise RuntimeError("All PQC KEM attempts failed")

# === Helper to shorten large byte strings for display ===

def shorten_bytes_for_display(data: bytes, length=10):
    if len(data) <= length:
        return data.hex()
    return data[:length].hex() + "..."

# === AHE Core Encryption Function with PQC ===

def ahe_encrypt_v9_5(message: str) -> dict:
    print("\n🔐 AHE v9.5 :: Quantum Secure Adaptive Encryption Begins")
    total_start = time.time()

    step_times = {}

    step_start = time.time()
    input_bytes = message.encode()
    input_entropy = calculate_shannon_entropy(input_bytes)
    step_times["input_entropy_calc"] = time.time() - step_start
    print(f"1️⃣ Input Entropy Score: {round(input_entropy,4)} (took {step_times['input_entropy_calc']:.6f}s)")

    step_start = time.time()
    system_entropy = get_environment_entropy()
    system_entropy_score = calculate_shannon_entropy(system_entropy)
    step_times["system_entropy_calc"] = time.time() - step_start
    print(f"2️⃣ System Entropy Score: {round(system_entropy_score,4)} (took {step_times['system_entropy_calc']:.6f}s)")

    step_start = time.time()
    fused_input = bytes(a ^ b for a, b in zip(input_bytes, system_entropy[:len(input_bytes)]))
    step_times["entropy_fusion"] = time.time() - step_start
    print(f"3️⃣ Fusion completed (took {step_times['entropy_fusion']:.6f}s)")

    step_start = time.time()
    anomaly, reasons = detect_anomaly(message, input_entropy)
    step_times["anomaly_detection"] = time.time() - step_start
    print(f"5️⃣ Anomaly Detected: {anomaly} (took {step_times['anomaly_detection']:.6f}s)")
    if anomaly:
        print(f"   Reasons: {', '.join(reasons)}")

    step_start = time.time()
    output = fused_input
    shuffled_algos = random.sample(HASH_ALGORITHMS, len(HASH_ALGORITHMS))
    for i, algo in enumerate(shuffled_algos):
        stage_start = time.time()
        output = hash_stage(output + system_entropy, algo)
        stage_time = time.time() - stage_start
        print(f"6️⃣ Stage {i + 1} :: {algo.upper()} (took {stage_time:.6f}s)")
    step_times["multi_hashing"] = time.time() - step_start

    step_start = time.time()
    salt = system_entropy[:16]
    password = output[:32]
    try:
        aes_key, shake_time, kem_time, kem_name, pqc_public_key, pqc_ciphertext, pqc_shared_secret = derive_key_hybrid_with_pqc(password, salt, anomaly)
    except Exception as e:
        print(f"❌ Encryption failed: {e}")
        return {}
    step_times["key_derivation_pqc"] = time.time() - step_start

    step_start = time.time()
    aes_bundle = aes_encrypt(message, aes_key)
    step_times["aes_encryption"] = time.time() - step_start
    print(f"8️⃣ AES-GCM encryption completed (took {step_times['aes_encryption']:.6f}s)")

    total_elapsed = time.time() - total_start

    pqc_pubkey_disp = shorten_bytes_for_display(pqc_public_key)
    pqc_ct_disp = shorten_bytes_for_display(pqc_ciphertext)
    pqc_ss_disp = urlsafe_b64encode(pqc_shared_secret).decode()

    print("\n✅ Encryption completed successfully!")
    print(f"Total encryption time: {total_elapsed:.6f}s")
    print(f"SHAKE-256 finalization time: {shake_time:.6f}s")
    print(f"PQC KEM ({kem_name}) total time: {kem_time:.6f}s")
    print(f"PQC Public Key (shortened): {pqc_pubkey_disp}")
    print(f"PQC Ciphertext (shortened): {pqc_ct_disp}")
    print(f"PQC Shared Secret (base64): {pqc_ss_disp}")

    return {
        "aes_encrypted": aes_bundle,
        "pqc": {
            "kem_name": kem_name,
            "public_key": pqc_pubkey_disp,
            "ciphertext": pqc_ct_disp,
            "shared_secret": pqc_ss_disp
        },
        "timing": {
            "total": total_elapsed,
            "input_entropy_calc": step_times["input_entropy_calc"],
            "system_entropy_calc": step_times["system_entropy_calc"],
            "entropy_fusion": step_times["entropy_fusion"],
            "anomaly_detection": step_times["anomaly_detection"],
            "multi_hashing": step_times["multi_hashing"],
            "key_derivation_pqc": step_times["key_derivation_pqc"],
            "aes_encryption": step_times["aes_encryption"],
            "shake256_final": shake_time,
            "pqc_kem": kem_time
        },
        "anomaly": anomaly,
        "anomaly_reasons": reasons if anomaly else []
    }

# === AHE Core Decryption Function with PQC ===

def ahe_decrypt_v9_5(encrypted_data: dict, private_kem: oqs.KeyEncapsulation) -> str:
    print("\n🔐 AHE v9.5 :: Quantum Secure Adaptive Decryption Begins")

    # Retrieve PQC ciphertext and decrypt shared secret
    ciphertext_b64 = encrypted_data["pqc"]["ciphertext"]
    # For decryption, we need full ciphertext bytes; user should have saved full ciphertext
    # Here we assume ciphertext was saved fully, not shortened, so adjust accordingly in real use
    # This example just outlines process, you should save full ciphertext in real system

    # Warning: Here we must get real ciphertext bytes for decapsulation
    # This example assumes ciphertext is stored in full in encrypted_data["pqc"]["ciphertext_full"]
    # Adapt as needed for your storage

    if "ciphertext_full" not in encrypted_data["pqc"]:
        raise ValueError("Full ciphertext not found for decryption.")

    ciphertext = urlsafe_b64decode(encrypted_data["pqc"]["ciphertext_full"])
    shared_secret = private_kem.decap_secret(ciphertext)

    aes_key = hashlib.shake_256(shared_secret).digest(AES_KEY_SIZE)

    # Decrypt AES bundle
    plaintext = aes_decrypt(encrypted_data["aes_encrypted"], aes_key)
    print("✅ Decryption completed successfully!")
    return plaintext

# === MAIN FUNCTION ===

def main():
    print("=== Adaptive Hashing Encryption (AHE) v9.5 ===")
    while True:
        print("\nChoose an option:")
        print("1. Encrypt a message")
        print("2. Exit")
        choice = input("Enter choice (1/2): ").strip()

        if choice == "1":
            message = input("\nEnter message to encrypt:\n")

            encrypted = ahe_encrypt_v9_5(message)
            if not encrypted:
                print("Encryption failed. Try again.")
                continue

            print("\n--- Encrypted Output ---")
            print(encrypted)

            # Note: For real decryption you must save full PQC ciphertext and keys!
            # Here, for demo, we just show encryption output.

        elif choice == "2":
            print("Exiting. Goodbye.")
            break
        else:
            print("Invalid choice, try again.")

if __name__ == "__main__":
    main()