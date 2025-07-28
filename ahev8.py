# === Adaptive Hashing Encryption (AHE) v8 ===
# By The Architect Beyond Time

import hashlib
import secrets
import time
import datetime
import math
import random
import os
import platform
import socket
import uuid
from base64 import urlsafe_b64encode, urlsafe_b64decode
from Crypto.Protocol.KDF import PBKDF2, HKDF
from Crypto.Hash import SHA512, HMAC, SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from argon2.low_level import hash_secret_raw, Type

# === CONFIGURATION ===
ENTROPY_WARN_THRESHOLD_LOW = 3.5
ENTROPY_WARN_THRESHOLD_HIGH = 4.75
PBKDF2_ITERATIONS = 100_000
AES_KEY_SIZE = 32
HASH_ALGORITHMS = ["sha3_512", "blake2b", "sha512", "blake2s"]

# === UTILITIES ===

def calculate_shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {b: data.count(b) / len(data) for b in set(data)}
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
    return hashlib.blake2b(raw).digest()

def generate_fractal_id() -> str:
    now = datetime.datetime.now(datetime.UTC)
    entropy = secrets.token_bytes(16)
    return hashlib.blake2b(f"{now.timestamp()}_{entropy.hex()}".encode()).hexdigest()[:64+1]

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

# === Adaptive Key Derivation Functions ===

def derive_key_pbkdf2(password: bytes, salt: bytes) -> bytes:
    return PBKDF2(password, salt, dkLen=AES_KEY_SIZE, count=PBKDF2_ITERATIONS, hmac_hash_module=SHA512)

def derive_key_hkdf(password: bytes, salt: bytes) -> bytes:
    return HKDF(password, AES_KEY_SIZE, salt, SHA256)

def derive_key_argon2(password: bytes, salt: bytes) -> bytes:
    # Real Argon2id key derivation - secure and memory hard
    return hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=4,         # adjustable: increase for higher security / slower performance
        memory_cost=102400,  # in kibibytes (100 MiB here)
        parallelism=8,
        hash_len=AES_KEY_SIZE,
        type=Type.ID
    )

# === AHE Core Encryption Function ===

def ahe_encrypt_v8(message: str) -> dict:
    print("\n🔐 AHE v8 :: Adaptive Encryption Begins")
    start_time = time.time()

    print("1️⃣ Reading user input and calculating input entropy...")
    t1 = time.time()
    input_bytes = message.encode()
    input_entropy = calculate_shannon_entropy(input_bytes)
    t1_elapsed = time.time() - t1
    print(f"   • Input Entropy Score: {round(input_entropy, 4)} (Calculated in {t1_elapsed:.6f}s)")

    print("2️⃣ Collecting system entropy for chrono-harmonic behavior...")
    t2 = time.time()
    system_entropy = get_environment_entropy()
    system_entropy_score = calculate_shannon_entropy(system_entropy)
    t2_elapsed = time.time() - t2
    print(f"   • System Entropy Score: {round(system_entropy_score, 4)} (Collected in {t2_elapsed:.6f}s)")

    print("3️⃣ Fusing input and environment entropy...")
    t3 = time.time()
    fused_input = bytes(a ^ b for a, b in zip(input_bytes, system_entropy[:len(input_bytes)]))
    t3_elapsed = time.time() - t3
    print(f"   • Fusion completed in {t3_elapsed:.6f}s")

    print("4️⃣ Generating Fractal Session ID...")
    t4 = time.time()
    fractal_id = generate_fractal_id()
    t4_elapsed = time.time() - t4
    print(f"   • Fractal ID: {fractal_id} (Generated in {t4_elapsed:.6f}s)")

    print("5️⃣ Anomaly detection (prior to hashing)...")
    t5 = time.time()
    anomaly, reasons = detect_anomaly(message, input_entropy)
    t5_elapsed = time.time() - t5
    print(f"   • Anomaly Detected: {anomaly} (Detected in {t5_elapsed:.6f}s)")
    if anomaly:
        print(f"   • Reasons: {', '.join(reasons)}")

    print("6️⃣ Randomized Multi-Stage Hashing begins...")
    t6 = time.time()
    output = fused_input
    hash_stages = []
    shuffled_algos = random.sample(HASH_ALGORITHMS, len(HASH_ALGORITHMS))
    for i, algo in enumerate(shuffled_algos):
        stage_start = time.time()
        output = hash_stage(output + system_entropy, algo)
        stage_time = time.time() - stage_start
        hash_stages.append({
            "stage": i + 1,
            "algo": algo,
            "output": output.hex(),
            "time": round(stage_time, 6)
        })
        print(f"   • Stage {i+1} :: {algo.upper()} :: {stage_time:.6f}s")
    t6_elapsed = time.time() - t6

    print("7️⃣ Adaptive Key Derivation based on anomaly severity...")
    t7 = time.time()
    salt = system_entropy[:16]
    password = output[:32]
    if anomaly:
        # High anomaly - use Argon2id (slowest, strongest)
        print("   • Using Argon2id key derivation (strongest, slowest)")
        aes_key = derive_key_argon2(password, salt)
    else:
        # No anomaly - use HKDF (fastest)
        print("   • Using HKDF key derivation (fastest)")
        aes_key = derive_key_hkdf(password, salt)
    t7_elapsed = time.time() - t7
    print(f"   • Key derivation completed in {t7_elapsed:.6f}s")

    print("8️⃣ Encrypting message using AES-GCM...")
    t8 = time.time()
    aes_bundle = aes_encrypt(message, aes_key)
    t8_elapsed = time.time() - t8
    print(f"   • AES-GCM encryption completed in {t8_elapsed:.6f}s")

    print("9️⃣ Encoding final output...")
    t9 = time.time()
    final_hash = urlsafe_b64encode(output).decode()
    t9_elapsed = time.time() - t9
    print(f"   • Final hash encoded in {t9_elapsed:.6f}s")

    total_time = time.time() - start_time
    print(f"🔟 Encryption completed in {total_time:.6f} seconds")

    return {
        "fractal_id": fractal_id,
        "input_entropy": input_entropy,
        "system_entropy": system_entropy_score,
        "anomaly": anomaly,
        "anomaly_reasons": reasons,
        "hash_stages": hash_stages,
        "final_hash": final_hash,
        "aes": aes_bundle,
        "total_time": total_time,
        "timings": {
            "input_entropy": t1_elapsed,
            "system_entropy": t2_elapsed,
            "fusion": t3_elapsed,
            "fractal_id": t4_elapsed,
            "anomaly_detection": t5_elapsed,
            "multi_hashing": t6_elapsed,
            "key_derivation": t7_elapsed,
            "aes_encryption": t8_elapsed,
            "final_encoding": t9_elapsed,
        }
    }

# === EXECUTION ===

def main():
    print("\n🚀 Welcome to Adaptive Hashing Encryption v8\n")
    while True:
        command = input("🟩 Enter text to encrypt, 'd' to decrypt, or 'exit': ").strip()
        if command.lower() == "exit":
            print("👋 Exiting.")
            break
        

        
        elif command.lower() == "d":
            print("🔐 Decryption mode (manual input)...")
            aes_bundle = eval(input("   🔐 AES Bundle (as dict): "))
            final_hash = input("   🔑 Final Hash (base64): ").encode()
            system_entropy = get_environment_entropy()
            password = urlsafe_b64decode(final_hash)[:32]
            salt = system_entropy[:16]
            anomaly = input("   ❓ Anomaly detected? (y/n): ").lower() == 'y'
            # Adaptive key derivation for decryption as well:
            if anomaly:
                print("   • Using Argon2id key derivation for decryption")
                key = derive_key_argon2(password, salt)
            else:
                print("   • Using HKDF key derivation for decryption")
                key = derive_key_hkdf(password, salt)
            plaintext = aes_decrypt(aes_bundle, key)
            print(f"✅ Decrypted Message: {plaintext}")
        else:
            result = ahe_encrypt_v8(command)
            print("\n🔎 Encryption Result Summary:")
            print(f"   🧬 Fractal ID: {result['fractal_id']}")
            print(f"   🧠 Input Entropy: {round(result['input_entropy'], 3)}")
            print(f"   🌐 System Entropy: {round(result['system_entropy'], 3)}")
            print(f"   🚨 Anomaly Detected: {result['anomaly']}")
            print(f"   🔁 Hash Sequence: {[s['algo'] for s in result['hash_stages']]}")
            print(f"   🔑 Final Hash (base64): {result['final_hash']}")
            print(f"   🔒 AES Ciphertext: {result['aes']['ciphertext']}")
            print(f"   🔖 AES Tag: {result['aes']['tag']}")
            print(f"   📍 AES Nonce: {result['aes']['nonce']}")
            print(f"   ⏱ Total Time: {result['total_time']:.6f}s")
            print("   ⏲ Timings Breakdown:")
            for stage, timing in result["timings"].items():
                print(f"     • {stage}: {timing:.6f}s")
            print()

if __name__ == "__main__":
    main()