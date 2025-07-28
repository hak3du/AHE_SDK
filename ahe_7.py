# === Adaptive Hashing Encryption (AHE) v7.2 ===
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
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

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
    return hashlib.blake2b(f"{now.timestamp()}_{entropy.hex()}".encode()).hexdigest()[:128]

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

# === AHE Core Encryption Function ===

def ahe_encrypt_v7_2(message: str) -> dict:
    print("\n🔐 AHE v7.2 :: Adaptive Encryption Begins")
    start_time = time.time()

    print("1️⃣ Reading user input and calculating input entropy...")
    input_bytes = message.encode()
    input_entropy = calculate_shannon_entropy(input_bytes)
    print(f"   • Input Entropy Score: {round(input_entropy, 4)}")

    print("2️⃣ Collecting system entropy for chrono-harmonic behavior...")
    system_entropy = get_environment_entropy()
    system_entropy_score = calculate_shannon_entropy(system_entropy)
    print(f"   • System Entropy Score: {round(system_entropy_score, 4)}")

    print("3️⃣ Fusing input and environment entropy...")
    fused_input = bytes(a ^ b for a, b in zip(input_bytes, system_entropy[:len(input_bytes)]))

    print("4️⃣ Generating Fractal Session ID...")
    fractal_id = generate_fractal_id()
    print(f"   • Fractal ID: {fractal_id}")

    print("5️⃣ Anomaly detection (prior to hashing)...")
    anomaly, reasons = detect_anomaly(message, input_entropy)
    print(f"   • Anomaly Detected: {anomaly}")
    if anomaly:
        print(f"   • Reasons: {', '.join(reasons)}")

    print("6️⃣ Randomized Multi-Stage Hashing begins...")
    output = fused_input
    hash_stages = []
    shuffled_algos = random.sample(HASH_ALGORITHMS, len(HASH_ALGORITHMS))
    for i, algo in enumerate(shuffled_algos):
        stage_start = time.time()
        output = hash_stage(output + system_entropy, algo)
        stage_time = round(time.time() - stage_start, 6)
        hash_stages.append({
            "stage": i + 1,
            "algo": algo,
            "output": output.hex(),
            "time": stage_time
        })
        print(f"   • Stage {i+1} :: {algo.upper()} :: {stage_time}s")

    print("7️⃣ Deriving AES key using PBKDF2 + system entropy...")
    aes_key = PBKDF2(output[:32], system_entropy[:32], dkLen=AES_KEY_SIZE, count=PBKDF2_ITERATIONS, hmac_hash_module=SHA512)

    print("8️⃣ Encrypting message using AES-GCM...")
    aes_bundle = aes_encrypt(message, aes_key)

    print("9️⃣ Encoding final output...")
    final_hash = urlsafe_b64encode(output).decode()

    total_time = round(time.time() - start_time, 6)
    print(f"🔟 Encryption completed in {total_time} seconds")

    return {
        "fractal_id": fractal_id,
        "input_entropy": input_entropy,
        "system_entropy": system_entropy_score,
        "anomaly": anomaly,
        "anomaly_reasons": reasons,
        "hash_stages": hash_stages,
        "final_hash": final_hash,
        "aes": aes_bundle,
        "total_time": total_time
    }

# === EXECUTION ===

def main():
    print("\n🚀 Welcome to Adaptive Hashing Encryption v7.2\n")
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
            key = PBKDF2(urlsafe_b64decode(final_hash)[:32], system_entropy[:32], dkLen=AES_KEY_SIZE, count=PBKDF2_ITERATIONS, hmac_hash_module=SHA512)
            plaintext = aes_decrypt(aes_bundle, key)
            print(f"✅ Decrypted Message: {plaintext}")
        else:
            result = ahe_encrypt_v7_2(command)
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
            print(f"   ⏱ Total Time: {result['total_time']}s\n")

if __name__ == "__main__":
    main()