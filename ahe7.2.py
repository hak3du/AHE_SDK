# === Adaptive Hashing Encryption (AHE) v7.x ===
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
import re
from base64 import urlsafe_b64encode, urlsafe_b64decode
from Crypto.Protocol.KDF import PBKDF2, HKDF
from Crypto.Hash import SHA512
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# === CONFIGURATION ===
ENTROPY_WARN_THRESHOLD_LOW = 3.5
ENTROPY_WARN_THRESHOLD_HIGH = 4.75
PBKDF2_ITERATIONS_FAST = 100_000
PBKDF2_ITERATIONS_SLOW = 500_000
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

def detect_anomaly_severity(input_data: str, entropy_score: float) -> tuple:
    severity = 0.0
    reasons = []

    # Suspicious characters check
    suspicious_chars = "0123456789+/=\n"
    if any(c in input_data for c in suspicious_chars):
        severity += 3.0
        reasons.append("suspicious characters detected")

    # Entropy deviation
    if entropy_score < ENTROPY_WARN_THRESHOLD_LOW:
        severity += 3.0 * (ENTROPY_WARN_THRESHOLD_LOW - entropy_score)
        reasons.append("entropy too low")
    elif entropy_score > ENTROPY_WARN_THRESHOLD_HIGH:
        severity += 3.0 * (entropy_score - ENTROPY_WARN_THRESHOLD_HIGH)
        reasons.append("entropy too high")

    # Repeated characters penalty (3 or more repeats)
    if re.search(r'(.)\1\1', input_data):
        severity += 2.0
        reasons.append("repeated characters detected")

    # Cap severity max 10
    severity = min(severity, 10.0)

    return severity > 0.0, reasons, severity

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

def adaptive_kdf(secret: bytes, salt: bytes, severity: float) -> bytes:
    """
    Adaptive key derivation function selecting KDF based on anomaly severity score.
    """
    if severity < 3.0:
        # Low threat: PBKDF2 fast
        return PBKDF2(secret, salt, dkLen=AES_KEY_SIZE, count=PBKDF2_ITERATIONS_FAST, hmac_hash_module=SHA512)
    elif severity < 7.0:
        # Medium threat: HKDF
        return HKDF(secret, AES_KEY_SIZE, salt, SHA512)
    else:
        # High threat: Try Argon2 (if installed), else slow PBKDF2 fallback
        try:
            from argon2 import PasswordHasher
            ph = PasswordHasher(time_cost=4, memory_cost=102400, parallelism=8)
            hashed = ph.hash(secret.hex())
            # Return first AES_KEY_SIZE bytes from hash string (simplified)
            return hashed.encode()[:AES_KEY_SIZE]
        except ImportError:
            return PBKDF2(secret, salt, dkLen=AES_KEY_SIZE, count=PBKDF2_ITERATIONS_SLOW, hmac_hash_module=SHA512)

# === AHE Core Encryption Function ===

def ahe_encrypt_v7_adaptive(message: str) -> dict:
    print("\n🔐 AHE v7.x :: Adaptive Encryption Begins")
    start_time = time.time()

    # Step 1: Input entropy
    step_start = time.time()
    input_bytes = message.encode()
    input_entropy = calculate_shannon_entropy(input_bytes)
    step_time_input_entropy = time.time() - step_start
    print(f"1️⃣ Input entropy calculated: {input_entropy:.4f} (took {step_time_input_entropy:.6f}s)")

    # Step 2: System entropy
    step_start = time.time()
    system_entropy = get_environment_entropy()
    system_entropy_score = calculate_shannon_entropy(system_entropy)
    step_time_system_entropy = time.time() - step_start
    print(f"2️⃣ System entropy collected: {system_entropy_score:.4f} (took {step_time_system_entropy:.6f}s)")

    # Step 3: Fuse input + system entropy
    step_start = time.time()
    fused_input = bytes(a ^ b for a, b in zip(input_bytes, system_entropy[:len(input_bytes)]))
    step_time_fusion = time.time() - step_start
    print(f"3️⃣ Input fused with system entropy (took {step_time_fusion:.6f}s)")

    # Step 4: Generate fractal ID
    step_start = time.time()
    fractal_id = generate_fractal_id()
    step_time_fractal = time.time() - step_start
    print(f"4️⃣ Fractal ID generated: {fractal_id} (took {step_time_fractal:.6f}s)")

    # Step 5: Anomaly detection + severity
    step_start = time.time()
    anomaly, reasons, severity = detect_anomaly_severity(message, input_entropy)
    step_time_anomaly = time.time() - step_start
    print(f"5️⃣ Anomaly detection: {anomaly} (severity {severity:.3f}) (took {step_time_anomaly:.6f}s)")
    if anomaly:
        print(f"   • Reasons: {', '.join(reasons)}")

    # Step 6: Multi-stage hashing
    step_start = time.time()
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
            "time": stage_time
        })
        print(f"6.{i+1} Hash stage {i+1} using {algo.upper()} took {stage_time:.6f}s")
    step_time_hashing = time.time() - step_start

    # Step 7: Adaptive key derivation based on severity
    step_start = time.time()
    aes_key = adaptive_kdf(output[:AES_KEY_SIZE], system_entropy[:AES_KEY_SIZE], severity)
    step_time_kdf = time.time() - step_start
    print(f"7️⃣ Adaptive key derivation done (severity={severity:.3f}) (took {step_time_kdf:.6f}s)")

    # Step 8: AES-GCM encryption
    step_start = time.time()
    aes_bundle = aes_encrypt(message, aes_key)
    step_time_encrypt = time.time() - step_start
    print(f"8️⃣ AES-GCM encryption done (took {step_time_encrypt:.6f}s)")

    # Step 9: Final base64 encode of hash output
    step_start = time.time()
    final_hash = urlsafe_b64encode(output).decode()
    step_time_final_encode = time.time() - step_start
    print(f"9️⃣ Final hash encoding done (took {step_time_final_encode:.6f}s)")

    total_time = time.time() - start_time
    print(f"🔟 Total encryption process time: {total_time:.6f}s\n")

    return {
        "fractal_id": fractal_id,
        "input_entropy": input_entropy,
        "system_entropy": system_entropy_score,
        "anomaly": anomaly,
        "anomaly_reasons": reasons,
        "anomaly_severity": severity,
        "hash_stages": hash_stages,
        "final_hash": final_hash,
        "aes": aes_bundle,
        "timings": {
            "input_entropy": step_time_input_entropy,
            "system_entropy": step_time_system_entropy,
            "fusion": step_time_fusion,
            "fractal_id": step_time_fractal,
            "anomaly_detection": step_time_anomaly,
            "hashing": step_time_hashing,
            "key_derivation": step_time_kdf,
            "encryption": step_time_encrypt,
            "final_encoding": step_time_final_encode,
            "total": total_time
        }
    }

# === EXECUTION ===

def main():
    print("\n🚀 Welcome to Adaptive Hashing Encryption v7.x\n")
    while True:
        command = input("🟩 Enter text to encrypt, 'd' to decrypt, or 'exit': ").strip()
        if command.lower() == "exit":
            print("👋 Exiting.")
            break
        elif command.lower() == "d":
            print("🔐 Decryption mode (manual input)...")
            try:
                aes_bundle = eval(input("   🔐 AES Bundle (as dict): "))
                final_hash = input("   🔑 Final Hash (base64): ").encode()
                system_entropy = get_environment_entropy()
                # Derive severity estimate from hash length (fallback to low severity)
                # In real scenario, you would store severity along with ciphertext
                severity = 0.0
                key = adaptive_kdf(urlsafe_b64decode(final_hash)[:AES_KEY_SIZE], system_entropy[:AES_KEY_SIZE], severity)
                plaintext = aes_decrypt(aes_bundle, key)
                print(f"✅ Decrypted Message: {plaintext}")
            except Exception as e:
                print(f"❌ Decryption failed: {e}")
        else:
            result = ahe_encrypt_v7_adaptive(command)
            print("\n🔎 Encryption Result Summary:")
            print(f"   🧬 Fractal ID: {result['fractal_id']}")
            print(f"   🧠 Input Entropy: {result['input_entropy']:.4f}")
            print(f"   🌐 System Entropy: {result['system_entropy']:.4f}")
            print(f"   🚨 Anomaly Detected: {result['anomaly']}")
            print(f"   ⚠ Anomaly Severity: {result['anomaly_severity']:.3f}")
            if result['anomaly']:
                print(f"   • Reasons: {', '.join(result['anomaly_reasons'])}")
            print(f"   🔁 Hash Sequence: {[stage['algo'] for stage in result['hash_stages']]}")
            for stage in result['hash_stages']:
                print(f"     - Stage {stage['stage']}: {stage['algo'].upper()} in {stage['time']:.6f}s")
            print(f"   🔑 Final Hash (base64): {result['final_hash']}")
            print(f"   🔒 AES Ciphertext: {result['aes']['ciphertext']}")
            print(f"   🔖 AES Tag: {result['aes']['tag']}")
            print(f"   📍 AES Nonce: {result['aes']['nonce']}")
            print(f"   ⏱ Timings (seconds):")
            for k,v in result['timings'].items():
                print(f"     • {k}: {v:.6f}")
            print()

if __name__ == "__main__":
    main()