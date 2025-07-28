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

# PQC Kyber imports
try:
    from pqcrypto.kem.kyber512 import generate_keypair, encrypt, decrypt
    PQC_AVAILABLE = True
except ImportError:
    print("pqcrypto not installed: PQC benchmarks disabled.")
    PQC_AVAILABLE = False

MAX_INPUT_LENGTH = 4096
PBKDF2_ITERATIONS = 100_000
AES_KEY_SIZE = 32
HASH_ALGORITHMS = ["sha3_512", "blake2b", "sha512", "blake2s"]

L_INF_THRESHOLD = 5.0

def calculate_shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {b: data.count(b) / len(data) for b in set(data)}
    entropy = -sum(p * math.log2(p) for p in freq.values())
    return entropy

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
    now = datetime.datetime.utcnow()
    entropy = secrets.token_bytes(16)
    data = f"{now.timestamp()}_{entropy.hex()}".encode()
    return hashlib.blake2b(data).hexdigest()[:16]

def l_infinity_norm(values: list) -> float:
    return max(abs(v) for v in values)

def detect_anomaly(input_data: str, entropy_components: dict) -> bool:
    l_inf = l_infinity_norm(list(entropy_components.values()))
    suspicious_chars = "0123456789+/=\n"
    has_suspicious_chars = any(c in input_data for c in suspicious_chars)
    return l_inf > L_INF_THRESHOLD or has_suspicious_chars

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

def max_repeat_run_score(data: str) -> float:
    max_run = 1
    current_run = 1
    for i in range(1, len(data)):
        if data[i] == data[i-1]:
            current_run += 1
            max_run = max(max_run, current_run)
        else:
            current_run = 1
    return float(max_run)

def ahe_encrypt(message: str) -> dict:
    input_bytes = message.encode()
    input_entropy = calculate_shannon_entropy(input_bytes)
    system_entropy = get_environment_entropy()
    system_entropy_score = calculate_shannon_entropy(system_entropy)

    entropy_components = {
        "input_entropy": input_entropy,
        "system_entropy": system_entropy_score,
        "repeat_char_score": max_repeat_run_score(message),
        "timing_deviation": 0  # Placeholder for timing anomalies
    }

    anomaly = detect_anomaly(message, entropy_components)
    fractal_id = generate_fractal_id()

    output = input_bytes
    hash_stages = []
    shuffled_algos = random.sample(HASH_ALGORITHMS, len(HASH_ALGORITHMS))
    start_time = time.time()

    for i, algo in enumerate(shuffled_algos):
        stage_start = time.time()
        output = hash_stage(output + system_entropy, algo)
        stage_time = time.time() - stage_start
        hash_stages.append({"stage": i + 1, "algo": algo, "time": stage_time})

    aes_key = PBKDF2(
        output[:32],
        system_entropy[:32],
        dkLen=AES_KEY_SIZE,
        count=PBKDF2_ITERATIONS,
        hmac_hash_module=SHA512
    )

    aes_bundle = aes_encrypt(message, aes_key)
    total_time = time.time() - start_time
    ahe_cipher_b64 = urlsafe_b64encode(output).decode()

    return {
        "fractal_id": fractal_id,
        "ahe_cipher": ahe_cipher_b64,
        "anomaly": anomaly,
        "input_entropy": input_entropy,
        "system_entropy": system_entropy_score,
        "aes": aes_bundle,
        "hash_stages": hash_stages,
        "total_time": total_time
    }

def benchmark_aes(message: str) -> float:
    key = get_random_bytes(AES_KEY_SIZE)
    start = time.time()
    aes_encrypt(message, key)
    end = time.time()
    return end - start

def benchmark_sha256(message: str) -> float:
    start = time.time()
    hashlib.sha256(message.encode()).digest()
    end = time.time()
    return end - start

def benchmark_rsa(message: str) -> float:
    try:
        from Crypto.PublicKey import RSA
        from Crypto.Cipher import PKCS1_OAEP
    except ImportError:
        return -1
    key = RSA.generate(2048)
    cipher = PKCS1_OAEP.new(key.publickey())
    start = time.time()
    cipher.encrypt(message.encode())
    end = time.time()
    return end - start

def benchmark_pqc_kyber(message: str):
    if not PQC_AVAILABLE:
        return None
    public_key, secret_key = generate_keypair()
    start = time.time()
    encrypt(message.encode(), public_key)
    end = time.time()
    return end - start

def main():
    print("Adaptive Hashing Encryption v7.0 - L∞ Anomaly Detection + Benchmarking")

    if not PQC_AVAILABLE:
        print(
            "pqcrypto not installed; skipping PQC benchmarks.\n"
            "Install with 'pip install pqcrypto'"
        )

    while True:
        msg = input("\nEnter message to encrypt (or 'exit'): ")
        if msg.lower() == "exit":
            print("Goodbye.")
            break

        result = ahe_encrypt(msg)

        time_ahe = result['total_time']
        time_aes = benchmark_aes(msg)
        time_sha = benchmark_sha256(msg)
        time_rsa = benchmark_rsa(msg)
        time_pqc = benchmark_pqc_kyber(msg) if PQC_AVAILABLE else None

        print("\n=== Encryption Result ===")
        print(f"Fractal ID: {result['fractal_id']}")
        print(f"Anomaly Detected: {result['anomaly']}")
        print(f"Input Entropy: {result['input_entropy']:.3f}")
        print(f"System Entropy: {result['system_entropy']:.3f}")
        print(f"AHE Hash (base64): {result['ahe_cipher']}")
        print(f"AES Ciphertext (base64): {result['aes']['ciphertext']}")
        print(f"AES Nonce (base64): {result['aes']['nonce']}")
        print(f"AES Tag (base64): {result['aes']['tag']}")

        print(f"\nExecution Times (seconds):")
        print(f" - AHE Encrypt: {time_ahe:.6f}")
        print(f" - AES-GCM Encrypt: {time_aes:.6f}")
        print(f" - SHA-256 Hash: {time_sha:.6f}")
        print(f" - RSA 2048 Encrypt: {time_rsa if time_rsa != -1 else 'N/A (pycryptodome missing)'}")
       

if __name__ == "__main__":
    main()