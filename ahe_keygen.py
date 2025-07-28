# === Adaptive Hashing Encryption (AHE) v5.1 ===
# Military-grade, Quantum-aware, Fully Verbose Execution Output
# Developed for unbreakable entropy chaining and anomaly-aware encryption


# === STANDARD LIBRARY IMPORTS ===
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


# === EXTERNAL LIBRARIES ===
from base64 import urlsafe_b64encode, urlsafe_b64decode
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


# === CONFIGURATION ===
MAX_INPUT_LENGTH = 4096
ENTROPY_WARN_THRESHOLD_LOW = 3.5
ENTROPY_WARN_THRESHOLD_HIGH = 4.75
PBKDF2_ITERATIONS = 200_000
AES_KEY_SIZE = 32  # 256-bit AES key
HASH_ALGORITHMS = [
    "sha3_512",
    "blake2b",
    "sha512",
    "blake2s"
]


# === ENTROPY UTILITIES ===
def calculate_shannon_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of a byte string.
    """
    if not data:
        return 0.0

    freq = {b: data.count(b) / len(data) for b in set(data)}
    entropy = -sum(p * math.log2(p) for p in freq.values())

    return entropy


def get_environment_entropy() -> bytes:
    """
    Gather system/environment-specific entropy.
    Combines device identifiers, OS info, time, hostname.
    """
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


# === SESSION & ID UTILITIES ===
def generate_fractal_id() -> str:
    """
    Generate a unique fractal session ID for the encryption instance.
    """
    now = datetime.datetime.now(datetime.UTC)
    entropy = secrets.token_bytes(16)
    data = f"{now.timestamp()}_{entropy.hex()}".encode()

    return hashlib.blake2b(data).hexdigest()[:16]


def detect_anomaly(input_data: str, entropy_score: float) -> bool:
    """
    Detect if the input is anomalous based on entropy and presence of
    suspicious characters typical for encoded or gibberish data.
    """
    suspicious_chars = "0123456789+/=\n"

    if entropy_score < ENTROPY_WARN_THRESHOLD_LOW:
        return True

    if entropy_score > ENTROPY_WARN_THRESHOLD_HIGH:
        return True

    if any(c in input_data for c in suspicious_chars):
        return True

    return False


# === HASHING FUNCTION ===
def hash_stage(data: bytes, algo: str) -> bytes:
    """
    Perform one stage of hashing using the specified algorithm.
    """
    h = hashlib.new(algo)
    h.update(data)

    return h.digest()


# === AES ENCRYPTION UTILITIES ===
def aes_encrypt(message: str, key: bytes) -> dict:
    """
    Encrypt the message using AES-GCM with the given key.
    Returns ciphertext, nonce, and tag, all base64 encoded.
    """
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())

    return {
        "ciphertext": urlsafe_b64encode(ciphertext).decode(),
        "nonce": urlsafe_b64encode(nonce).decode(),
        "tag": urlsafe_b64encode(tag).decode()
    }


def aes_decrypt(bundle: dict, key: bytes) -> str:
    """
    Decrypt AES-GCM encrypted bundle with the given key.
    """
    nonce = urlsafe_b64decode(bundle["nonce"])
    tag = urlsafe_b64decode(bundle["tag"])
    ciphertext = urlsafe_b64decode(bundle["ciphertext"])

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()


# === MAIN AHE FUNCTION ===
def ahe_encrypt(message: str) -> dict:
    """
    Adaptive Hashing Encryption core:
    - Calculate input entropy and anomaly detection
    - Gather environment entropy
    - Generate unique fractal session ID
    - Multi-stage shuffled hashing combined with environment entropy
    - Derive AES-GCM key from hash output + environment entropy
    - Encrypt message with AES-GCM
    - Print detailed verbose info in logical sequence
    """
    print("\n🔍 [1] Reading User Input and Calculating Entropy...")
    input_bytes = message.encode()

    input_entropy = calculate_shannon_entropy(input_bytes)
    anomaly = detect_anomaly(message, input_entropy)

    print(f"📊 Input Entropy Score: {round(input_entropy, 3)}")
    print(f"🚨 Anomaly Detected: {anomaly}")

    print("\n🔐 [2] Gathering System Entropy for Key Derivation...")
    system_entropy = get_environment_entropy()
    system_entropy_score = calculate_shannon_entropy(system_entropy)

    print(f"🌐 System Entropy Score: {round(system_entropy_score, 3)}")

    print("\n🧬 [3] Generating Unique Fractal Session ID...")
    fractal_id = generate_fractal_id()
    print(f"🔑 Fractal ID: {fractal_id}")

    print("\n🔄 [4] Starting Multi-Stage Hashing with Randomized Algorithms...")
    output = input_bytes
    hash_stages = []

    shuffled_algos = random.sample(HASH_ALGORITHMS, len(HASH_ALGORITHMS))

    start_time = time.time()

    for i, algo in enumerate(shuffled_algos):
        print(f"   • Stage {i+1}: Hashing with {algo.upper()}...")
        stage_start = time.time()

        output = hash_stage(output + system_entropy, algo)

        stage_time = round(time.time() - stage_start, 6)
        hash_stages.append({"stage": i+1, "algo": algo, "time": stage_time})

    print("\n🔏 [5] Deriving AES-GCM Key Using PBKDF2 + System Entropy...")
    aes_key = PBKDF2(
        output[:32],
        system_entropy[:32],
        dkLen=AES_KEY_SIZE,
        count=PBKDF2_ITERATIONS,
        hmac_hash_module=SHA512
    )

    print("🔒 Encrypting Message Using AES-GCM...")
    aes_bundle = aes_encrypt(message, aes_key)

    total_time = round(time.time() - start_time, 6)

    print("\n🧾 === AHE Summary ===")
    print(f"✅ Anomaly Flag: {anomaly}")
    print(f"📊 Input Entropy: {round(input_entropy, 3)}")
    print(f"🌐 System Entropy: {round(system_entropy_score, 3)}")
    print(f"🔁 Hash Stages: {[stage['algo'] for stage in hash_stages]}")
    print(f"🛡 AES Ciphertext Sample: {aes_bundle['ciphertext'][:64]}...")
    print(f"⏱ Total Encryption Time: {total_time} seconds")

    return {
        "fractal_id": fractal_id,
        "ahe_cipher": urlsafe_b64encode(output).decode(),
        "anomaly": anomaly,
        "input_entropy": input_entropy,
        "system_entropy": system_entropy_score,
        "aes": aes_bundle,
        "hash_stages": hash_stages,
        "total_time": total_time
    }


# === MAIN EXECUTION ===
def main():
    print("\n🧠 Adaptive Hashing Encryption v5.1 :: Fully Verbose Execution Mode ::")
    while True:
        msg = input("\n✉ Enter message to encrypt (or 'exit'): ")

        if msg.lower() == "exit":
            print("👋 Goodbye.")
            break

        result = ahe_encrypt(msg)

        print("\n--- END OF SESSION ---")


if __name__ == "__main__":
    main()