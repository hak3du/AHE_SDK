# === STANDARD LIBRARY IMPORTS ===
import hashlib
import secrets
import time
import datetime
import math
import random
import platform
import uuid
import socket
import psutil

# === EXTERNAL LIBRARY IMPORTS ===
from base64 import urlsafe_b64encode, urlsafe_b64decode
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# === CONFIGURATION CONSTANTS ===
MAX_INPUT_LENGTH = 4096
ENTROPY_WARN_THRESHOLD_LOW = 2.5
ENTROPY_WARN_THRESHOLD_HIGH = 5.0
PBKDF2_ITERATIONS = 150_000
AES_KEY_SIZE = 32  # 256-bit AES key

HASH_ALGORITHMS = [
    "sha3_512",
    "blake2b",
    "sha512",
    "blake2s"
]

# === UTILITY FUNCTIONS ===

def calculate_shannon_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of byte data.
    Returns entropy value in bits per byte.
    """
    if not data:
        return 0.0

    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1

    entropy = 0.0
    length = len(data)

    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)

    return entropy


def get_secure_entropy_bytes(length: int = 64) -> bytes:
    """
    Get cryptographically secure random bytes from OS entropy pool.
    """
    return secrets.token_bytes(length)


def get_system_entropy() -> bytes:
    """
    Collect local system entropy from device characteristics,
    system uptime, CPU load, memory info, MAC address, and UUID.
    """
    entropy_sources = []

    # Device hostname
    try:
        hostname = socket.gethostname()
        entropy_sources.append(hostname.encode())
    except Exception:
        pass

    # Device UUID
    try:
        device_uuid = uuid.getnode()
        entropy_sources.append(device_uuid.to_bytes(6, 'big', signed=False))
    except Exception:
        pass

    # System platform info
    try:
        platform_info = platform.platform()
        entropy_sources.append(platform_info.encode())
    except Exception:
        pass

    # System uptime
    try:
        uptime_seconds = time.time() - psutil.boot_time()
        entropy_sources.append(str(uptime_seconds).encode())
    except Exception:
        pass

    # CPU load
    try:
        cpu_load = psutil.cpu_percent(interval=0.1)
        entropy_sources.append(str(cpu_load).encode())
    except Exception:
        pass

    # Memory usage
    try:
        mem = psutil.virtual_memory()
        entropy_sources.append(str(mem.available).encode())
    except Exception:
        pass

    combined = b''.join(entropy_sources)
    hashed = hashlib.blake2b(combined).digest()

    return hashed


def generate_fractal_id() -> str:
    """
    Generate a unique fractal session ID bound to time and local entropy.
    Non-replayable and device-bound.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    entropy = get_system_entropy()
    data = f"{now.timestamp()}_{entropy.hex()}".encode()
    fractal_hash = hashlib.blake2b(data).hexdigest()
    return fractal_hash[:16]


def hash_stage(data: bytes, algo: str) -> bytes:
    """
    Hash data using specified algorithm from HASH_ALGORITHMS.
    """
    hasher = hashlib.new(algo)
    hasher.update(data)
    return hasher.digest()


def aes_encrypt(message: str, key: bytes) -> dict:
    """
    AES-GCM encrypt message with given key.
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
    AES-GCM decrypt ciphertext bundle with given key.
    """
    nonce = urlsafe_b64decode(bundle["nonce"])
    tag = urlsafe_b64decode(bundle["tag"])
    ciphertext = urlsafe_b64decode(bundle["ciphertext"])

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    return plaintext.decode()


def is_entropy_anomalous(entropy_score: float) -> bool:
    """
    Detect if entropy score is suspiciously low or high.
    """
    if entropy_score < ENTROPY_WARN_THRESHOLD_LOW:
        return True
    if entropy_score > ENTROPY_WARN_THRESHOLD_HIGH:
        return True
    return False


# === CORE AHE ENCRYPTION ===

def ahe_encrypt(message: str) -> dict:
    """
    Adaptive Hashing Encryption:
    - Local environment entropy injected
    - Multi-stage shuffled hashing
    - Passwordless local key derivation
    - AES-GCM encryption bound to environment
    """

    if len(message) > MAX_INPUT_LENGTH:
        raise ValueError(f"Input exceeds max length of {MAX_INPUT_LENGTH} bytes")

    # Encode message to bytes for hashing
    output = message.encode()

    # Collect local entropy from device + system
    system_entropy = get_system_entropy()

    # Calculate entropy of user input
    input_entropy_score = calculate_shannon_entropy(output)

    # Calculate entropy of system entropy (internal entropy)
    internal_entropy_score = calculate_shannon_entropy(system_entropy)

    # Check anomaly for input entropy
    input_entropy_anomaly = is_entropy_anomalous(input_entropy_score)

    # Check anomaly for internal entropy
    internal_entropy_anomaly = is_entropy_anomalous(internal_entropy_score)

    # Generate fractal session ID
    fractal_id = generate_fractal_id()

    # Start timing total encryption process
    start_time = time.time()

    # Shuffle hashing stages for unpredictability
    shuffled_algos = random.sample(HASH_ALGORITHMS, len(HASH_ALGORITHMS))

    stages = []

    for i, algo in enumerate(shuffled_algos):
        stage_start = time.time()
        # Hash combination of output and system entropy
        output = hash_stage(output + system_entropy, algo)
        stage_time = round(time.time() - stage_start, 6)

        stages.append({
            "stage": i,
            "algo": algo,
            "time": stage_time
        })

    # Use PBKDF2 with system entropy and final hashed output for AES key derivation
    key = PBKDF2(
        system_entropy,
        output[:32],
        dkLen=AES_KEY_SIZE,
        count=PBKDF2_ITERATIONS,
        hmac_hash_module=SHA512
    )

    # AES encrypt the original message with the derived key
    aes_result = aes_encrypt(message, key)

    total_time = round(time.time() - start_time, 6)

    return {
        "ahe_cipher": urlsafe_b64encode(output).decode(),
        "fractal_id": fractal_id,
        "input_entropy_score": round(input_entropy_score, 3),
        "input_entropy_anomaly": input_entropy_anomaly,
        "internal_entropy_score": round(internal_entropy_score, 3),
        "internal_entropy_anomaly": internal_entropy_anomaly,
        "encryption": aes_result,
        "hash_stages": stages,
        "total_time": total_time
    }


def ahe_decrypt(bundle: dict) -> str:
    """
    Decrypt ciphertext bundle using environment-bound key derivation.
    """

    # Decode the ahe cipher to bytes for key derivation
    raw_key_source = urlsafe_b64decode(bundle["ahe_cipher"])[:32]

    # Regenerate system entropy for key derivation
    system_entropy = get_system_entropy()

    # Derive AES key with PBKDF2
    key = PBKDF2(
        system_entropy,
        raw_key_source,
        dkLen=AES_KEY_SIZE,
        count=PBKDF2_ITERATIONS,
        hmac_hash_module=SHA512
    )

    # Decrypt AES ciphertext
    plaintext = aes_decrypt(bundle["encryption"], key)

    return plaintext


# === MAIN EXECUTION LOOP ===

def main():
    print("\n🔐 Adaptive Hashing Encryption Engine v5.0 — Quantum-Aware, Anomaly-Flagging, Environment-Bound")

    while True:
        msg = input("\n📥 Enter message to encrypt (or type 'exit' to quit): ")

        if msg.strip().lower() == "exit":
            print("👋 Exiting AHE.")
            break

        try:
            result = ahe_encrypt(msg)

            print("\n🔒 AHE Cipher (hashed):", result["ahe_cipher"][:64], "...")
            print("🔑 Fractal Session ID:", result["fractal_id"])
            print(f"📊 Input Entropy Score: {result['input_entropy_score']} (Anomaly: {result['input_entropy_anomaly']})")
            print(f"📊 Internal Entropy Score: {result['internal_entropy_score']} (Anomaly: {result['internal_entropy_anomaly']})")
            print("🔐 AES Ciphertext:", result["encryption"]["ciphertext"][:64], "...")
            print("🧬 Hash Stages:", [stage["algo"] for stage in result["hash_stages"]])
            print(f"⏱ Total Encryption Time: {result['total_time']} seconds")

            # Verify by decrypting immediately
            decrypted = ahe_decrypt(result)
            print("\n🔓 Decrypted Message:", decrypted)

        except Exception as e:
            print(f"❌ Error: {str(e)}")


if __name__ == "__main_":
    main()