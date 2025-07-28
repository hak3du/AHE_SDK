# === Adaptive Hashing Encryption (AHE) v9 with PQCrypto Kyber512 + Dilithium2 ===

import os
import time
import math
import hashlib
import random
from base64 import urlsafe_b64encode, urlsafe_b64decode
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import HKDF, PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from pqcrypto.kem.kyber512 import generate_keypair as kem_keypair, encrypt as kem_encaps, decrypt as kem_decaps
from pqcrypto.sign.dilithium2 import generate_keypair as sign_keypair, sign, verify

# === Configuration constants ===
AES_KEY_SIZE = 32
HASH_ALGOS = ["sha3_512", "blake2b", "sha512", "sha3_256"]

# === Utility functions ===

def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {b: data.count(b) / len(data) for b in set(data)}
    return -sum(p * math.log2(p) for p in freq.values())

def aes_encrypt(plaintext: str, key: bytes) -> dict:
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
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

# === Core AHE functions ===

def ahe_encrypt_v9(message: str) -> dict:
    # 1. Entropy scoring
    entropy_seed = os.urandom(16)
    entropy_score = calculate_entropy(entropy_seed)

    # 🔐 Kyber512 KEM
    kem_pk, kem_sk = kem_keypair()
    kem_ct, kem_ss = kem_encaps(kem_pk)

    # Derive AES key via HKDF
    aes_key = HKDF(kem_ss, AES_KEY_SIZE, entropy_seed, SHA256)

    aes_bundle = aes_encrypt(message, aes_key)

    # Multi-stage hashing + undecidability
    fused = hashlib.blake2b(entropy_seed + message.encode()).digest()
    fused += bytes([sum(fused) % 127])
    for algo in random.sample(HASH_ALGOS, len(HASH_ALGOS)):
        fused = hashlib.new(algo, fused).digest()
    final_hash = urlsafe_b64encode(fused).decode()

    # Dilithium2 signing
    sign_pk, sign_sk = sign_keypair()
    signature = sign(fused, sign_sk)

    return {
        "aes_bundle": aes_bundle,
        "kem_ciphertext": urlsafe_b64encode(kem_ct).decode(),
        "kem_secret_key": urlsafe_b64encode(kem_sk).decode(),
        "entropy_seed": urlsafe_b64encode(entropy_seed).decode(),
        "final_hash": final_hash,
        "sign_public_key": urlsafe_b64encode(sign_pk).decode(),
        "signature": urlsafe_b64encode(signature).decode()
    }

def ahe_decrypt_v9(payload: dict) -> str:
    entropy_seed = urlsafe_b64decode(payload["entropy_seed"])
    kem_ct = urlsafe_b64decode(payload["kem_ciphertext"])
    kem_sk = urlsafe_b64decode(payload["kem_secret_key"])
    kem_ss = kem_decaps(kem_ct, kem_sk)

    aes_key = HKDF(kem_ss, AES_KEY_SIZE, entropy_seed, SHA256)
    plaintext = aes_decrypt(payload["aes_bundle"], aes_key)

    fused = hashlib.blake2b(entropy_seed + plaintext.encode()).digest()
    fused += bytes([sum(fused) % 127])
    for algo in HASH_ALGOS:  # same order assumed
        fused = hashlib.new(algo, fused).digest()
    final_hash = urlsafe_b64encode(fused).decode()

    # Verify Dilithium signature
    sign_pk = urlsafe_b64decode(payload["sign_public_key"])
    signature = urlsafe_b64decode(payload["signature"])
    if not verify(fused, signature, sign_pk):
        raise ValueError("Signature verification failed — integrity breached")

    if final_hash != payload["final_hash"]:
        raise ValueError("Final hash mismatch — tampering detected")

    return plaintext

# === Execution ===

def main():
    print("\n🔐 Adaptive Hashing Encryption v9 with Kyber512 + Dilithium2")
    while True:
        cmd = input("[E]ncrypt / [D]ecrypt / [Q]uit: ").strip().lower()
        if cmd == "e":
            msg = input("Enter message: ")
            payload = ahe_encrypt_v9(msg)
            print("\n📦 Payload:")
            print(payload)
        elif cmd == "d":
            import ast
            data = input("Paste payload dict: ")
            payload = ast.literal_eval(data)
            try:
                text = ahe_decrypt_v9(payload)
                print(f"\n✅ Decrypted: {text}")
            except Exception as e:
                print(f"\n❌ Error: {e}")
        elif cmd == "q":
            print("Goodbye.")
            break
        else:
            print("Invalid option.")

if __name__ == "__main__":
    main()