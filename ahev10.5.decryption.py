import os
import random
import hashlib
import time
from base64 import urlsafe_b64encode, urlsafe_b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import oqs

AES_KEY_SIZE = 32
META_EXT = ".meta"
ENC_EXT = ".ahe"
PQC_KEMS = ["Kyber768", "Kyber512", "ML-KEM-768"]

def derive_key(password_bytes, pubkey_bytes, ciphertext_bytes):
    fusion = password_bytes + pubkey_bytes + ciphertext_bytes
    key = hashlib.sha3_512(fusion).digest()[:AES_KEY_SIZE]
    print(f"Derived key (SHA3-512 truncated): {key.hex()}")
    return key

def aes_encrypt(plaintext_bytes, key):
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext_bytes)
    print(f"AES encrypt: nonce({len(nonce)} bytes), tag({len(tag)} bytes), ciphertext({len(ciphertext)} bytes)")
    return ciphertext, nonce, tag

def aes_decrypt(ciphertext, nonce, tag, key):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    print(f"AES decrypt successful: plaintext length {len(plaintext)} bytes")
    return plaintext

def encrypt_file(filepath, password):
    print(f"\n--- Encryption start for: {filepath} ---")
    start_time = time.time()

    with open(filepath, "rb") as f:
        plaintext = f.read()
    print(f"Read plaintext: {len(plaintext)} bytes")

    kem_name = random.choice(PQC_KEMS)
    print(f"Selected PQC KEM: {kem_name}")
    kem = oqs.KeyEncapsulation(kem_name)

    pubkey = kem.generate_keypair()
    print(f"Generated public key: {len(pubkey)} bytes")

    ciphertext_kem, shared_secret = kem.encap_secret(pubkey)
    print(f"KEM ciphertext: {len(ciphertext_kem)} bytes")
    print(f"KEM shared secret: {len(shared_secret)} bytes")

    key = derive_key(password.encode(), pubkey, ciphertext_kem)

    ciphertext, nonce, tag = aes_encrypt(plaintext, key)

    out_enc_path = filepath + ENC_EXT
    out_meta_path = filepath + META_EXT

    with open(out_enc_path, "wb") as f:
        f.write(ciphertext)
    print(f"Encrypted data written to: {out_enc_path}")

    with open(out_meta_path, "wb") as f:
        f.write(urlsafe_b64encode(nonce) + b"\n")
        f.write(urlsafe_b64encode(tag) + b"\n")
        f.write(urlsafe_b64encode(pubkey) + b"\n")
        f.write(urlsafe_b64encode(ciphertext_kem) + b"\n")
        f.write(kem_name.encode() + b"\n")
    print(f"Metadata written to: {out_meta_path}")

    elapsed = time.time() - start_time
    print(f"Encryption completed in {elapsed:.4f} seconds")

def decrypt_file(enc_path, password):
    print(f"\n--- Decryption start for: {enc_path} ---")
    start_time = time.time()

    meta_path = enc_path.replace(ENC_EXT, META_EXT)
    if not os.path.exists(meta_path):
        raise FileNotFoundError(f"Metadata file not found: {meta_path}")
    print(f"Found metadata file: {meta_path}")

    with open(enc_path, "rb") as f:
        ciphertext = f.read()
    print(f"Read ciphertext: {len(ciphertext)} bytes")

    with open(meta_path, "rb") as f:
        lines = f.read().splitlines()
        nonce = urlsafe_b64decode(lines[0])
        tag = urlsafe_b64decode(lines[1])
        pubkey = urlsafe_b64decode(lines[2])
        ciphertext_kem = urlsafe_b64decode(lines[3])
        kem_name = lines[4].decode()
    print(f"Parsed metadata:")
    print(f" - nonce: {len(nonce)} bytes")
    print(f" - tag: {len(tag)} bytes")
    print(f" - pubkey: {len(pubkey)} bytes")
    print(f" - KEM ciphertext: {len(ciphertext_kem)} bytes")
    print(f" - KEM name: {kem_name}")

    kem = oqs.KeyEncapsulation(kem_name)
    kem.generate_keypair()  # initialize

    shared_secret = kem.decap_secret(ciphertext_kem)
    print(f"Decapsulated shared secret: {len(shared_secret)} bytes")

    key = derive_key(password.encode(), pubkey, ciphertext_kem)

    try:
        plaintext = aes_decrypt(ciphertext, nonce, tag, key)
    except Exception as e:
        print(f"ERROR during AES decrypt and verify: {e}")
        raise

    out_dec_path = enc_path.replace(ENC_EXT, ".dec")

    with open(out_dec_path, "wb") as f:
        f.write(plaintext)
    print(f"Decrypted file written to: {out_dec_path}")

    elapsed = time.time() - start_time
    print(f"Decryption completed in {elapsed:.4f} seconds")

def main():
    print("=== Adaptive Hashing Encryption v10.5 with Metrics ===")
    while True:
        print("\nOptions:")
        print("1. Encrypt a file")
        print("2. Decrypt a file")
        print("3. Exit")
        choice = input("Choice: ").strip()

        if choice == "1":
            path = input("File to encrypt: ").strip()
            pwd = input("Password: ").strip()
            encrypt_file(path, pwd)

        elif choice == "2":
            path = input(f"Encrypted file ({ENC_EXT}): ").strip()
            pwd = input("Password: ").strip()
            try:
                decrypt_file(path, pwd)
            except Exception as e:
                print(f"Error: {e}")

        elif choice == "3":
            print("Goodbye.")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()