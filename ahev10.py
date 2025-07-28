import os
import random
import hashlib
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
    return hashlib.sha3_512(fusion).digest()[:AES_KEY_SIZE]

def aes_encrypt(plaintext_bytes, key):
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext_bytes)
    return ciphertext, nonce, tag

def aes_decrypt(ciphertext, nonce, tag, key):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def encrypt_file(filepath, password):
    with open(filepath, "rb") as f:
        plaintext = f.read()

    kem_name = random.choice(PQC_KEMS)
    kem = oqs.KeyEncapsulation(kem_name)

    pubkey = kem.generate_keypair()
    ciphertext_kem, shared_secret = kem.encap_secret(pubkey)

    key = derive_key(password.encode(), pubkey, ciphertext_kem)

    ciphertext, nonce, tag = aes_encrypt(plaintext, key)

    out_enc_path = filepath + ENC_EXT
    out_meta_path = filepath + META_EXT

    with open(out_enc_path, "wb") as f:
        f.write(ciphertext)

    with open(out_meta_path, "wb") as f:
        f.write(urlsafe_b64encode(nonce) + b"\n")
        f.write(urlsafe_b64encode(tag) + b"\n")
        f.write(urlsafe_b64encode(pubkey) + b"\n")
        f.write(urlsafe_b64encode(ciphertext_kem) + b"\n")
        f.write(kem_name.encode() + b"\n")

    print(f"Encrypted to {out_enc_path} with metadata {out_meta_path}")

def decrypt_file(enc_path, password):
    meta_path = enc_path.replace(ENC_EXT, META_EXT)
    if not os.path.exists(meta_path):
        raise FileNotFoundError(f"Metadata file not found: {meta_path}")

    with open(enc_path, "rb") as f:
        ciphertext = f.read()

    with open(meta_path, "rb") as f:
        lines = f.read().splitlines()
        nonce = urlsafe_b64decode(lines[0])
        tag = urlsafe_b64decode(lines[1])
        pubkey = urlsafe_b64decode(lines[2])
        ciphertext_kem = urlsafe_b64decode(lines[3])
        kem_name = lines[4].decode()

    kem = oqs.KeyEncapsulation(kem_name)
    kem.generate_keypair()  # initialize

    shared_secret = kem.decap_secret(ciphertext_kem)

    key = derive_key(password.encode(), pubkey, ciphertext_kem)

    plaintext = aes_decrypt(ciphertext, nonce, tag, key)

    out_dec_path = enc_path.replace(ENC_EXT, ".dec")

    with open(out_dec_path, "wb") as f:
        f.write(plaintext)

    print(f"Decrypted to {out_dec_path}")

def main():
    print("=== Adaptive Hashing Encryption v10.5 ===")
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