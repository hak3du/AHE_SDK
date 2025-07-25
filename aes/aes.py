# AES/aes.py
from base64 import urlsafe_b64encode, urlsafe_b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from logger import logger

def aes_encrypt(message: str, key: bytes) -> dict:
    logger.info("Starting AES encryption")
    try:
        nonce = get_random_bytes(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(message.encode())

        logger.info("AES encryption successful")
        return {
            "ciphertext": urlsafe_b64encode(ciphertext).decode(),
            "nonce": urlsafe_b64encode(nonce).decode(),
            "tag": urlsafe_b64encode(tag).decode()
        }
    except Exception as e:
        logger.error(f"AES encryption failed: {e}", exc_info=True)
        raise  # Propagate error upward for handling at SDK/API level

def aes_decrypt(bundle: dict, key: bytes) -> str:
    logger.info("Starting AES decryption")
    try:
        nonce = urlsafe_b64decode(bundle["nonce"])
        tag = urlsafe_b64decode(bundle["tag"])
        ciphertext = urlsafe_b64decode(bundle["ciphertext"])
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        logger.info("AES decryption successful")
        return plaintext.decode()
    except Exception as e:
        logger.error(f"AES decryption failed: {e}", exc_info=True)
        raise