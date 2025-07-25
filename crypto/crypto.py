from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from logger import logger

# AES-GCM ENCRYPTION
def aes_encrypt(message, key: bytes) -> tuple:
    """
    Encrypts message using AES-GCM.
    Accepts str or bytes.
    Returns (ciphertext, nonce, tag) as raw bytes.
    """
    logger.info("Starting AES encryption process")
    try:
        if isinstance(message, str):
            message = message.encode()
        elif not isinstance(message, bytes):
            raise TypeError("Message must be str or bytes")

        nonce = get_random_bytes(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(message)

        logger.info("AES encryption completed successfully")
        return ciphertext, nonce, tag
    except Exception as e:
        logger.error(f"AES encryption failed: {e}", exc_info=True)
        raise


# AES-GCM DECRYPTION
def aes_decrypt(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes) -> bytes:
    """
    Decrypts AES-GCM encrypted data.
    Returns plaintext as bytes.
    """
    logger.info("Starting AES decryption process")
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        logger.info("AES decryption completed successfully")
        return plaintext
    except Exception as e:
        logger.error(f"AES decryption failed: {e}", exc_info=True)
        raise