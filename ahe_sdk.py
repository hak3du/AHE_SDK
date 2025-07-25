"""
=========================================================
AHE SDK Wrapper
=========================================================
Provides a clean interface for developers to use AHE encryption
and decryption without dealing with internal core logic.

Features:
- Class-based interface for scalability
- Simple methods: encrypt() and decrypt()
- Returns structured JSON-like results
"""

import os
from core.core import encrypt_message, decrypt_latest
from logger import logger

class AHEClient:
    def _init_(self, storage_dir="secure_storage"):
        self.storage_dir = storage_dir
        if not os.path.exists(self.storage_dir):
            os.makedirs(self.storage_dir)
        logger.info("[INIT] AHEClient initialized with storage directory")

    def encrypt(self, message: str, password: str) -> dict:
        """
        Encrypt a message using AHE and return metadata info.
        """
        logger.info("[SDK] Encrypt called via SDK")
        try:
            encrypt_message(message, password)
            return {
                "status": "success",
                "message": "Message encrypted and stored securely.",
                "storage_dir": self.storage_dir
            }
        except Exception as e:
            logger.error(f"[SDK ERROR] Encryption failed: {str(e)}")
            return {"status": "error", "error": str(e)}

    def decrypt(self, password: str) -> dict:
        """
        Decrypt the latest message using AHE.
        """
        logger.info("[SDK] Decrypt called via SDK")
        try:
            plaintext = decrypt_latest(password)
            return {
                "status": "success",
                "plaintext": plaintext
            }
        except Exception as e:
            logger.error(f"[SDK ERROR] Decryption failed: {str(e)}")
            return {"status": "error", "error": str(e)}