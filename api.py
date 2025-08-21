from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from core.core import encrypt_message, decrypt_latest
from logger import logger
from schemas import (
    EncryptRequest,
    EncryptResponse,
    DecryptRequest,
    DecryptResponse,
    HealthResponse
)
import os

# ---------------------------
# FASTAPI APP
# ---------------------------
app = FastAPI(
    title="Adaptive Hashing Encryption API",
    description="Elite Quantum-Safe Encryption API",
    version="1.0.0"
)

# ---------------------------
# CORS CONFIGURATION
# ---------------------------
# Allow any origin (so JS can call from anywhere, including local HTML)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------
# OPENAPI CUSTOMIZATION
# ---------------------------
original_openapi = app.openapi
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = original_openapi()
    for path in openapi_schema.get("paths", {}).values():
        for method in path.values():
            responses = method.get("responses", {})
            responses.pop("422", None)
            responses.pop("500", None)
    app.openapi_schema = openapi_schema
    return app.openapi_schema
app.openapi = custom_openapi

# ---------------------------
# HEALTH CHECK
# ---------------------------
@app.get("/health", response_model=HealthResponse)
async def health_check():
    return {"status": "healthy"}

# ---------------------------
# ENCRYPT / DECRYPT ROUTES
# ---------------------------
@app.post("/encrypt", response_model=EncryptResponse)
async def encrypt(req: EncryptRequest):
    try:
        logger.info("[ENCRYPT] Processing request...")
        data = encrypt_message(req.message, req.password)
        # Match exactly what JS expects
        return {
            "status": "success",
            "encrypted": data.get("ciphertext_path"),  # this is what JS reads
        }
    except Exception as e:
        logger.error(f"[ENCRYPT ERROR] {str(e)}")
        raise HTTPException(status_code=500, detail="Encryption failed")

@app.post("/decrypt", response_model=DecryptResponse)
async def decrypt(req: DecryptRequest):
    try:
        logger.info("[DECRYPT] Processing request...")
        data = decrypt_latest(req.password)
        # Match exactly what JS expects
        return {
            "status": "success",
            "decrypted": data.get("decrypted_message"),
        }
    except Exception as e:
        logger.error(f"[DECRYPT ERROR] {str(e)}")
        raise HTTPException(status_code=500, detail="Decryption failed")

# ---------------------------
# DEBUG ROUTE
# ---------------------------
@app.get("/debug-files")
async def debug_files():
    templates_exist = os.path.isdir("templates")
    files = os.listdir("templates") if templates_exist else []
    return {"templates_exist": templates_exist, "templates_files": files}
