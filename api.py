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
# Add all frontend domains you want to allow
origins = [
    "http://localhost:3000",               # your local HTML
    "https://your-frontend-domain.com"    # hosted frontend domain
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
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
        return {
            "status": "success",
            "ciphertext_path": data.get("ciphertext_path"),
            "metadata_path": data.get("metadata_path"),
            "pqc_profile": data.get("pqc_profile"),
            "entropy_score": data.get("entropy_score"),
            "anomaly_detected": data.get("anomaly_detected")
        }
    except Exception as e:
        logger.error(f"[ENCRYPT ERROR] {str(e)}")
        raise HTTPException(status_code=500, detail="Encryption failed")

@app.post("/decrypt", response_model=DecryptResponse)
async def decrypt(req: DecryptRequest):
    try:
        logger.info("[DECRYPT] Processing request...")
        data = decrypt_latest(req.password)
        return {
            "status": "success",
            "decrypted_message": data.get("decrypted_message"),
            "pqc_profile": data.get("pqc_profile"),
            "entropy_score": data.get("entropy_score"),
            "anomaly_detected": data.get("anomaly_detected")
        }
    except Exception as e:
        logger.error(f"[DECRYPT ERROR] {str(e)}")
        raise HTTPException(status_code=500, detail="Decryption failed")

# ---------------------------
# DEBUG ROUTE
# ---------------------------
import os
@app.get("/debug-files")
async def debug_files():
    # Check for templates folder (even if FastAPI isn't serving HTML)
    templates_exist = os.path.isdir("templates")
    files = os.listdir("templates") if templates_exist else []
    return {"templates_exist": templates_exist, "templates_files": files}
