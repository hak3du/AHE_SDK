from fastapi import FastAPI, HTTPException
from core.core import encrypt_message, decrypt_latest
from logger import logger
from schemas import (
    EncryptRequest,
    EncryptResponse,
    DecryptRequest,
    DecryptResponse,
    HealthResponse
)

app = FastAPI(
    title="Adaptive Hashing Encryption API",
    description="Elite Quantum-Safe Encryption API",
    version="1.0.0"
)

# Remove 422 & 500 from docs
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

@app.get("/health", response_model=HealthResponse)
async def health_check():
    return {"status": "healthy"}

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