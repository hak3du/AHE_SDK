from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
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
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins
    allow_credentials=False,  # Set to False to avoid browser CORS errors
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
# SERVE INDEX.HTML FROM TEMPLATES
# ---------------------------
@app.get("/", include_in_schema=False)
async def serve_index():
    index_path = os.path.join("templates", "index.html")
    if os.path.isfile(index_path):
        return FileResponse(index_path)
    raise HTTPException(status_code=404, detail="index.html not found")

# ---------------------------
# HEALTH CHECK
# ---------------------------
@app.get("/health", response_model=HealthResponse)
async def health_check():
    return {"status": "healthy"}

# ---------------------------
# ENCRYPT ROUTE
# ---------------------------
@app.post("/encrypt", response_model=EncryptResponse)
async def encrypt(req: EncryptRequest):
    try:
        logger.info("[ENCRYPT] Processing request...")
        data = encrypt_message(req.message, req.password)

        # Map backend return keys to Pydantic model
        ciphertext_path = data.get("ciphertext") or data.get("encrypted")

        return {
            "status": "success",
            "ciphertext_path": ciphertext_path,  # matches EncryptResponse
        }

    except Exception as e:
        logger.error(f"[ENCRYPT ERROR] {str(e)}")
        raise HTTPException(status_code=500, detail="Encryption failed")

# ---------------------------
# DECRYPT ROUTE
# ---------------------------
@app.post("/decrypt", response_model=DecryptResponse)
async def decrypt(req: DecryptRequest):
    try:
        logger.info("[DECRYPT] Processing request...")
        data = decrypt_latest(req.password)

        # Map backend return keys to Pydantic model
        decrypted_message = data.get("decrypted_message") or data.get("decrypted")

        return {
            "status": "success",
            "decrypted_message": decrypted_message,  # matches DecryptResponse
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
