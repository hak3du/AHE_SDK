from pydantic import BaseModel
from typing import Optional

class EncryptRequest(BaseModel):
    message: str
    password: str

class EncryptResponse(BaseModel):
    status: str
    ciphertext_path: Optional[str]
    metadata_path: Optional[str]
    pqc_profile: Optional[str]
    entropy_score: Optional[float]
    anomaly_detected: Optional[bool]

class DecryptRequest(BaseModel):
    password: str

class DecryptResponse(BaseModel):
    status: str
    decrypted_message: Optional[str]
    pqc_profile: Optional[str]
    entropy_score: Optional[float]
    anomaly_detected: Optional[bool]

class HealthResponse(BaseModel):
    status: str