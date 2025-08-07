Adaptive Hashing Encryption (AHE) SDK

Quantum-Safe, Anomaly-Driven Encryption for the Next Generation


---

🚀 Features

✅ Quantum-Safe (Kyber PQC)

✅ Adaptive Hashing + Entropy-based Security

✅ Zero Knowledge Assurance

✅ Anomaly Detection & Logging

✅ FastAPI REST API

✅ Cross-Platform Support (Windows, Linux, macOS)


---

📂 Project Structure

AHE_SDK/
├── api.py             # FastAPI entry point
├── core/              # Core encryption engine
├── crypto/            # AES & PQC cryptographic logic
├── kdf/               # Key derivation functions
├── utils/             # Entropy & anomaly tools
├── secure_storage/    # Encrypted files & metadata
├── tests/             # Unit tests
├── logger.py          # Logging utility
├── requirements.txt   # Dependencies
└── README.md


---

📦 Installation

1. Clone the Repository

git clone https://github.com/hak3du/AHE_SDK.git

cd AHE_SDK

2. Create Virtual Environment

# Linux/Mac
python3 -m venv ahe_env
source ahe_env/bin/activate

# Windows
python -m venv ahe_env
ahe_env\Scripts\activate

3. Install Dependencies

pip install -r requirements.txt

### 🔁 Option 1: Auto Setup (Windows - PowerShell)

Run this command from the project root:

powershell
./setup_end_run.ps1

If powershell refuses enter:
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
---

▶ Run the API

uvicorn api:app --host 0.0.0.0 --port 8000 --reload

API Docs:
Once running, visit:

Swagger UI: http://127.0.0.1:8000/docs

ReDoc: http://127.0.0.1:8000/redoc



---

✅ API Endpoints

Method	Endpoint	Description

GET	/health	Check API health
POST	/encrypt	Encrypt a message
POST	/decrypt	Decrypt latest message



---

🔐 Encrypt Example

curl -X POST "http://127.0.0.1:8000/encrypt" \
-H "Content-Type: application/json" \
-d '{"message": "Hello World", "password": "strong_pass"}'


---

🔓 Decrypt Example

curl -X POST "http://127.0.0.1:8000/decrypt" \
-H "Content-Type: application/json" \
-d '{"password": "strong_pass"}'


---

🧪 Run Tests

pytest tests/


---

🐳 Docker Support (Optional)

docker build -t ahe_sdk .
docker run -p 8000:8000 ahe_sdk


---

📜 License

⚠ License: Proprietary – All rights reserved.
Unauthorized reproduction or distribution is prohibited.


