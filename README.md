Adaptive Hashing Encryption (AHE) SDK

Quantum-Safe, Anomaly-Driven Encryption for the Next Generation


---

🚀 Features

✅ Quantum-Safe (Kyber PQC)

✅ Adaptive Hashing + Entropy

✅ Zero Knowledge Assurance

✅ FastAPI REST API

✅ Cross-Platform Support



---

📦 Installation

1. Clone the repository

git clone https://github.com/YOUR_USERNAME/AHE_SDK.git
cd AHE_SDK

2. Create virtual environment

python3 -m venv ahe_env
source ahe_env/bin/activate   # Linux/Mac
ahe_env\Scripts\activate      # Windows

3. Install dependencies

pip install -r requirements.txt


---

▶ Run the API

uvicorn api:app --host 0.0.0.0 --port 8000 --reload


---

✅ API Endpoints

Method	Endpoint	Description

GET	/health	Check API status
POST	/encrypt	Encrypt message
POST	/decrypt	Decrypt latest message



---

Encrypt Example

curl -X POST "http://127.0.0.1:8000/encrypt" \
-H "Content-Type: application/json" \
-d '{"message": "Hello World", "password": "strong_pass"}'