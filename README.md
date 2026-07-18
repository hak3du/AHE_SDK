# 🛡️ Adaptive Hashing Encryption (Hybrid Quantum Encryption Kit)

> **Adaptive, modular cryptographic software exploring secure encryption workflows, post-quantum primitives, and intelligent security engineering.**

---

## 🚀 Overview

Adaptive Hashing Encryption (AHE) is a Python-based software development kit designed to explore modern cryptographic engineering through a modular architecture. The project combines symmetric encryption, post-quantum cryptographic components, secure key management, anomaly monitoring, and RESTful APIs into a unified platform for research, prototyping, and secure application development.

Rather than focusing on a single encryption algorithm, AHE provides an extensible framework where multiple security components can work together while remaining modular and independently maintainable.

---

# ✨ Highlights

* 🔐 Adaptive encryption workflows
* ⚛️ Post-Quantum Cryptography integration (Kyber/liboqs)
* 🔑 Secure key derivation
* 📊 Entropy-aware security components
* 🛡️ Secure storage support
* 🌐 FastAPI REST interface
* 📜 Security logging
* 🐳 Docker support
* 🖥️ Cross-platform compatibility
* 🧩 Modular architecture

---

# 🏗️ Architecture

```text
                Client
                   │
            FastAPI Interface
                   │
        ┌──────────┴──────────┐
        │                     │
 Encryption Engine      Security Services
        │                     │
 ┌──────┴──────┐       ┌──────┴──────┐
 │             │       │             │
AES        PQC Layer  Logging   Secure Storage
 │             │
 └──────┬──────┘
        │
 Key Derivation
        │
 Adaptive Hashing
```

---

# 📂 Project Structure

```text
AHE_SDK/
├── aes/
├── core/
├── crypto/
├── kdf/
├── pqc/
├── secure_storage/
├── templates/
├── tests/
├── utils/
├── api.py
├── sdk.py
├── main.py
└── README.md
```

---

# ⚡ Installation

```bash
git clone https://github.com/hak3du/AHE_SDK.git
cd AHE_SDK

python -m venv venv

# Windows
venv\Scripts\activate

# Linux/macOS
source venv/bin/activate

pip install -r requirements.txt
```

---

# ▶️ Running the API

```bash
uvicorn api:app --reload
```

Documentation becomes available at:

* 📘 `/docs`
* 📙 `/redoc`

---

# 🔐 API Endpoints

| Method | Endpoint   | Description    |
| ------ | ---------- | -------------- |
| GET    | `/health`  | Service health |
| POST   | `/encrypt` | Encrypt data   |
| POST   | `/decrypt` | Decrypt data   |

---

# 🧪 Testing

```bash
pytest tests/
```

---

# 🐳 Docker

Build:

```bash
docker build -t ahe_sdk .
```

Run:

```bash
docker run -p 8000:8000 ahe_sdk
```

---

# 🛣️ Roadmap

* ✅ Modular encryption engine
* ✅ FastAPI integration
* ✅ Post-Quantum cryptography support
* 🔄 Performance benchmarking
* 🔄 Extended automated testing
* 🔄 Enhanced API documentation
* 🔄 Plugin architecture
* 🔄 Additional cryptographic algorithms

---

# 🤝 Contributing

Contributions, issues, feature requests, and constructive feedback are welcome. Please open an issue before submitting significant architectural changes so they can be discussed.

---

# 📄 License

This repository is released under the license included with this project. See the `LICENSE` file for details.

---

## 💡 Engineering Philosophy

> Secure software is more than algorithms. It is the discipline of building systems where security, performance, maintainability, and simplicity reinforce one another.

Adaptive Hashing Encryption is an ongoing exploration of that philosophy.
