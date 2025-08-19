# main.py
from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
from core.core import encrypt_message, decrypt_latest
import os

app = Flask(__name__)

# ---------------------------
# GLOBAL CORS CONFIG
# ---------------------------
# Allow all routes, all methods, all headers
# For credentials: set to True if you need cookies/auth headers
# If True, DO NOT use "*" for origins; set your frontend domain instead
FRONTEND_DOMAIN = "https://hak3du.github.io"

CORS(
    app,
    resources={r"/*": {"origins": FRONTEND_DOMAIN}},
    supports_credentials=True,
    allow_headers=["Content-Type", "Authorization"],
    methods=["GET", "POST", "OPTIONS", "PUT", "DELETE", "PATCH"]
)

# ---------------------------
# HANDLE PRE-FLIGHT OPTIONS
# ---------------------------
@app.before_request
def handle_options():
    if request.method == "OPTIONS":
        response = make_response()
        response.headers.add("Access-Control-Allow-Origin", FRONTEND_DOMAIN)
        response.headers.add("Access-Control-Allow-Methods", "GET,POST,OPTIONS,PUT,DELETE,PATCH")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type, Authorization")
        response.headers.add("Access-Control-Allow-Credentials", "true")
        return response, 200

# ---------------------------
# ROUTES
# ---------------------------
@app.route("/")
def home():
    return jsonify({"message": "AHE API is running."})

@app.route("/encrypt", methods=["POST", "OPTIONS"])
def encrypt():
    if request.method == "OPTIONS":
        # OPTIONS handled globally via before_request, just in case
        response = make_response()
        response.headers.add("Access-Control-Allow-Origin", FRONTEND_DOMAIN)
        response.headers.add("Access-Control-Allow-Methods", "POST, OPTIONS")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type, Authorization")
        response.headers.add("Access-Control-Allow-Credentials", "true")
        return response, 200

    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON payload."}), 400

        message = data.get("message")
        password = data.get("password")
        if not message or not password:
            return jsonify({"error": "Message and password are required."}), 400

        encrypted_data = encrypt_message(message, password)

        response = {
            "status": "success",
            "encrypted": encrypted_data.get("ciphertext"),
            "ciphertext_path": encrypted_data.get("ciphertext_path"),
            "metadata_path": encrypted_data.get("metadata_path"),
            "pqc_profile": encrypted_data.get("pqc_profile"),
            "entropy_score": encrypted_data.get("entropy_score"),
            "anomaly_detected": encrypted_data.get("anomaly_detected", False)
        }
        return jsonify(response)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/decrypt", methods=["POST", "OPTIONS"])
def decrypt():
    if request.method == "OPTIONS":
        response = make_response()
        response.headers.add("Access-Control-Allow-Origin", FRONTEND_DOMAIN)
        response.headers.add("Access-Control-Allow-Methods", "POST, OPTIONS")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type, Authorization")
        response.headers.add("Access-Control-Allow-Credentials", "true")
        return response, 200

    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON payload."}), 400

        password = data.get("password")
        if not password:
            return jsonify({"error": "Password is required."}), 400

        decrypted_data = decrypt_latest(password)

        response = {
            "status": "success",
            "decrypted": decrypted_data.get("plaintext"),
            "entropy_score": decrypted_data.get("entropy_score"),
            "anomaly_detected": decrypted_data.get("anomaly_detected", False)
        }
        return jsonify(response)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---------------------------
# RUN SERVER
# ---------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
