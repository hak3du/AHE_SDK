# main.py
from flask import Flask, request, jsonify
from flask_cors import CORS
from core.core import encrypt_message, decrypt_latest
import os

# Initialize Flask app
app = Flask(__name__)

# ---------------------------
# CORS Setup
# ---------------------------
# Allow only your portfolio domain, enable credentials, force headers and methods
CORS(app, resources={r"/*": {"origins": ["https://hak3du.github.io"]}}, 
     supports_credentials=True, 
     allow_headers=["Content-Type", "Authorization"], 
     methods=["GET", "POST", "OPTIONS"])

# ---------------------------
# Routes
# ---------------------------
@app.route("/")
def home():
    return jsonify({"message": "AHE API is running."})

@app.route("/encrypt", methods=["POST"])
def encrypt():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON payload."}), 400

        message = data.get("message")
        password = data.get("password")
        if not message or not password:
            return jsonify({"error": "Message and password are required."}), 400

        # Call encryption logic from core
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
        return jsonify({"error": "Internal server error."}), 500

@app.route("/decrypt", methods=["POST"])
def decrypt():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON payload."}), 400

        password = data.get("password")
        if not password:
            return jsonify({"error": "Password is required."}), 400

        # Call decryption logic from core
        decrypted_data = decrypt_latest(password)

        response = {
            "status": "success",
            "decrypted": decrypted_data.get("plaintext"),
            "entropy_score": decrypted_data.get("entropy_score"),
            "anomaly_detected": decrypted_data.get("anomaly_detected", False)
        }
        return jsonify(response)
    except Exception as e:
        return jsonify({"error": "Internal server error."}), 500

# ---------------------------
# Run server
# ---------------------------
if __name__ == "__main__":
    # Use Railway dynamic PORT if available
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
