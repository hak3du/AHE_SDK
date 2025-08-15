from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
from core.core import encrypt_message, decrypt_latest

app = Flask(__name__)

# Enable CORS for all routes and allow requests from your front-end origin
CORS(app, resources={r"/*": {"origins": ["https://hak3du.github.io"]}}, supports_credentials=True)

@app.before_request
def handle_options_request():
    if request.method == "OPTIONS":
        response = make_response()
        response.headers.add("Access-Control-Allow-Origin", "https://hak3du.github.io")
        response.headers.add("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type, Authorization")
        response.headers.add("Access-Control-Allow-Credentials", "true")
        return response, 200

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

        # Call the encryption function
        encrypted_data = encrypt_message(message, password)

        # Example: Add additional fields to the response
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

@app.route("/decrypt", methods=["POST"])
def decrypt():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON payload."}), 400

        password = data.get("password")
        if not password:
            return jsonify({"error": "Password is required."}), 400

        # Call the decryption function
        decrypted_data = decrypt_latest(password)

        # Example: Add additional fields to the response
        response = {
            "status": "success",
            "decrypted": decrypted_data.get("plaintext"),
            "entropy_score": decrypted_data.get("entropy_score"),
            "anomaly_detected": decrypted_data.get("anomaly_detected", False)
        }
        return jsonify(response)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
