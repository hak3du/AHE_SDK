from flask import Flask, request, jsonify, make_response, send_from_directory
from flask_cors import CORS
from core.core import encrypt_message, decrypt_latest
import os

# Initialize Flask app with frontend folder
app = Flask(__name__, static_folder="frontend", static_url_path="")

# Enable CORS globally
CORS(app, resources={r"/": {"origins": ""}}, supports_credentials=True)

# ---------------------------
# SERVE FRONTEND
# ---------------------------
@app.route("/")
def serve_frontend():
    return send_from_directory(app.static_folder, "index.html")

# ---------------------------
# API ROUTES
# ---------------------------
@app.route("/encrypt", methods=["POST", "OPTIONS"])
def encrypt():
    if request.method == "OPTIONS":
        return build_cors_preflight_response()
    try:
        data = request.get_json()
        message = data.get("message")
        password = data.get("password")
        if not message or not password:
            return jsonify({"error": "Message and password are required."}), 400
        encrypted = encrypt_message(message, password)
        return jsonify({"encrypted": encrypted})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/decrypt", methods=["POST", "OPTIONS"])
def decrypt():
    if request.method == "OPTIONS":
        return build_cors_preflight_response()
    try:
        data = request.get_json()
        password = data.get("password")
        if not password:
            return jsonify({"error": "Password is required."}), 400
        decrypted = decrypt_latest(password)
        return jsonify({"decrypted": decrypted})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------
# CORS Preflight Response
# ---------------------------
def build_cors_preflight_response():
    response = make_response()
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response


# ---------------------------
# RUN SERVER
# ---------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
