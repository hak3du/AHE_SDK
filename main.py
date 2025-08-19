from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from core.core import encrypt_message, decrypt_latest
import os

# Initialize Flask with frontend folder
app = Flask(__name__, static_folder="frontend", static_url_path="")

# Enable CORS for API calls
CORS(app, resources={r"/encrypt": {"origins": "*"}, r"/decrypt": {"origins": "*"}})

# ---------------------------
# SERVE FRONTEND
# ---------------------------
@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve_frontend(path):
    full_path = os.path.join(app.static_folder, path)
    if path != "" and os.path.exists(full_path):
        return send_from_directory(app.static_folder, path)
    else:
        # fallback to index.html for any unmatched route
        return send_from_directory(app.static_folder, "index.html")

# ---------------------------
# API ROUTES
# ---------------------------
@app.route("/encrypt", methods=["POST"])
def encrypt():
    data = request.get_json()
    message = data.get("message")
    password = data.get("password")
    if not message or not password:
        return jsonify({"error": "Message and password are required."}), 400
    encrypted = encrypt_message(message, password)
    return jsonify({"encrypted": encrypted})

@app.route("/decrypt", methods=["POST"])
def decrypt():
    data = request.get_json()
    password = data.get("password")
    if not password:
        return jsonify({"error": "Password is required."}), 400
    decrypted = decrypt_latest(password)
    return jsonify({"decrypted": decrypted})

# ---------------------------
# RUN SERVER
# ---------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))  # use Railway's dynamic PORT
    app.run(host="0.0.0.0", port=port, debug=True)
