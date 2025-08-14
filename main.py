# main.py
from flask import Flask, request, jsonify
from core.core import encrypt_message, decrypt_latest
from flask_cors import CORS

app = Flask(__name__)

# Enable CORS for all routes and origins
CORS(app, resources={r"/*": {"origins": "*"}})

@app.route("/")
def home():
    return jsonify({"message": "AHE API is running."})

@app.route("/encrypt", methods=["POST"])
def encrypt():
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

@app.route("/decrypt", methods=["POST"])
def decrypt():
    try:
        data = request.get_json()
        password = data.get("password")

        if not password:
            return jsonify({"error": "Password is required."}), 400

        decrypted = decrypt_latest(password)
        return jsonify({"decrypted": decrypted})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)






