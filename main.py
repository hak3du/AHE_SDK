from flask import Flask, request, jsonify, make_response
from core.core import encrypt_message, decrypt_latest
from flask_cors import CORS

app = Flask(__name__)
CORS(app, resources={r"/": {"origins": ""}})  # Allow all origins

# Helper function to add headers for every response
@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'  # allow all domains
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response

@app.route("/")
def home():
    return jsonify({"message": "AHE API is running."})

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

def build_cors_preflight_response():
    response = make_response()
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)


