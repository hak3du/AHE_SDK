from flask import Flask, request, jsonify, make_response
from core.core import encrypt_message, decrypt_latest

app = Flask(__name__)

# Universal CORS headers function
def set_cors_headers(resp):
    resp.headers['Access-Control-Allow-Origin'] = '*'  # allow all domains
    resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    resp.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    resp.headers['Access-Control-Allow-Credentials'] = 'true'
    return resp

# Handle preflight globally
@app.before_request
def handle_options_requests():
    if request.method == 'OPTIONS':
        resp = make_response()
        return set_cors_headers(resp)

@app.after_request
def apply_cors_headers(response):
    return set_cors_headers(response)

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
    app.run(host="0.0.0.0", port=5000, debug=True)
