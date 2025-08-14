from flask import Flask, request, jsonify
from core.core import encrypt_message, decrypt_latest
from flask_cors import CORS

app = Flask(__name__)from flask import Flask, request, jsonify, make_response
from core.core import encrypt_message, decrypt_latest
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Keep this as a backup, but we will explicitly set headers too

# Helper function to add CORS headers manually
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response

@app.route("/", methods=["GET", "OPTIONS"])
def home():
    if request.method == "OPTIONS":
        return add_cors_headers(make_response())
    response = jsonify({"message": "AHE API is running."})
    return add_cors_headers(response)

@app.route("/encrypt", methods=["POST", "OPTIONS"])
def encrypt():
    if request.method == "OPTIONS":
        return add_cors_headers(make_response())
    
    try:
        data = request.get_json()
        message = data.get("message")
        password = data.get("password")

        if not message or not password:
            response = jsonify({"error": "Message and password are required."})
            return add_cors_headers(response), 400

        encrypted = encrypt_message(message, password)
        response = jsonify({"encrypted": encrypted})
        return add_cors_headers(response)

    except Exception as e:
        response = jsonify({"error": str(e)})
        return add_cors_headers(response), 500

@app.route("/decrypt", methods=["POST", "OPTIONS"])
def decrypt():
    if request.method == "OPTIONS":
        return add_cors_headers(make_response())
    
    try:
        data = request.get_json()
        password = data.get("password")

        if not password:
            response = jsonify({"error": "Password is required."})
            return add_cors_headers(response), 400

        decrypted = decrypt_latest(password)
        response = jsonify({"decrypted": decrypted})
        return add_cors_headers(response)

    except Exception as e:
        response = jsonify({"error": str(e)})
        return add_cors_headers(response), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

# Allow all origins and methods for all routes
CORS(app, resources={r"/*": {"origins": "*"}}, methods=["GET", "POST", "OPTIONS"])

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



