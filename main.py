from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from core.core import encrypt_message, decrypt_latest

app = Flask(__name__, template_folder="templates")  # templates folder for index.html
CORS(app, resources={r"/encrypt": {"origins": "*"}, r"/decrypt": {"origins": "*"}})

# Serve frontend
@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve_frontend(path):
    return render_template("index.html")  # Always render index.html

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
# DEBUG: Confirm templates exist
# ---------------------------
@app.route("/debug-files")
def debug_files():
    import os
    files = [f for f in os.listdir(app.template_folder)]
    return jsonify({"templates": files})

# ---------------------------
# RUN SERVER
# ---------------------------
if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port)
