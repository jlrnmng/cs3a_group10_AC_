from flask import Flask, render_template, request, jsonify, send_file
from symmetric_algorithms import encrypt_text as sym_encrypt, decrypt_text as sym_decrypt
from symmetric_algorithms import encrypt_file as sym_encrypt_file, decrypt_file as sym_decrypt_file
from asymmetric_algorithms import encrypt_text as asym_encrypt, decrypt_text as asym_decrypt
from hash_functions import hash_text, hash_file
from werkzeug.utils import secure_filename
import os
import io

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt_text', methods=['POST'])
def encrypt():
    algorithm = request.form['algorithm']
    plaintext = request.form['plaintext']
    key = request.form.get('key', '')

    if algorithm in ["AES", "DES", "ChaCha20"]:
        result = sym_encrypt(plaintext, key, algorithm)
    else:
        result = asym_encrypt(plaintext, algorithm)

    return jsonify({"result": result})

@app.route('/decrypt_text', methods=['POST'])
def decrypt():
    algorithm = request.form['algorithm']
    ciphertext = request.form['ciphertext']
    key = request.form.get('key', '')

    if algorithm in ["AES", "DES", "ChaCha20"]:
        result = sym_decrypt(ciphertext, key, algorithm)
    else:
        result = asym_decrypt(ciphertext, algorithm)

    return jsonify({"result": result})

@app.route('/hash_text', methods=['POST'])
def hash_handler():
    algorithm = request.form['hash_algorithm']
    text = request.form['text']
    result = hash_text(text, algorithm)
    return jsonify({"result": result})

@app.route('/encrypt_file', methods=['POST'])
def encrypt_file_handler():
    file = request.files['file']
    algorithm = request.form['algorithm']
    key = request.form['key']

    if file and algorithm and key:
        file_data = file.read()
        encrypted = sym_encrypt_file(file_data, key, algorithm)
        return send_file(
            io.BytesIO(encrypted),
            download_name=f"encrypted_{secure_filename(file.filename)}",
            as_attachment=True
        )
    return "Missing data", 400

@app.route('/decrypt_file', methods=['POST'])
def decrypt_file_handler():
    file = request.files['file']
    algorithm = request.form['algorithm']
    key = request.form['key']

    if file and algorithm and key:
        file_data = file.read()
        decrypted = sym_decrypt_file(file_data, key, algorithm)
        return send_file(
            io.BytesIO(decrypted),
            download_name=f"decrypted_{secure_filename(file.filename)}",
            as_attachment=True
        )
    return "Missing data", 400

@app.route('/hash_file', methods=['POST'])
def hash_file_handler():
    file = request.files['file']
    algorithm = request.form['hash_algorithm']

    if file and algorithm:
        file_data = file.read()
        result = hash_file(file_data, algorithm)
        return jsonify({"result": result})
    return "Missing data", 400

if __name__ == "__main__":
    app.run(debug=True)
