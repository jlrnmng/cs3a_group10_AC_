from flask import Flask, render_template, request, jsonify, send_file
from symmetric_algorithms import encrypt_text as sym_encrypt, decrypt_text as sym_decrypt
from symmetric_algorithms import encrypt_file as sym_encrypt_file, decrypt_file as sym_decrypt_file
from asymmetric_algorithms import encrypt_text as asym_encrypt, decrypt_text as asym_decrypt
from hash_functions import hash_text, hash_file
from werkzeug.utils import secure_filename
from flask import send_from_directory
import os
import io

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/encrypt_text', methods=['GET'])
def encrypt_text_page():
    return render_template('encrypt_text.html')

@app.route('/decrypt_text', methods=['GET'])
def decrypt_text_page():
    return render_template('decrypt_text.html')

@app.route('/decrypt_file', methods=['GET'])
def decrypt_file_page():
    return render_template('decrypt_file.html')

@app.route('/encrypt_file', methods=['GET'])
def encrypt_file_page():
    return render_template('encrypt_file.html')

@app.route('/hash_text', methods=['GET'])
def hash_text_page():
    return render_template('hash_text.html')


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

@app.route('/decrypt_text', methods=['GET', 'POST'])
def decrypt_text_handler():
    if request.method == 'POST':
        ciphertext = request.form['ciphertext']
        decryption_type = request.form.get('decryption_type')
        if not decryption_type:
            return render_template('decrypt_text.html', plaintext="Missing decryption type.")


        if decryption_type == 'symmetric':
            key = request.form['key']
            algorithm = request.form['algorithm']
            plaintext = sym_decrypt(ciphertext, key, algorithm)

        elif decryption_type == 'asymmetric':
            algorithm = request.form['asym_algorithm']
            private_key_file = request.files['private_key']
            private_key_data = private_key_file.read().decode()
            plaintext = asym_decrypt(ciphertext, private_key_data, algorithm)

        else:
            plaintext = "Invalid decryption type."

        return render_template('decrypt_text.html', plaintext=plaintext)

    return render_template('decrypt_text.html')

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
        filename = secure_filename(file.filename)
        input_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        output_path = os.path.join(app.config['UPLOAD_FOLDER'], f"encrypted_{filename}")
        
        # Save uploaded file
        file.save(input_path)

        # Call correct function
        sym_encrypt_file(input_path, output_path, key, algorithm)

        # Send the encrypted file
        return send_file(
            output_path,
            download_name=f"encrypted_{filename}",
            as_attachment=True
        )

    return "Missing data", 400

@app.route('/decrypt_file', methods=['POST'])
def decrypt_file_handler():
    file = request.files['file']
    algorithm = request.form['algorithm']
    key = request.form['key']

    if file and algorithm and key:
        filename = secure_filename(file.filename)
        input_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        output_path = os.path.join(app.config['UPLOAD_FOLDER'], f"decrypted_{filename}")
        
        # Save uploaded encrypted file
        file.save(input_path)

        # Call the decryption function using file paths
        sym_decrypt_file(input_path, output_path, key, algorithm)

        # Send the decrypted file back
        return send_file(
            output_path,
            download_name=f"decrypted_{filename}",
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

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    uploads_dir = os.path.join(app.root_path, 'uploads')
    return send_from_directory(uploads_dir, filename)

if __name__ == '__main__':
    app.run(debug=True)

