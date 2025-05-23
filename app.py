from flask import Flask, render_template, request, jsonify, send_file
from symmetric_algorithms import encrypt_text as sym_encrypt, decrypt_text as sym_decrypt
from symmetric_algorithms import encrypt_file as sym_encrypt_file, decrypt_file as sym_decrypt_file
from asymmetric_algorithms import encrypt_text as asym_encrypt, decrypt_text as asym_decrypt, generate_key_pair, validate_key_pair
from hash_functions import hash_text, hash_file
from werkzeug.utils import secure_filename
from flask import send_from_directory
import os
import io
import traceback

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
    try:
        print("=== ENCRYPT TEXT REQUEST ===")
        print(f"Request method: {request.method}")
        print(f"Content-Type: {request.content_type}")
        print(f"Form data: {dict(request.form)}")
        
        plaintext = request.form.get('plaintext')
        algorithm = request.form.get('algorithm')
        asym_algorithm = request.form.get('asym_algorithm')
        key = request.form.get('key')
        public_key = request.form.get('public_key')

        print(f"Parsed data:")
        print(f"  plaintext: {plaintext[:50] if plaintext else 'None'}...")
        print(f"  algorithm: {algorithm}")
        print(f"  asym_algorithm: {asym_algorithm}")
        print(f"  key: {'[PROVIDED]' if key else 'None'}")
        print(f"  public_key: {'[PROVIDED]' if public_key else 'None'}")

        # Validate input
        if not plaintext:
            return jsonify({"error": "Plaintext is required"}), 400

        if algorithm in ["AES", "DES", "ChaCha20"]:
            if not key:
                return jsonify({"error": "Key is required for symmetric encryption"}), 400
            print(f"Using symmetric encryption: {algorithm}")
            result = sym_encrypt(plaintext, key, algorithm)
        elif asym_algorithm:
            if not public_key:
                return jsonify({"error": "Public key is required for asymmetric encryption"}), 400
            if not public_key.strip():
                return jsonify({"error": "Public key cannot be empty"}), 400
            
            print(f"Using asymmetric encryption: {asym_algorithm}")
            print(f"Public key preview: {public_key[:100]}...")
            
            result = asym_encrypt(plaintext, public_key, asym_algorithm)
            
            # Add metadata for better user understanding
            if asym_algorithm == "ECC":
                result_info = {
                    "result": result,
                    "algorithm": "ECC",
                    "note": "ECC encrypted data contains ciphertext, nonce, and ephemeral key information encoded in base64"
                }
                return jsonify(result_info)
        else:
            return jsonify({"error": "Missing or invalid algorithm"}), 400

        print(f"Encryption successful, result length: {len(str(result))}")
        return jsonify({"result": result})
    
    except Exception as e:
        print(f"=== ENCRYPTION ERROR ===")
        print(f"Error: {str(e)}")
        print(f"Traceback:")
        traceback.print_exc()
        return jsonify({"error": f"Encryption failed: {str(e)}"}), 500

@app.route("/generate_keys", methods=["POST"])
def generate_keys():
    try:
        print("=== GENERATE KEYS REQUEST ===")
        algorithm = request.form.get("algorithm")
        print(f"Algorithm: {algorithm}")
        
        public_key, private_key = generate_key_pair(algorithm)
        if private_key:
            print(f"Keys generated successfully for {algorithm}")
            
            # Validate the generated key pair
            is_valid = validate_key_pair(public_key, private_key, algorithm)
            print(f"Key pair validation: {'PASSED' if is_valid else 'FAILED'}")
            
            return jsonify({
                "public_key": public_key,
                "private_key": private_key,
                "algorithm": algorithm,
                "key_size": "2048-bit" if algorithm == "RSA" else "P-256 curve",
                "validated": is_valid
            })
        else:
            print(f"Key generation failed: {public_key}")
            return jsonify({"error": public_key}), 400
    except Exception as e:
        print(f"=== KEY GENERATION ERROR ===")
        print(f"Error: {str(e)}")
        traceback.print_exc()
        return jsonify({"error": f"Key generation failed: {str(e)}"}), 500

@app.route('/validate_keys', methods=['POST'])
def validate_keys():
    try:
        public_key = request.form.get('public_key')
        private_key = request.form.get('private_key')
        algorithm = request.form.get('algorithm')
        
        if not all([public_key, private_key, algorithm]):
            return jsonify({"error": "Missing required parameters"}), 400
            
        is_valid = validate_key_pair(public_key, private_key, algorithm)
        
        return jsonify({
            "valid": is_valid,
            "message": "Key pair is valid and matching" if is_valid else "Key pair does not match or is invalid"
        })
    except Exception as e:
        return jsonify({"error": f"Validation failed: {str(e)}"}), 500

@app.route('/decrypt_text', methods=['GET', 'POST'])
def decrypt_text_handler():
    if request.method == 'POST':
        try:
            print("=== DECRYPT TEXT REQUEST ===")
            print(f"Form data: {dict(request.form)}")
            
            ciphertext = request.form.get('ciphertext')
            decryption_type = request.form.get('decryption_type')
            
            if not ciphertext:
                return jsonify({"error": "Ciphertext is required"}), 400
            
            if not decryption_type:
                return jsonify({"error": "Missing decryption type"}), 400

            if decryption_type == 'asymmetric':
                algorithm = request.form.get('asym_algorithm')
                private_key = request.form.get('private_key')
                
                if not algorithm:
                    return jsonify({"error": "Missing asymmetric algorithm"}), 400
                if not private_key:
                    return jsonify({"error": "Private key is required for asymmetric decryption"}), 400
                
                print(f"Using asymmetric decryption: {algorithm}")
                print(f"Private key preview: {private_key[:100]}...")
                
                plaintext = asym_decrypt(ciphertext, private_key, algorithm)
                
                # Check if decryption failed
                if isinstance(plaintext, str) and (plaintext.startswith("Decryption error:") or plaintext.startswith("ECC decryption error:")):
                    return jsonify({"error": plaintext}), 400
                
                return jsonify({
                    "result": plaintext,
                    "algorithm": algorithm,
                    "note": "Successfully decrypted with asymmetric encryption"
                })

            elif decryption_type == 'symmetric':
                algorithm = request.form.get('algorithm')
                key = request.form.get('key')
                
                if not algorithm:
                    return jsonify({"error": "Missing symmetric algorithm"}), 400
                if not key:
                    return jsonify({"error": "Key is required for symmetric decryption"}), 400
                
                print(f"Using symmetric decryption: {algorithm}")
                
                plaintext = sym_decrypt(ciphertext, key, algorithm)
                
                # Check if decryption failed
                if isinstance(plaintext, str) and plaintext.startswith("Decryption error:"):
                    return jsonify({"error": plaintext}), 400
                
                return jsonify({
                    "result": plaintext,
                    "algorithm": algorithm,
                    "note": "Successfully decrypted with symmetric encryption"
                })
            else:
                return jsonify({"error": "Invalid decryption type"}), 400

        except Exception as e:
            print(f"=== DECRYPTION ERROR ===")
            print(f"Error: {str(e)}")
            traceback.print_exc()
            return jsonify({"error": f"Decryption failed: {str(e)}"}), 500

    # GET request - return the template
    return render_template('decrypt_text.html')

@app.route('/hash_text', methods=['POST'])
def hash_handler():
    try:
        algorithm = request.form['hash_algorithm']
        text = request.form['text']
        result = hash_text(text, algorithm)
        return jsonify({"result": result})
    except Exception as e:
        return jsonify({"error": f"Hashing failed: {str(e)}"}), 500

@app.route('/encrypt_file', methods=['POST'])
def encrypt_file_handler():
    try:
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

        return jsonify({"error": "Missing data"}), 400
    except Exception as e:
        return jsonify({"error": f"File encryption failed: {str(e)}"}), 500

@app.route('/decrypt_file', methods=['POST'])
def decrypt_file_handler():
    try:
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

        return jsonify({"error": "Missing data"}), 400
    except Exception as e:
        return jsonify({"error": f"File decryption failed: {str(e)}"}), 500

@app.route('/hash_file', methods=['POST'])
def hash_file_handler():
    try:
        file = request.files['file']
        algorithm = request.form['hash_algorithm']

        if file and algorithm:
            file_data = file.read()
            result = hash_file(file_data, algorithm)
            return jsonify({"result": result})
        return jsonify({"error": "Missing data"}), 400
    except Exception as e:
        return jsonify({"error": f"File hashing failed: {str(e)}"}), 500

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    uploads_dir = os.path.join(app.root_path, 'uploads')
    return send_from_directory(uploads_dir, filename)

# Add a catch-all error handler
@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Route not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    app.run(debug=True)