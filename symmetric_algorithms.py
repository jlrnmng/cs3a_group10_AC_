from Crypto.Cipher import AES, DES, ChaCha20
from Crypto.Random import get_random_bytes
import base64
import hashlib

# Padding for AES and DES
BS_AES = AES.block_size
BS_DES = DES.block_size

def pad(text, block_size):
    padding_len = block_size - len(text) % block_size
    return text + chr(padding_len) * padding_len

def unpad(text):
    return text[:-ord(text[-1])]

def encrypt_text(plaintext, key, algorithm):
    plaintext = plaintext.encode()
    if algorithm == "AES":
        key = hashlib.sha256(key.encode()).digest()
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(plaintext.decode(), BS_AES).encode())
        return base64.b64encode(cipher.iv + ct_bytes).decode('utf-8')

    elif algorithm == "DES":
        key = hashlib.md5(key.encode()).digest()[:8]
        cipher = DES.new(key, DES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(plaintext.decode(), BS_DES).encode())
        return base64.b64encode(cipher.iv + ct_bytes).decode('utf-8')

    elif algorithm == "ChaCha20":
        key = hashlib.sha256(key.encode()).digest()[:32]
        cipher = ChaCha20.new(key=key)
        ciphertext = cipher.encrypt(plaintext)
        return base64.b64encode(cipher.nonce + ciphertext).decode('utf-8')

    return "Unsupported Algorithm"

def decrypt_text(ciphertext, key, algorithm):
    try:
        ciphertext = base64.b64decode(ciphertext)
        if algorithm == "AES":
            key = hashlib.sha256(key.encode()).digest()
            iv = ciphertext[:16]
            ct = ciphertext[16:]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct).decode())
            return pt

        elif algorithm == "DES":
            key = hashlib.md5(key.encode()).digest()[:8]
            iv = ciphertext[:8]
            ct = ciphertext[8:]
            cipher = DES.new(key, DES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct).decode())
            return pt

        elif algorithm == "ChaCha20":
            key = hashlib.sha256(key.encode()).digest()[:32]
            nonce = ciphertext[:12]
            ct = ciphertext[12:]
            cipher = ChaCha20.new(key=key, nonce=nonce)
            return cipher.decrypt(ct).decode()

        return "Unsupported Algorithm"

    except Exception as e:
        return f"Error: {str(e)}"

def encrypt_file(input_file_path, output_file_path, key, algorithm):
    with open(input_file_path, 'rb') as f:
        file_data = f.read()

    if algorithm == "AES":
        key = hashlib.sha256(key.encode()).digest()
        cipher = AES.new(key, AES.MODE_CBC)
        padded_data = pad(file_data.decode('latin1'), BS_AES).encode('latin1')
        ct_bytes = cipher.encrypt(padded_data)
        encrypted = cipher.iv + ct_bytes

    elif algorithm == "DES":
        key = hashlib.md5(key.encode()).digest()[:8]
        cipher = DES.new(key, DES.MODE_CBC)
        padded_data = pad(file_data.decode('latin1'), BS_DES).encode('latin1')
        ct_bytes = cipher.encrypt(padded_data)
        encrypted = cipher.iv + ct_bytes

    elif algorithm == "ChaCha20":
        key = hashlib.sha256(key.encode()).digest()[:32]
        cipher = ChaCha20.new(key=key)
        ct_bytes = cipher.encrypt(file_data)
        encrypted = cipher.nonce + ct_bytes

    else:
        raise ValueError("Unsupported Algorithm")

    with open(output_file_path, 'wb') as f:
        f.write(encrypted)

def decrypt_file(input_file_path, output_file_path, key, algorithm):
    with open(input_file_path, 'rb') as f:
        file_data = f.read()

    try:
        if algorithm == "AES":
            key = hashlib.sha256(key.encode()).digest()
            iv = file_data[:16]
            ct = file_data[16:]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(ct).decode('latin1')).encode('latin1')

        elif algorithm == "DES":
            key = hashlib.md5(key.encode()).digest()[:8]
            iv = file_data[:8]
            ct = file_data[8:]
            cipher = DES.new(key, DES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(ct).decode('latin1')).encode('latin1')

        elif algorithm == "ChaCha20":
            key = hashlib.sha256(key.encode()).digest()[:32]
            nonce = file_data[:12]
            ct = file_data[12:]
            cipher = ChaCha20.new(key=key, nonce=nonce)
            decrypted = cipher.decrypt(ct)

        else:
            raise ValueError("Unsupported Algorithm")

        with open(output_file_path, 'wb') as f:
            f.write(decrypted)

    except Exception as e:
        print(f"Decryption failed: {str(e)}")