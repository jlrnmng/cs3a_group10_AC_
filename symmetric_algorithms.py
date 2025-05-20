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
            nonce = ciphertext[:12]  # 12 bytes for ChaCha20
            ct = ciphertext[12:]
            cipher = ChaCha20.new(key=key, nonce=nonce)
            return cipher.decrypt(ct).decode()

        return "Unsupported Algorithm"

    except Exception as e:
        return f"Error: {str(e)}"