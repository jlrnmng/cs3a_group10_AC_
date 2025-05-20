from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
import base64

# Simple key storage (in-memory)
keys = {
    "RSA": RSA.generate(2048),
    "ECC": ECC.generate(curve='P-256')
}

def encrypt_text(plaintext, algorithm):
    plaintext = plaintext.encode()

    if algorithm == "RSA":
        pub_key = keys["RSA"].publickey()
        cipher = PKCS1_OAEP.new(pub_key)
        encrypted = cipher.encrypt(plaintext)
        return base64.b64encode(encrypted).decode('utf-8')

    elif algorithm == "ECC":
        signer = DSS.new(keys["ECC"], 'fips-186-3')
        h = SHA256.new(plaintext)
        signature = signer.sign(h)
        return base64.b64encode(signature).decode('utf-8')

    return "Unsupported Algorithm"

def decrypt_text(ciphertext, algorithm):
    try:
        ciphertext = base64.b64decode(ciphertext)

        if algorithm == "RSA":
            cipher = PKCS1_OAEP.new(keys["RSA"])
            decrypted = cipher.decrypt(ciphertext)
            return decrypted.decode()

        elif algorithm == "ECC":
            # ECC does not directly decrypt, simulate by verifying a known message
            # In real use, ECC would be used for key exchange or digital signatures
            return "ECC used for digital signature, not encryption"

        return "Unsupported Algorithm"
    
    except Exception as e:
        return f"Error: {str(e)}"