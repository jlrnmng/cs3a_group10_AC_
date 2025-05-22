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
    """
    Encrypts plaintext using the specified asymmetric algorithm (RSA or ECC).
    RSA uses PKCS1_OAEP for encryption.
    ECC is used for digital signatures (signing) with DSS and SHA256.
    Args:
        plaintext (str): Text to encrypt or sign.
        algorithm (str): Algorithm name ("RSA", "ECC").
    Returns:
        str: Base64 encoded ciphertext or signature.
    """
    try:
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

        else:
            return "Unsupported Algorithm"
    except Exception as e:
        return f"Encryption error: {str(e)}"

def decrypt_text(ciphertext, algorithm):
    """
    Decrypts ciphertext using the specified asymmetric algorithm (RSA or ECC).
    RSA uses PKCS1_OAEP for decryption.
    ECC does not support decryption; used for signature verification.
    Args:
        ciphertext (str): Base64 encoded ciphertext or signature.
        algorithm (str): Algorithm name ("RSA", "ECC").
    Returns:
        str: Decrypted plaintext or message.
    """
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

        else:
            return "Unsupported Algorithm"
    except Exception as e:
        return f"Decryption error: {str(e)}"
