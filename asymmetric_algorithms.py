from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
import base64


def encrypt_text(plaintext, public_key_pem, algorithm):
    try:
        plaintext = plaintext.encode()

        if algorithm == "RSA":
            pub_key = RSA.import_key(public_key_pem)
            cipher = PKCS1_OAEP.new(pub_key)
            encrypted = cipher.encrypt(plaintext)
            return base64.b64encode(encrypted).decode()

        elif algorithm == "ECC":
            pub_key = ECC.import_key(public_key_pem)
            signer = DSS.new(pub_key, 'fips-186-3')
            h = SHA256.new(plaintext)
            signature = signer.sign(h)
            return base64.b64encode(signature).decode()

        else:
            return "Unsupported Algorithm"

    except Exception as e:
        return f"Encryption error: {str(e)}"


def decrypt_text(ciphertext, private_key_pem, algorithm):
    try:
        ciphertext = base64.b64decode(ciphertext)

        if algorithm == "RSA":
            priv_key = RSA.import_key(private_key_pem)
            cipher = PKCS1_OAEP.new(priv_key)
            decrypted = cipher.decrypt(ciphertext)
            return decrypted.decode()

        elif algorithm == "ECC":
            priv_key = ECC.import_key(private_key_pem)
            verifier = DSS.new(priv_key, 'fips-186-3')
            h = SHA256.new(b"verify message")  # placeholder
            try:
                verifier.verify(h, ciphertext)
                return "Signature is valid (simulated)"
            except ValueError:
                return "Signature is invalid"

        else:
            return "Unsupported Algorithm"

    except Exception as e:
        return f"Decryption error: {str(e)}"
