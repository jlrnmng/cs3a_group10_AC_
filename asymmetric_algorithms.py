from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from symmetric_algorithms import pad, unpad
from Crypto.Cipher import ChaCha20
import json
import base64


def encrypt_text(plaintext, public_key_pem, algorithm):
    try:
        plaintext = plaintext.encode()

        if algorithm == "RSA":
            # Load the public key
            pub_key = RSA.import_key(public_key_pem)
            cipher = PKCS1_OAEP.new(pub_key)
            ciphertext = cipher.encrypt(plaintext)
            # Return base64 encoded result for RSA
            return base64.b64encode(ciphertext).decode()

        elif algorithm == "ECC":
            recipient_key = ECC.import_key(public_key_pem)
            ephemeral_key = ECC.generate(curve='P-256')

            # Derive shared secret using ECDH
            shared_secret_point = ephemeral_key.d * recipient_key.pointQ
            
            # Check if we got a valid point (not point at infinity)
            if shared_secret_point is None or not hasattr(shared_secret_point, 'x'):
                raise ValueError("ECDH key exchange failed - invalid shared secret point")
            
            # Convert the x-coordinate to bytes
            shared_secret_bytes = int(shared_secret_point.x).to_bytes(32, 'big')

            # Derive encryption key using HKDF
            key = HKDF(shared_secret_bytes, 32, b'', SHA256)

            # Encrypt with ChaCha20
            cipher = ChaCha20.new(key=key)
            ciphertext = cipher.encrypt(plaintext)

            # Create a more compact representation
            result_data = {
                "ciphertext": base64.b64encode(ciphertext).decode(),
                "nonce": base64.b64encode(cipher.nonce).decode(),
                "ephemeral_public_key": ephemeral_key.public_key().export_key(format='PEM')
            }

            # Return a more user-friendly format - combine all components into one base64 string
            combined_data = json.dumps(result_data).encode()
            return base64.b64encode(combined_data).decode()

        else:
            return "Unsupported Algorithm"

    except Exception as e:
        return f"Encryption error: {str(e)}"


def decrypt_text(ciphertext, private_key_pem, algorithm):
    try:
        if algorithm == "RSA":
            # Decode the base64 ciphertext
            ciphertext_bytes = base64.b64decode(ciphertext)
            priv_key = RSA.import_key(private_key_pem)
            cipher = PKCS1_OAEP.new(priv_key)
            decrypted = cipher.decrypt(ciphertext_bytes)
            return decrypted.decode()

        elif algorithm == "ECC":
            try:
                # First, try to decode as the new compact format
                try:
                    combined_data = base64.b64decode(ciphertext)
                    data = json.loads(combined_data.decode())
                except:
                    # Fallback: try to parse as direct JSON (for backward compatibility)
                    data = json.loads(ciphertext)
                
                encrypted_data = base64.b64decode(data["ciphertext"])
                nonce = base64.b64decode(data["nonce"])
                ephemeral_public_key = ECC.import_key(data["ephemeral_public_key"])
                private_key = ECC.import_key(private_key_pem)

                # Derive shared secret using ECDH
                shared_secret_point = ephemeral_public_key.pointQ * private_key.d
                
                # Check if we got a valid point (not point at infinity)
                if shared_secret_point is None or not hasattr(shared_secret_point, 'x'):
                    raise ValueError("ECDH key exchange failed - invalid shared secret point")
                
                shared_secret_bytes = int(shared_secret_point.x).to_bytes(32, 'big')

                # Derive key using HKDF
                key = HKDF(shared_secret_bytes, 32, b'', SHA256)

                # Decrypt with ChaCha20
                cipher = ChaCha20.new(key=key, nonce=nonce)
                plaintext = cipher.decrypt(encrypted_data)

                return plaintext.decode()
            except Exception as e:
                return f"ECC decryption error: {str(e)}"

        else:
            return "Unsupported Algorithm"

    except Exception as e:
        return f"Decryption error: {str(e)}"
    
    
def generate_key_pair(algorithm):
    try:
        if algorithm == "RSA":
            key = RSA.generate(2048)
            # Remove .decode() since export_key with format='PEM' already returns a string
            private_key = key.export_key(format='PEM')
            public_key = key.publickey().export_key(format='PEM')
            
            # Ensure they are strings (they should be already)
            if isinstance(private_key, bytes):
                private_key = private_key.decode()
            if isinstance(public_key, bytes):
                public_key = public_key.decode()
                
            return public_key, private_key

        elif algorithm == "ECC":
            key = ECC.generate(curve="P-256")
            # Remove .decode() since export_key with format='PEM' already returns a string
            private_key = key.export_key(format='PEM')
            public_key = key.public_key().export_key(format='PEM')
            
            # Ensure they are strings (they should be already)
            if isinstance(private_key, bytes):
                private_key = private_key.decode()
            if isinstance(public_key, bytes):
                public_key = public_key.decode()
                
            return public_key, private_key

        else:
            return "Unsupported Algorithm", None

    except Exception as e:
        return f"Key generation error: {str(e)}", None


def validate_key_pair(public_key_pem, private_key_pem, algorithm):
    """Validate that a public/private key pair match"""
    try:
        if algorithm == "RSA":
            private_key = RSA.import_key(private_key_pem)
            public_key = RSA.import_key(public_key_pem)
            
            # Check if the public key from private key matches the provided public key
            derived_public = private_key.publickey().export_key(format='PEM')
            provided_public = public_key.export_key(format='PEM')
            
            # Ensure both are strings for comparison
            if isinstance(derived_public, bytes):
                derived_public = derived_public.decode()
            if isinstance(provided_public, bytes):
                provided_public = provided_public.decode()
                
            return derived_public == provided_public
            
        elif algorithm == "ECC":
            private_key = ECC.import_key(private_key_pem)
            public_key = ECC.import_key(public_key_pem)
            
            # Check if the public key from private key matches the provided public key
            derived_public = private_key.public_key().export_key(format='PEM')
            provided_public = public_key.export_key(format='PEM')
            
            # Ensure both are strings for comparison
            if isinstance(derived_public, bytes):
                derived_public = derived_public.decode()
            if isinstance(provided_public, bytes):
                provided_public = provided_public.decode()
                
            return derived_public == provided_public
            
        return False
    except Exception as e:
        print(f"Validation error: {str(e)}")
        return False