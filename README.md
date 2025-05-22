# Encryption, Decryption, and Hashing Flask App

## Overview

This Flask application provides encryption, decryption, and hashing functionalities for both text and files. It supports a variety of cryptographic algorithms implemented using standard Python libraries such as `pycryptodome` and `hashlib`.

## Supported Algorithms

### Symmetric Algorithms
- **AES (Advanced Encryption Standard)**
- **DES (Data Encryption Standard)**
- **ChaCha20**

These algorithms are used for encrypting and decrypting both text and files. The implementations use the `pycryptodome` library, with proper padding for block ciphers (AES and DES) and nonce handling for ChaCha20.

### Asymmetric Algorithms
- **RSA (Rivest–Shamir–Adleman)**
- **ECC (Elliptic Curve Cryptography)**

These algorithms are used for text encryption and digital signatures. RSA uses PKCS1_OAEP for encryption/decryption, while ECC is used for digital signatures with DSS and SHA256. The `pycryptodome` library is used for these implementations.

### Hashing Algorithms
- **SHA-256**
- **SHA-1**
- **SHA-512**
- **MD5**

Hashing is supported for both text and files using Python's built-in `hashlib` library.

## Usage

- Use the Flask UI to encrypt, decrypt, and hash text or files.
- Select the desired algorithm from the available options.
- For symmetric algorithms, provide a key for encryption/decryption.
- For asymmetric algorithms, encryption and decryption are handled with in-memory keys.
- Hashing functions produce hexadecimal digest outputs.

## Implementation Details

- Symmetric algorithms use secure key derivation with SHA-256 or MD5 hashing of the provided key.
- Padding is applied for block ciphers to ensure proper block sizes.
- Asymmetric keys are generated at runtime and stored in memory.
- ECC is used for digital signatures rather than encryption.
- Error handling is implemented to provide informative messages on failures.

## Libraries Used

- `pycryptodome` for cryptographic primitives and algorithms.
- `hashlib` for hashing functions.

## Notes

- This app is intended for educational and demonstration purposes.
- For production use, secure key management and storage are necessary.
- ECC encryption is not implemented; ECC is used for signing only.

## License

MIT License
