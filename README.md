# Encryption, Decryption, and Hashing Flask Application

[![Python](https://img.shields.io/badge/Python-3.x-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Group Members
- John Rein Manaog
- Mark Angelo Gonzales
- Rolando Perina

## Introduction
This Flask application provides comprehensive encryption, decryption, and hashing functionalities for both text and files. It supports a variety of cryptographic algorithms implemented using standard Python libraries such as `pycryptodome` and `hashlib`. The application is designed for educational and demonstration purposes, showcasing cryptographic techniques and security best practices.

## Features
- Encrypt/decrypt text and files using symmetric algorithms (AES, DES, ChaCha20)
- Encrypt/decrypt text using asymmetric algorithms (RSA, ECC)
- Hash text and files using SHA-256, SHA-1, SHA-512, and MD5
- User-friendly web interface
- Runtime key generation
- Informative error handling

## Objectives
- Implement a secure and user-friendly web app for cryptographic operations
- Support various symmetric and asymmetric cryptographic algorithms
- Address security vulnerabilities and improve the original application's design

## Setup Instructions

1. **Clone the Repository**
   ```bash
   git clone <repository-url>
   cd <repository-directory>
   ```

2. **Create and Activate a Virtual Environment**

   - On **Windows**:
     ```bash
     python -m venv venv
     venv\Scripts\activate
     ```

   - On **macOS/Linux**:
     ```bash
     python3 -m venv venv
     source venv/bin/activate
     ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the Application**
   ```bash
   python app.py
   ```

5. **Open in Browser**
   Visit: [http://127.0.0.1:5000](http://127.0.0.1:5000)

> **Note**: For production, configure HTTPS and secure environment variables.

## Directory Structure
```
├── app.py
├── asymmetric_algorithms.py
├── symmetric_algorithms.py
├── hash_functions.py
├── requirements.txt
├── templates/
│   └── *.html
├── static/
│   └── styles and JS
├── uploads/
│   └── (temporary files)
└── README.md
```

## Security Highlights

### Issues Found
- Weak keys and insecure storage
- Input fields vulnerable to injection
- Lack of CSRF/XSS protections
- Deprecated hash algorithms (MD5, SHA-1)

### Fixes Implemented
- Secure key derivation and runtime generation
- Input validation and sanitization
- CSRF protection and secure sessions
- Deprecation of weak algorithms
- Better error handling and HTTPS recommendation

## Technology Stack
- Python 3.x
- Flask
- PyCryptodome
- Hashlib
- HTML/CSS/JS (Bootstrap)

## Walkthrough

### Home Page
Upon launching the application, the home page provides navigation to all major functionalities: symmetric encryption, asymmetric encryption, and hashing.

### Symmetric Encryption/Decryption
1. Navigate to the "Symmetric Encryption" section.
2. Choose an algorithm (AES, DES, or ChaCha20).
3. Enter your text or upload a file.
4. Provide a key (if required) or use auto-generate options.
5. Click "Encrypt" or "Decrypt" to process the data.
6. Download the resulting file (for file-based operations).

### Asymmetric Encryption/Decryption
1. Go to "Asymmetric Encryption".
2. Choose between RSA and ECC.
3. Input text for encryption or decryption.
4. Keys are generated on the fly.
5. View encrypted/decrypted output and optionally save it.

### Hashing
1. Navigate to "Hashing".
2. Choose the hashing algorithm (SHA-256, SHA-1, SHA-512, or MD5).
3. Enter text or upload a file.
4. Click "Generate Hash".
5. View the resulting hash output.

This walkthrough helps users quickly utilize the platform’s core functionality for learning or testing encryption, decryption, and hashing.

## Contribution

Contributions are welcome! Please fork the repository, create a feature branch, and submit a pull request.

## License

This project is licensed under the [MIT License](https://opensource.org/licenses/MIT).
