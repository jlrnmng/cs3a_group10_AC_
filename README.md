# Encryption, Decryption, and Hashing Flask Application

## Group Members
- Member 1 john rein manaog 
- Member 2 mark angelo gonzales 
- Member 3 rolando perina
- Member 4

## Introduction
This Flask application provides comprehensive encryption, decryption, and hashing functionalities for both text and files. It supports a variety of cryptographic algorithms implemented using standard Python libraries such as `pycryptodome` and `hashlib`. The application is designed for educational and demonstration purposes, showcasing cryptographic techniques and security best practices.

## Objectives
- To implement a secure and user-friendly web application for encryption, decryption, and hashing.
- To support multiple symmetric and asymmetric cryptographic algorithms.
- To identify and address security vulnerabilities in the original application.
- To improve the security posture of the application through enhancements and best practices.
- To provide clear documentation and setup instructions for users and developers.

## Original Application Features
- Encryption and decryption of text and files using symmetric algorithms: AES, DES, and ChaCha20.
- Text encryption and digital signatures using asymmetric algorithms: RSA and ECC.
- Hashing of text and files using SHA-256, SHA-1, SHA-512, and MD5.
- User interface built with Flask to facilitate cryptographic operations.
- Runtime key generation for asymmetric algorithms.
- Error handling with informative messages.

## Security Assessment Findings
During the security assessment of the original application, the following vulnerabilities were identified:
- Insecure key management practices, including use of static or weak keys.
- Lack of input validation leading to potential injection attacks.
- Insufficient protection against common web vulnerabilities such as CSRF and XSS.
- Use of deprecated or weak cryptographic algorithms (e.g., MD5, SHA-1).
- Missing secure transport enforcement (e.g., HTTPS).
- Inadequate error handling exposing sensitive information.

## Security Improvements Implemented
To address the identified vulnerabilities, the following improvements were made:
- Enhanced key management with secure key derivation and runtime key generation.
- Input validation and sanitization to prevent injection attacks.
- Implementation of CSRF protection and secure session management.
- Removal or deprecation warnings for weak algorithms; promotion of stronger alternatives.
- Recommendations and configuration for HTTPS enforcement.
- Improved error handling to avoid leaking sensitive details.
- Code refactoring to follow security best practices and standards.

## Penetration Testing Report
The penetration testing conducted revealed:
- Vulnerabilities in input fields that could be exploited for injection attacks.
- Potential for session hijacking due to missing secure cookie flags.
- Exposure of sensitive error messages in certain failure scenarios.
- Weaknesses in cryptographic algorithm choices impacting data confidentiality.
Exploitation steps included crafted input payloads and session manipulation. Recommendations focused on input validation, secure cookie settings, and algorithm upgrades.

## Remediation Plan
The remediation plan involved:
- Applying input validation and sanitization across all user inputs.
- Enabling CSRF tokens and secure cookie attributes.
- Updating cryptographic algorithms to recommended standards.
- Configuring the application to enforce HTTPS.
- Enhancing error handling to log errors internally without exposing details to users.
- Conducting code reviews and security testing to verify fixes.

## Technology Stack
- Python 3.x
- Flask web framework
- PyCryptodome library for cryptographic algorithms
- Hashlib for hashing functions
- HTML, CSS, and JavaScript for frontend interface

## Setup Instructions
1. Clone the repository:
   ```
   git clone <repository-url>
   cd <repository-directory>
   ```
2. Create and activate a virtual environment:
   ```
   python3 -m venv venv
   source venv/bin/activate
   ```
3. Install required dependencies:
   ```
   pip install -r requirements.txt
   ```
4. Run the Flask application:
   ```
   flask run
   ```
5. Open your web browser and navigate to `http://127.0.0.1:5000` to access the application.

**Note:** For production deployment, configure HTTPS and secure environment variables accordingly.

---

MIT License
