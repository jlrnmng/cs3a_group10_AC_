import hashlib

def hash_text(text, algorithm):
    """
    Hashes the input text using the specified algorithm.
    Supported algorithms: SHA256, SHA512, MD5, SHA1.
    Uses Python's hashlib library for implementation.
    """
    text = text.encode()

    if algorithm == "SHA256":
        return hashlib.sha256(text).hexdigest()

    elif algorithm == "SHA512":
        return hashlib.sha512(text).hexdigest()

    elif algorithm == "MD5":
        return hashlib.md5(text).hexdigest()

    elif algorithm == "SHA1":
        return hashlib.sha1(text).hexdigest()

    return "Unsupported Algorithm"

def hash_file(file_data, algorithm):
    """
    Hashes the input file data using the specified algorithm.
    Supported algorithms: SHA256, SHA512, MD5, SHA1.
    Uses Python's hashlib library for implementation.
    """
    if algorithm == "SHA256":
        return hashlib.sha256(file_data).hexdigest()

    elif algorithm == "SHA512":
        return hashlib.sha512(file_data).hexdigest()

    elif algorithm == "MD5":
        return hashlib.md5(file_data).hexdigest()

    elif algorithm == "SHA1":
        return hashlib.sha1(file_data).hexdigest()

    return "Unsupported Algorithm"
