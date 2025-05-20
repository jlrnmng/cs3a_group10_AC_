import hashlib

def hash_text(text, algorithm):
    text = text.encode()

    if algorithm == "SHA256":
        return hashlib.sha256(text).hexdigest()

    elif algorithm == "SHA3":
        return hashlib.sha3_256(text).hexdigest()

    elif algorithm == "MD5":
        return hashlib.md5(text).hexdigest()

    elif algorithm == "SHA1":
        return hashlib.sha1(text).hexdigest()

    return "Unsupported Algorithm"

def hash_file(file_data, algorithm):
    if algorithm == "SHA256":
        return hashlib.sha256(file_data).hexdigest()

    elif algorithm == "SHA3":
        return hashlib.sha3_256(file_data).hexdigest()

    elif algorithm == "MD5":
        return hashlib.md5(file_data).hexdigest()

    elif algorithm == "SHA1":
        return hashlib.sha1(file_data).hexdigest()

    return "Unsupported Algorithm"