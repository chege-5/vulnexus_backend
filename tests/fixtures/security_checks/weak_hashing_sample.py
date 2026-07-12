import hashlib
import zlib


def legacy_password_digest(password):
    return hashlib.md5(password.encode()).hexdigest()


def reset_token_marker(token):
    return zlib.crc32(token.encode())
