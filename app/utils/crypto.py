"""Cryptographic utilities for encrypting sensitive tokens."""
import os
import base64
from typing import Optional

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from app.config import settings


def _get_fernet() -> Fernet:
    """Get or create a Fernet instance for token encryption."""
    key = settings.ENCRYPTION_KEY
    if not key:
        # Derive from secret key as fallback
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"vulnexus-salt",
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(settings.SECRET_KEY.encode()))
    else:
        key = key.encode() if isinstance(key, str) else key
        if len(key) != 44:
            # Pad or derive
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b"vulnexus-salt",
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(key))
    return Fernet(key)


async def encrypt_token(token: str) -> str:
    """Encrypt a token for secure storage."""
    f = _get_fernet()
    return f.encrypt(token.encode()).decode()


async def decrypt_token(encrypted_token: str) -> str:
    """Decrypt an encrypted token."""
    f = _get_fernet()
    return f.decrypt(encrypted_token.encode()).decode()