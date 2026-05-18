"""Small encryption wrapper for per-audit secrets.

Private repo credentials are stored only as encrypted blobs. The worker
decrypts them just-in-time for cloning and the job workspace is deleted at the
end of the run.
"""
from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken

from app.config import get_settings


class SecretConfigError(RuntimeError):
    pass


class SecretDecryptError(RuntimeError):
    pass


def encrypt_secret(value: str) -> str:
    return _fernet().encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_secret(value: str) -> str:
    try:
        return _fernet().decrypt(value.encode("ascii")).decode("utf-8")
    except InvalidToken as e:
        raise SecretDecryptError("secret could not be decrypted") from e


def _fernet() -> Fernet:
    key = get_settings().secret_encryption_key
    if not key:
        raise SecretConfigError("SECRET_ENCRYPTION_KEY is required for private repository credentials")
    try:
        return Fernet(key.encode("ascii"))
    except Exception as e:
        raise SecretConfigError("SECRET_ENCRYPTION_KEY must be a valid Fernet key") from e
