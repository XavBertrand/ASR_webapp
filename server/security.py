from __future__ import annotations

import json
import secrets
from typing import Iterable

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken

ph = PasswordHasher()


def hash_password(password: str) -> str:
    return ph.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return ph.verify(password_hash, password)
    except VerifyMismatchError:
        return False
    except Exception:
        return False


def needs_rehash(password_hash: str) -> bool:
    try:
        return ph.check_needs_rehash(password_hash)
    except Exception:
        return False


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def totp_from_secret(secret: str) -> pyotp.TOTP:
    return pyotp.TOTP(secret)


def make_fernet(key: str | None) -> Fernet | None:
    if not key:
        return None
    try:
        return Fernet(key)
    except ValueError:
        return None


def encrypt_secret(secret: str, fernet: Fernet | None) -> tuple[str, bool]:
    if not fernet:
        return secret, False
    token = fernet.encrypt(secret.encode("utf-8"))
    return token.decode("utf-8"), True


def decrypt_secret(raw: str | None, fernet: Fernet | None) -> str | None:
    if raw is None:
        return None
    if not fernet:
        return raw
    try:
        return fernet.decrypt(raw.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        return None


def generate_recovery_codes(count: int = 5) -> list[str]:
    return [secrets.token_hex(8) for _ in range(count)]


def hash_recovery_codes(codes: Iterable[str]) -> list[str]:
    return [hash_password(code) for code in codes]


def verify_recovery_code_hash(stored_hash: str, code: str) -> bool:
    return verify_password(stored_hash, code)


def redact_password(value: str | None) -> str:
    if value is None:
        return "<none>"
    return "<redacted>"


def safe_json(obj: dict | list | None) -> str | None:
    if obj is None:
        return None
    return json.dumps(obj, ensure_ascii=False)
