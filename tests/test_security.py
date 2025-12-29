import json

from cryptography.fernet import Fernet

from server.security import (
    decrypt_secret,
    encrypt_secret,
    generate_recovery_codes,
    generate_totp_secret,
    hash_password,
    hash_recovery_codes,
    make_fernet,
    needs_rehash,
    redact_password,
    safe_json,
    totp_from_secret,
    verify_password,
    verify_recovery_code_hash,
)


def test_password_hashing_and_verify():
    hashed = hash_password("Password123")
    assert verify_password(hashed, "Password123") is True
    assert verify_password(hashed, "wrong") is False


def test_needs_rehash_handles_invalid_hash():
    assert needs_rehash("not-a-hash") is False


def test_totp_secret_round_trip():
    secret = generate_totp_secret()
    totp = totp_from_secret(secret)
    code = totp.now()
    assert totp.verify(code)


def test_fernet_encrypt_decrypt():
    key = Fernet.generate_key().decode("utf-8")
    fernet = make_fernet(key)
    assert fernet is not None

    token, encrypted = encrypt_secret("top-secret", fernet)
    assert encrypted is True
    assert token != "top-secret"
    assert decrypt_secret(token, fernet) == "top-secret"
    assert decrypt_secret("invalid", fernet) is None

    raw, raw_encrypted = encrypt_secret("plain", None)
    assert raw == "plain"
    assert raw_encrypted is False
    assert decrypt_secret(raw, None) == "plain"


def test_make_fernet_invalid_returns_none():
    assert make_fernet("bad-key") is None


def test_recovery_codes_hash_and_verify():
    codes = generate_recovery_codes(2)
    hashes = hash_recovery_codes(codes)
    assert verify_recovery_code_hash(hashes[0], codes[0]) is True
    assert verify_recovery_code_hash(hashes[0], "nope") is False


def test_redact_and_safe_json():
    assert redact_password(None) == "<none>"
    assert redact_password("secret") == "<redacted>"
    assert safe_json(None) is None
    assert json.loads(safe_json({"a": 1})) == {"a": 1}
