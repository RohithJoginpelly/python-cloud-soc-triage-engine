"""Secure password hashing for SOC analyst accounts."""

from __future__ import annotations

import base64
import hashlib
import secrets
from hmac import compare_digest


SCHEME = "scrypt"
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
KEY_LENGTH = 64
SALT_LENGTH = 16
MINIMUM_PASSWORD_LENGTH = 12


def _encode(value: bytes) -> str:
    """Encode bytes for safe database storage."""

    return base64.urlsafe_b64encode(
        value
    ).decode("ascii")


def _decode(value: str) -> bytes:
    """Decode a database-safe byte representation."""

    return base64.urlsafe_b64decode(
        value.encode("ascii")
    )


def hash_password(password: str) -> str:
    """Hash a password using a random salt and scrypt."""

    if not isinstance(password, str):
        raise TypeError(
            "Password must be a string."
        )

    if len(password) < MINIMUM_PASSWORD_LENGTH:
        raise ValueError(
            "Password must contain at least "
            f"{MINIMUM_PASSWORD_LENGTH} characters."
        )

    salt = secrets.token_bytes(
        SALT_LENGTH
    )

    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=KEY_LENGTH,
    )

    return "$".join(
        [
            SCHEME,
            str(SCRYPT_N),
            str(SCRYPT_R),
            str(SCRYPT_P),
            _encode(salt),
            _encode(digest),
        ]
    )


def verify_password(
    password: str,
    encoded_hash: str,
) -> bool:
    """Verify a password against a stored scrypt hash."""

    if not isinstance(password, str):
        return False

    if not isinstance(encoded_hash, str):
        return False

    try:
        (
            scheme,
            n_value,
            r_value,
            p_value,
            salt_value,
            digest_value,
        ) = encoded_hash.split("$")

        if scheme != SCHEME:
            return False

        n = int(n_value)
        r = int(r_value)
        p = int(p_value)

        salt = _decode(salt_value)
        expected_digest = _decode(
            digest_value
        )

        supplied_digest = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=n,
            r=r,
            p=p,
            dklen=len(expected_digest),
        )
    except (
        ValueError,
        TypeError,
        base64.binascii.Error,
    ):
        return False

    return compare_digest(
        supplied_digest,
        expected_digest,
    )
