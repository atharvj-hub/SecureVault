"""
Key Derivation Functions (KDF) for SecureVault.

Provides Argon2id (modern, GPU-resistant) and PBKDF2 (fallback) for
deriving encryption keys from passwords.

Drop this file at: src/securevault/crypto/kdf.py
"""

from __future__ import annotations

import logging
import os
from typing import Dict, Tuple, Literal, Optional

# Argon2 low-level interface
from argon2 import low_level
# cryptography primitives
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import hmac

# configure module logger
logger = logging.getLogger("securevault.kdf")
if not logger.handlers:
    # Avoid adding duplicate handlers if logger is configured elsewhere
    handler = logging.NullHandler()
    logger.addHandler(handler)

# KDF configuration constants
ARGON2_TIME_COST = 3  # iterations
# memory_cost for argon2.low_level.hash_secret_raw is expressed in KiB (kibibytes).
# 65536 KiB == 64 MiB (not "MB" ambiguous). Keep unit clarity.
ARGON2_MEMORY_COST = 65_536  # 65536 KiB == 64 MiB
ARGON2_PARALLELISM = 4  # threads
ARGON2_HASH_LEN = 32  # 256 bits
ARGON2_SALT_LEN = 16  # 128 bits

PBKDF2_ITERATIONS = 100_000
PBKDF2_KEY_LEN = 32  # 256 bits
PBKDF2_SALT_LEN = 16  # 128 bits

KDFType = Literal["argon2id", "pbkdf2"]


class KDFError(Exception):
    """Base exception for KDF operations."""


__all__ = [
    "derive_key",
    "derive_key_argon2id",
    "derive_key_pbkdf2",
    "verify_password_argon2id",
    "get_kdf_params",
    "KDFError",
]


def derive_key_argon2id(
    password: str | bytes,
    salt: Optional[bytes] = None,
    time_cost: int = ARGON2_TIME_COST,
    memory_cost: int = ARGON2_MEMORY_COST,
    parallelism: int = ARGON2_PARALLELISM,
    hash_len: int = ARGON2_HASH_LEN,
) -> Tuple[bytes, bytes]:
    """
    Derive encryption key using Argon2id (recommended).

    Args:
        password: User password (string or bytes)
        salt: Optional salt (generated if None)
        time_cost: Number of iterations
        memory_cost: Memory usage in KiB
        parallelism: Number of lanes (threads)
        hash_len: Output key length in bytes

    Returns:
        Tuple of (derived_key, salt)

    Raises:
        KDFError: If key derivation fails
    """
    try:
        if salt is None:
            salt = os.urandom(ARGON2_SALT_LEN)

        password_bytes = password.encode("utf-8") if isinstance(password, str) else password

        # Use low_level.hash_secret_raw to get raw bytes suitable for symmetric key usage
        key = low_level.hash_secret_raw(
            secret=password_bytes,
            salt=salt,
            time_cost=int(time_cost),
            memory_cost=int(memory_cost),
            parallelism=int(parallelism),
            hash_len=int(hash_len),
            type=low_level.Type.ID,  # Argon2id variant
        )

        if not isinstance(key, (bytes, bytearray)):
            raise KDFError("Argon2id did not return raw bytes as expected")

        return bytes(key), salt

    except Exception as exc:
        logger.exception("Argon2id key derivation failed")
        raise KDFError(f"Argon2id key derivation failed: {exc}") from exc


def derive_key_pbkdf2(
    password: str | bytes,
    salt: Optional[bytes] = None,
    iterations: int = PBKDF2_ITERATIONS,
    key_length: int = PBKDF2_KEY_LEN,
) -> Tuple[bytes, bytes]:
    """
    Derive encryption key using PBKDF2-HMAC-SHA256 (fallback).

    Args:
        password: User password (string or bytes)
        salt: Optional salt (generated if None)
        iterations: Number of iterations (default: PBKDF2_ITERATIONS)
        key_length: Output key length in bytes

    Returns:
        Tuple of (derived_key, salt)

    Raises:
        KDFError: If key derivation fails
    """
    try:
        if salt is None:
            salt = os.urandom(PBKDF2_SALT_LEN)

        password_bytes = password.encode("utf-8") if isinstance(password, str) else password

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=int(key_length),
            salt=salt,
            iterations=int(iterations),
        )

        key = kdf.derive(password_bytes)
        return key, salt

    except Exception as exc:
        logger.exception("PBKDF2 key derivation failed")
        raise KDFError(f"PBKDF2 key derivation failed: {exc}") from exc


def derive_key(
    password: str | bytes,
    salt: Optional[bytes] = None,
    method: KDFType = "argon2id",
    **kwargs,
) -> Tuple[bytes, bytes, KDFType]:
    """
    Derive encryption key using specified KDF method.

    Returns:
        (derived_key, salt, method_used)
    """
    method = method.lower()
    if method == "argon2id":
        key, used_salt = derive_key_argon2id(password, salt, **kwargs)
    elif method == "pbkdf2":
        key, used_salt = derive_key_pbkdf2(password, salt, **kwargs)
    else:
        raise KDFError(f"Unknown KDF method: {method}")

    return key, used_salt, method


def verify_password_argon2id(
    password: str | bytes,
    salt: bytes,
    expected_key: bytes,
    **kwargs,
) -> bool:
    """
    Verify password by re-deriving key and comparing (constant-time).

    Returns:
        True if password derives to expected_key, False otherwise.
    """
    try:
        derived_key, _ = derive_key_argon2id(password, salt, **kwargs)
        # Use constant-time comparison
        return hmac.compare_digest(derived_key, expected_key)
    except KDFError as exc:
        # Likely an invalid parameter or other derivation issue
        logger.debug("Argon2id verification failed: %s", exc)
        return False
    except Exception as exc:
        logger.exception("Unexpected error during Argon2id verification")
        return False


def get_kdf_params(method: KDFType = "argon2id") -> Dict[str, int]:
    """
    Return default KDF parameters for the specified method.
    """
    method = method.lower()
    if method == "argon2id":
        return {
            "time_cost": ARGON2_TIME_COST,
            "memory_cost": ARGON2_MEMORY_COST,
            "parallelism": ARGON2_PARALLELISM,
            "hash_len": ARGON2_HASH_LEN,
        }
    elif method == "pbkdf2":
        return {"iterations": PBKDF2_ITERATIONS, "key_length": PBKDF2_KEY_LEN}
    else:
        raise KDFError(f"Unknown KDF method: {method}")


# Quick self-test when run as main (not for production use)
if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    pw = "correcthorsebatterystaple"
    key_a, salt_a, m1 = derive_key(pw, method="argon2id")
    print("argon2id key (hex):", key_a.hex()[:64], "salt:", salt_a.hex())
    key_p, salt_p, m2 = derive_key(pw, method="pbkdf2")
    print("pbkdf2 key (hex):", key_p.hex()[:64], "salt:", salt_p.hex())
    print("verify argon2:", verify_password_argon2id(pw, salt_a, key_a))
