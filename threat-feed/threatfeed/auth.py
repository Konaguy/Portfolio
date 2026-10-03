"""Password hashing (scrypt, stdlib) and opaque bearer tokens."""

from __future__ import annotations

import hashlib
import hmac
import secrets

SESSION_TTL_SECONDS = 30 * 24 * 3600

_N, _R, _P = 2**14, 8, 1


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=32)
    return f"scrypt${_N}${_R}${_P}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt, dk = stored.split("$")
    except ValueError:
        return False
    if algo != "scrypt":
        return False
    calc = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p),
                          dklen=len(bytes.fromhex(dk)))
    return hmac.compare_digest(calc.hex(), dk)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_session_token() -> str:
    return "tfs_" + secrets.token_urlsafe(32)


def new_api_key() -> tuple[str, str]:
    """Returns (full key shown once, short prefix used to identify/revoke it)."""
    key = "tf_live_" + secrets.token_urlsafe(32)
    return key, key[:16]
