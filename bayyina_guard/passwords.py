"""Password storage for Bayyina's local break-glass accounts. Rules: README.md, "What to build", part 3."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import unicodedata

_CURRENT = (2**14, 8, 5)  # n, r, p
_DKLEN = 32
_MAXMEM = 64 * 1024 * 1024
_B64_ALPHABET = re.compile(r"^[A-Za-z0-9_-]*$")


def _b64_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64_decode(text: str) -> bytes | None:
    if not isinstance(text, str) or "=" in text or _B64_ALPHABET.fullmatch(text) is None:
        return None
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except Exception:
        return None


def _parse_stored(stored):
    """Return (n, r, p, salt_bytes, hash_bytes) or None if malformed/out of bounds.

    This is used by both verify_password and needs_rehash, so a stored value
    that cannot be parsed is treated the same way by both.
    """
    if not isinstance(stored, str):
        return None
    parts = stored.split("$")
    if len(parts) != 6 or parts[0] != "scrypt":
        return None
    _, n_text, r_text, p_text, salt_text, hash_text = parts
    if not n_text.isdigit() or not r_text.isdigit() or not p_text.isdigit():
        return None
    try:
        n, r, p = int(n_text), int(r_text), int(p_text)
    except ValueError:
        return None
    if n < 2 or n > 2**20 or (n & (n - 1)) != 0:
        return None
    if not 1 <= r <= 32 or not 1 <= p <= 16:
        return None
    salt = _b64_decode(salt_text)
    key = _b64_decode(hash_text)
    if salt is None or len(salt) < 16:
        return None
    if key is None or len(key) != _DKLEN:
        return None
    return n, r, p, salt, key


def hash_password(password: str) -> str:
    """scrypt$<n>$<r>$<p>$<salt>$<hash> with n=2**14, r=8, p=5, a 16-byte random salt, dklen=32."""
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    normalized = unicodedata.normalize("NFKC", password)
    if not 8 <= len(normalized) <= 128:
        raise ValueError("password must be 8-128 characters after NFKC normalisation")
    n, r, p = _CURRENT
    salt = os.urandom(16)
    key = hashlib.scrypt(
        normalized.encode("utf-8"), salt=salt, n=n, r=r, p=p,
        dklen=_DKLEN, maxmem=_MAXMEM,
    )
    return f"scrypt${n}${r}${p}${_b64_encode(salt)}${_b64_encode(key)}"


def verify_password(password: str, stored: str) -> bool:
    """True only if `password` matches `stored`. Never raises: anything malformed is False."""
    try:
        if not isinstance(password, str):
            return False
        parsed = _parse_stored(stored)
        if parsed is None:
            return False
        n, r, p, salt, key = parsed
        normalized = unicodedata.normalize("NFKC", password)
        derived = hashlib.scrypt(
            normalized.encode("utf-8"), salt=salt, n=n, r=r, p=p,
            dklen=_DKLEN, maxmem=_MAXMEM,
        )
        return hmac.compare_digest(derived, key)
    except Exception:
        return False


def needs_rehash(stored: str) -> bool:
    """True if `stored` cannot be parsed or any of n, r, p is below the current values."""
    parsed = _parse_stored(stored)
    if parsed is None:
        return True
    n, r, p, _salt, _key = parsed
    return n < _CURRENT[0] or r < _CURRENT[1] or p < _CURRENT[2]
