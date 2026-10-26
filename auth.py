"""SecureGate authentication helpers for a local learning project.

Not suitable as a production authentication service.
"""
import base64
import hashlib
import hmac
import secrets
import struct
import time

ITERATIONS = 300_000


def hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    """Return (salt_hex, password_hash_hex) using PBKDF2-HMAC-SHA256."""
    if salt is None:
        salt = secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS)
    return salt.hex(), derived.hex()


def check_password(password: str, salt_hex: str, stored_hash: str) -> bool:
    """Recalculate the password hash and compare without timing-sensitive ==."""
    _, candidate_hash = hash_password(password, bytes.fromhex(salt_hex))
    return hmac.compare_digest(candidate_hash, stored_hash)


def create_totp_secret() -> str:
    """Generate a random Base32 key that works in authenticator apps."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii")


def totp(secret: str, now: int | None = None) -> str:
    """Create a standard six-digit SHA-1 TOTP code (RFC 6238)."""
    if now is None:
        now = int(time.time())
    key = base64.b32decode(secret, casefold=True)
    counter = now // 30
    message = struct.pack(">Q", counter)
    digest = hmac.new(key, message, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(number % 1_000_000).zfill(6)


def matching_totp_counter(secret: str, submitted_code: str,
                          now: int | None = None) -> int | None:
    """Return the matching time counter; None for an invalid code.

    Tracking the counter lets password recovery reject reuse of one TOTP step.
    """
    if not (submitted_code.isascii() and submitted_code.isdigit()
            and len(submitted_code) == 6):
        return None
    if now is None:
        now = int(time.time())
    for offset in (-1, 0, 1):
        candidate_time = now + offset * 30
        if candidate_time < 0:
            continue
        if hmac.compare_digest(totp(secret, candidate_time), submitted_code):
            return candidate_time // 30
    return None


def verify_totp(secret: str, submitted_code: str, now: int | None = None) -> bool:
    return matching_totp_counter(secret, submitted_code, now) is not None


def generate_recovery_codes(count: int = 8) -> list[str]:
    """Generate unpredictable 128-bit single-use codes in readable groups."""
    codes = []
    for _ in range(count):
        token = secrets.token_hex(16).upper()
        codes.append("-".join(token[i:i + 4] for i in range(0, 32, 4)))
    return codes


def hash_recovery_code(code: str) -> str | None:
    """Normalize and hash a recovery code, or reject malformed input."""
    compact = code.strip().replace("-", "").replace(" ", "").upper()
    if len(compact) != 32 or any(char not in "0123456789ABCDEF" for char in compact):
        return None
    # A high-entropy random code is safe to hash directly with SHA-256.
    return hashlib.sha256(compact.encode("ascii")).hexdigest()
