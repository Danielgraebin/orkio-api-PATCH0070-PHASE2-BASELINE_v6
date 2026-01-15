from __future__ import annotations
import os, time, base64, hashlib, hmac
import jwt

JWT_SECRET = os.getenv("JWT_SECRET", "")
JWT_ALG = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRES_IN = int(os.getenv("JWT_EXPIRES_IN", "3600"))

PBKDF2_ITERS = int(os.getenv("PBKDF2_ITERS", "600000"))

def require_secret():
    if not JWT_SECRET or JWT_SECRET.lower().startswith("change"):
        raise RuntimeError("JWT_SECRET is not configured (refuse to start)")

def new_salt() -> str:
    return base64.urlsafe_b64encode(os.urandom(16)).decode("utf-8").rstrip("=")

def pbkdf2_hash(password: str, salt: str) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), PBKDF2_ITERS)
    return base64.urlsafe_b64encode(dk).decode("utf-8").rstrip("=")

def verify_password(password: str, salt: str, pw_hash: str) -> bool:
    calc = pbkdf2_hash(password, salt)
    return hmac.compare_digest(calc, pw_hash)

def mint_token(payload: dict) -> str:
    now = int(time.time())
    exp = now + JWT_EXPIRES_IN
    data = {**payload, "iat": now, "exp": exp}
    return jwt.encode(data, JWT_SECRET, algorithm=JWT_ALG)

def decode_token(token: str) -> dict:
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
