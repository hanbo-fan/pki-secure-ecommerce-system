# auth_utils.py
import hashlib, jwt, secrets, time, os
from fastapi import HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Optional
from dotenv import load_dotenv

# SECRET_KEY = "dev_secret_key_replace_in_prod"
load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY must be set in production")

security   = HTTPBearer()
# print(f"**SECRET_KEY: '{SECRET_KEY}'**")

challenge_store = {}

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def create_token(account_id: int, username: str, role: str) -> str:
    payload = {
        "account_id": account_id,
        "username":   username,
        "role":       role,
        "exp":        int(time.time()) + 86400
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256") # type: ignore

def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"]) # type: ignore
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid token")

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> dict:
    return decode_token(credentials.credentials)

def require_role(role: str):
    def checker(user=Depends(get_current_user)):
        if user["role"] != role:
            raise HTTPException(403, f"Requires {role} role")
        return user
    return checker

def create_challenge(username: str, role: str) -> str:
    challenge = secrets.token_hex(32)
    challenge_store[f"{username}:{role}"] = {
        "challenge": challenge,
        "expires":   int(time.time()) + 60
    }
    return challenge

def pop_challenge(username: str, role: str) -> Optional[str]:
    """extract challenge, return None if expired"""
    key   = f"{username}:{role}"
    entry = challenge_store.pop(key, None)
    if not entry or int(time.time()) > entry["expires"]:
        return None
    return entry["challenge"]