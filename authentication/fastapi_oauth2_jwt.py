"""OAuth2 password flow + JWT bearer tokens with FastAPI, PyJWT and pwdlib."""
import os
from datetime import datetime, timedelta, timezone
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pwdlib import PasswordHash

ALGORITHM = "HS256"
password_hash = PasswordHash.recommended()
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="token",
    scopes={"items:read": "Read items", "items:write": "Create or modify items"},
)

_USERS = {
    "alice": {"hashed_password": password_hash.hash("alice-password"), "scopes": ["items:read"]},
    "bob": {"hashed_password": password_hash.hash("bob-password"), "scopes": ["items:read", "items:write"]},
}

CREDENTIALS_EXCEPTION = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)


def _secret() -> str:
    return os.environ["JWT_SECRET_KEY"]


def authenticate_user(username: str, password: str):
    user = _USERS.get(username)
    if not user or not password_hash.verify(password, user["hashed_password"]):
        return None
    return {"username": username, **user}


def create_access_token(subject: str, scopes: list[str], expires: timedelta = timedelta(minutes=15)) -> str:
    payload = {"sub": subject, "scopes": scopes, "exp": datetime.now(timezone.utc) + expires}
    return jwt.encode(payload, _secret(), algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, _secret(), algorithms=[ALGORITHM])
    except jwt.InvalidTokenError:
        raise CREDENTIALS_EXCEPTION


def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]) -> dict:
    payload = decode_token(token)
    username = payload.get("sub")
    if username not in _USERS:
        raise CREDENTIALS_EXCEPTION
    return {"username": username, "scopes": payload.get("scopes", [])}
