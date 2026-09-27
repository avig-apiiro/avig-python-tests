"""Static API-key authentication with fastapi.security.APIKeyHeader."""
import hmac
import os

from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def require_api_key(api_key: str | None = Security(api_key_header)) -> str:
    valid_keys = [k for k in os.environ.get("API_KEYS", "").split(",") if k]
    if api_key and any(hmac.compare_digest(api_key, k) for k in valid_keys):
        return api_key
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing API key")
