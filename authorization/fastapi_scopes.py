"""OAuth2 scope-based authorization with fastapi.security.SecurityScopes."""
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import SecurityScopes

from authentication.fastapi_oauth2_jwt import decode_token, oauth2_scheme


def require_scopes(security_scopes: SecurityScopes, token: Annotated[str, Depends(oauth2_scheme)]) -> dict:
    payload = decode_token(token)
    granted = set(payload.get("scopes", []))
    for scope in security_scopes.scopes:
        if scope not in granted:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions",
                headers={"WWW-Authenticate": f'Bearer scope="{security_scopes.scope_str}"'},
            )
    return {"username": payload["sub"], "scopes": list(granted)}
