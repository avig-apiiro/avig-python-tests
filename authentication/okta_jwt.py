"""Okta access-token validation with okta-jwt-verifier."""
import os
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from okta_jwt_verifier import AccessTokenVerifier, JWTUtils

OKTA_ISSUER = os.environ["OKTA_ISSUER"]  # e.g. https://{yourOktaDomain}/oauth2/default
OKTA_AUDIENCE = os.environ.get("OKTA_AUDIENCE", "api://default")

bearer = HTTPBearer()
verifier = AccessTokenVerifier(issuer=OKTA_ISSUER, audience=OKTA_AUDIENCE)


async def verify_okta_token(creds: Annotated[HTTPAuthorizationCredentials, Depends(bearer)]) -> dict:
    try:
        await verifier.verify(creds.credentials)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Okta token")
    _, claims, _, _ = JWTUtils.parse_token(creds.credentials)
    return claims
