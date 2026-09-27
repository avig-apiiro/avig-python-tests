"""Auth0 access-token validation via the tenant JWKS with PyJWT."""
import os
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

AUTH0_DOMAIN = os.environ["AUTH0_DOMAIN"]
AUTH0_AUDIENCE = os.environ["AUTH0_AUDIENCE"]
ISSUER = f"https://{AUTH0_DOMAIN}/"

bearer = HTTPBearer()
jwks_client = jwt.PyJWKClient(f"{ISSUER}.well-known/jwks.json")


def verify_auth0_token(creds: Annotated[HTTPAuthorizationCredentials, Depends(bearer)]) -> dict:
    try:
        signing_key = jwks_client.get_signing_key_from_jwt(creds.credentials)
        return jwt.decode(
            creds.credentials,
            signing_key.key,
            algorithms=["RS256"],
            audience=AUTH0_AUDIENCE,
            issuer=ISSUER,
        )
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Auth0 token")
