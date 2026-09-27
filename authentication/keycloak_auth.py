"""Keycloak token introspection with python-keycloak."""
import os
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from keycloak import KeycloakOpenID

keycloak_openid = KeycloakOpenID(
    server_url=os.environ["KEYCLOAK_URL"],
    realm_name=os.environ["KEYCLOAK_REALM"],
    client_id=os.environ["KEYCLOAK_CLIENT_ID"],
    client_secret_key=os.environ["KEYCLOAK_CLIENT_SECRET"],
)

bearer = HTTPBearer()


def verify_keycloak_token(creds: Annotated[HTTPAuthorizationCredentials, Depends(bearer)]) -> dict:
    token_info = keycloak_openid.introspect(creds.credentials)
    if not token_info.get("active"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Inactive Keycloak token")
    return token_info
