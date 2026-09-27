"""AWS Cognito user-pool access-token validation via the pool JWKS."""
import os
from functools import wraps

import jwt
from flask import abort, g, request

REGION = os.environ["COGNITO_REGION"]
USER_POOL_ID = os.environ["COGNITO_USER_POOL_ID"]
APP_CLIENT_ID = os.environ["COGNITO_APP_CLIENT_ID"]
ISSUER = f"https://cognito-idp.{REGION}.amazonaws.com/{USER_POOL_ID}"

jwks_client = jwt.PyJWKClient(f"{ISSUER}/.well-known/jwks.json")


def verify_cognito_token(token: str) -> dict:
    signing_key = jwks_client.get_signing_key_from_jwt(token)
    claims = jwt.decode(token, signing_key.key, algorithms=["RS256"], issuer=ISSUER)
    if claims.get("token_use") != "access" or claims.get("client_id") != APP_CLIENT_ID:
        raise jwt.InvalidTokenError("Not an access token for this app client")
    return claims


def cognito_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            abort(401)
        try:
            g.cognito_claims = verify_cognito_token(header.removeprefix("Bearer "))
        except jwt.PyJWTError:
            abort(401)
        return view(*args, **kwargs)

    return wrapper
