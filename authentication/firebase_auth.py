"""Firebase Authentication / Google Identity Platform ID-token validation with firebase-admin."""
from typing import Annotated

import firebase_admin
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from firebase_admin import auth, credentials

firebase_app = firebase_admin.initialize_app(credentials.ApplicationDefault())
bearer = HTTPBearer()


def verify_firebase_token(creds: Annotated[HTTPAuthorizationCredentials, Depends(bearer)]) -> dict:
    try:
        return auth.verify_id_token(creds.credentials, check_revoked=True)
    except (auth.InvalidIdTokenError, auth.ExpiredIdTokenError, auth.RevokedIdTokenError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Firebase token")
