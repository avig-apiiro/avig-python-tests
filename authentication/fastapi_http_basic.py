"""HTTP Basic authentication with fastapi.security.HTTPBasic."""
import os
import secrets
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

security = HTTPBasic()


def get_current_username(credentials: Annotated[HTTPBasicCredentials, Depends(security)]) -> str:
    expected_user = os.environ.get("BASIC_AUTH_USER", "").encode()
    expected_password = os.environ.get("BASIC_AUTH_PASSWORD", "").encode()
    user_ok = secrets.compare_digest(credentials.username.encode(), expected_user)
    password_ok = secrets.compare_digest(credentials.password.encode(), expected_password)
    if not (user_ok and password_ok):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username
