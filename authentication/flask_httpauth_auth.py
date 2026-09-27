"""HTTP Basic and Bearer-token authentication with Flask-HTTPAuth."""
import hmac
import os

from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth
from werkzeug.security import check_password_hash, generate_password_hash

basic_auth = HTTPBasicAuth()
token_auth = HTTPTokenAuth(scheme="Bearer")

_USERS = {"alice": generate_password_hash("alice-password")}


@basic_auth.verify_password
def verify_password(username: str, password: str):
    password_hash = _USERS.get(username)
    if password_hash and check_password_hash(password_hash, password):
        return username
    return None


@token_auth.verify_token
def verify_token(token: str):
    expected = os.environ.get("SERVICE_API_TOKEN", "")
    if expected and hmac.compare_digest(token, expected):
        return "service-account"
    return None
