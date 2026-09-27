"""JWT authentication with Flask-JWT-Extended."""
import os
from datetime import timedelta

from flask import Flask
from flask_jwt_extended import JWTManager, create_access_token
from werkzeug.security import check_password_hash, generate_password_hash

jwt = JWTManager()

_USERS = {"alice": {"password_hash": generate_password_hash("alice-password"), "roles": ["reader"]}}


def init_jwt(app: Flask) -> None:
    app.config["JWT_SECRET_KEY"] = os.environ["JWT_SECRET_KEY"]
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=15)
    jwt.init_app(app)


def login(username: str, password: str):
    user = _USERS.get(username)
    if not user or not check_password_hash(user["password_hash"], password):
        return None
    return create_access_token(identity=username, additional_claims={"roles": user["roles"]})
