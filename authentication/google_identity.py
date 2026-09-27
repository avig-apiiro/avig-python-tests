"""Google Sign-In / Google Cloud ID-token validation with google-auth."""
import os
from functools import wraps

from flask import abort, g, request
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token

GOOGLE_CLIENT_ID = os.environ["GOOGLE_CLIENT_ID"]
_transport = google_requests.Request()


def verify_google_id_token(token: str) -> dict:
    return id_token.verify_oauth2_token(token, _transport, GOOGLE_CLIENT_ID)


def google_login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            abort(401)
        try:
            g.google_user = verify_google_id_token(header.removeprefix("Bearer "))
        except ValueError:
            abort(401)
        return view(*args, **kwargs)

    return wrapper
