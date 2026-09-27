from authlib.integrations.flask_oauth2 import current_token
from flask import Flask, jsonify

from authentication.authlib_oidc import require_oauth

app = Flask(__name__)


@app.get("/api/profile")
@require_oauth("profile")
def profile():
    return jsonify(sub=current_token["sub"], scope=current_token.get("scope"))
