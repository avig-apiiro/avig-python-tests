from flask import Flask, g, jsonify

from authentication.google_identity import google_login_required

app = Flask(__name__)


@app.get("/api/me")
@google_login_required
def me():
    return jsonify(email=g.google_user.get("email"), sub=g.google_user["sub"])
