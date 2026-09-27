from flask import Flask, jsonify

from authentication.flask_httpauth_auth import basic_auth, token_auth

app = Flask(__name__)


@app.get("/me")
@basic_auth.login_required
def me():
    return jsonify(username=basic_auth.current_user())


@app.get("/internal/metrics")
@token_auth.login_required
def metrics():
    return jsonify(caller=token_auth.current_user(), requests=42)
