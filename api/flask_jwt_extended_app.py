from flask import Flask, jsonify, request
from flask_jwt_extended import get_jwt, get_jwt_identity, jwt_required

from authentication.flask_jwt_extended_auth import init_jwt, login

app = Flask(__name__)
init_jwt(app)


@app.post("/auth/login")
def auth_login():
    body = request.get_json(force=True)
    token = login(body.get("username", ""), body.get("password", ""))
    if token is None:
        return jsonify(error="invalid credentials"), 401
    return jsonify(access_token=token)


@app.get("/orders")
@jwt_required()
def list_orders():
    return jsonify(owner=get_jwt_identity(), roles=get_jwt().get("roles", []), orders=[])
