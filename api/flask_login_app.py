import os

from flask import Flask, jsonify, request
from flask_login import current_user, login_required, login_user, logout_user

from authentication.flask_login_auth import authenticate, login_manager

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ["FLASK_SECRET_KEY"]
login_manager.init_app(app)


@app.post("/login")
def login():
    body = request.get_json(force=True)
    user = authenticate(body.get("username", ""), body.get("password", ""))
    if user is None:
        return jsonify(error="invalid credentials"), 401
    login_user(user)
    return jsonify(message="logged in")


@app.post("/logout")
@login_required
def logout():
    logout_user()
    return jsonify(message="logged out")


@app.get("/profile")
@login_required
def profile():
    return jsonify(username=current_user.username)
