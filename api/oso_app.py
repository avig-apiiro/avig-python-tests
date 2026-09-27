from flask import Flask, g, jsonify

from authentication.flask_httpauth_auth import basic_auth
from authorization.oso_authz import oso_authorize

app = Flask(__name__)


@app.before_request
def set_user():
    g.user_id = basic_auth.current_user()


@app.get("/repositories/<repo_id>")
@basic_auth.login_required
@oso_authorize("read", "Repository", id_arg="repo_id")
def get_repository(repo_id: str):
    return jsonify(id=repo_id, name=f"repo-{repo_id}")
