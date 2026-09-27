from flask import Flask, jsonify

from authentication.flask_httpauth_auth import basic_auth
from authorization.flask_principal_authz import admin_permission, init_principal, reader_permission

app = Flask(__name__)
init_principal(app)


@app.get("/articles")
@basic_auth.login_required
@reader_permission.require(http_exception=403)
def list_articles():
    return jsonify(articles=[])


@app.delete("/articles/<int:article_id>")
@basic_auth.login_required
@admin_permission.require(http_exception=403)
def delete_article(article_id: int):
    return jsonify(deleted=article_id)
