from flask import Flask, g, jsonify

from authentication.aws_cognito import cognito_required

app = Flask(__name__)


@app.get("/api/invoices")
@cognito_required
def invoices():
    return jsonify(user=g.cognito_claims["sub"], groups=g.cognito_claims.get("cognito:groups", []), invoices=[])
