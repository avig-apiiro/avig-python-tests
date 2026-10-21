from datetime import datetime, timezone

from flask import Flask, jsonify

from authorization.custom_api_key_authz import require_api_key

app = Flask(__name__)


@app.get("/healthz")
def health():
    return jsonify(status="ok")


@app.get("/reports")
@require_api_key
def list_reports():
    return jsonify(reports=[], generated_at=datetime.now(timezone.utc).isoformat())


@app.post("/reports")
@require_api_key
def create_report():
    return jsonify(message="created"), 201
