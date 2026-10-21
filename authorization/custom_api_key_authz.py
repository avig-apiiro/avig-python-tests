"""Project-local API-key authorization decorator.

No third-party auth library is involved, so Apiiro recognizes it only through a
custom framework definition that names this module and the decorator below.
"""
import os
from functools import wraps

from flask import jsonify, request

_AUTH_HEADER = "X-Api-Key"
_ENV_VAR = "SERVICE_API_KEY"


def require_api_key(func):
    """Reject a request whose API-key header does not match the configured key."""

    @wraps(func)
    def _wrapper(*args, **kwargs):
        expected_key = os.environ.get(_ENV_VAR, "")
        provided_key = request.headers.get(_AUTH_HEADER, "")
        if not expected_key or provided_key != expected_key:
            return jsonify(error="unauthorized"), 401
        return func(*args, **kwargs)

    return _wrapper
