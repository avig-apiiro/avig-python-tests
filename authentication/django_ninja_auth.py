"""Bearer JWT and API-key authentication with Django Ninja security classes."""
import hmac
import os

import jwt
from django.conf import settings
from django.contrib.auth import get_user_model
from ninja.security import APIKeyHeader, HttpBearer


class JWTBearer(HttpBearer):
    def authenticate(self, request, token):
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        except jwt.PyJWTError:
            return None
        return get_user_model().objects.filter(pk=payload.get("sub"), is_active=True).first()


class ServiceApiKey(APIKeyHeader):
    param_name = "X-API-Key"

    def authenticate(self, request, key):
        expected = os.environ.get("NINJA_SERVICE_API_KEY", "")
        if expected and key and hmac.compare_digest(key, expected):
            return "service-account"
        return None
