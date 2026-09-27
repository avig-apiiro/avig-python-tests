"""API-key authentication middleware for Litestar (identifies the user for guards)."""
import os
from dataclasses import dataclass, field

from litestar.connection import ASGIConnection
from litestar.exceptions import NotAuthorizedException
from litestar.middleware import AbstractAuthenticationMiddleware, AuthenticationResult


@dataclass
class ApiUser:
    name: str
    roles: list[str] = field(default_factory=list)


def _load_keys() -> dict[str, ApiUser]:
    # API_KEYS="key1:alice:reader,key2:bob:reader|admin"
    keys = {}
    for entry in filter(None, os.environ.get("API_KEYS", "").split(",")):
        key, name, roles = entry.split(":")
        keys[key] = ApiUser(name=name, roles=roles.split("|"))
    return keys


class ApiKeyAuthMiddleware(AbstractAuthenticationMiddleware):
    async def authenticate_request(self, connection: ASGIConnection) -> AuthenticationResult:
        api_key = connection.headers.get("X-API-Key")
        user = _load_keys().get(api_key or "")
        if user is None:
            raise NotAuthorizedException("Invalid API key")
        return AuthenticationResult(user=user, auth=api_key)
