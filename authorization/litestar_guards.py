"""Role guards for Litestar route handlers."""
from litestar.connection import ASGIConnection
from litestar.exceptions import PermissionDeniedException
from litestar.handlers.base import BaseRouteHandler


def requires_role(role: str):
    def guard(connection: ASGIConnection, _: BaseRouteHandler) -> None:
        if role not in connection.user.roles:
            raise PermissionDeniedException(f"Requires role '{role}'")

    return guard


def owner_or_admin_guard(connection: ASGIConnection, _: BaseRouteHandler) -> None:
    user = connection.user
    if "admin" not in user.roles and connection.path_params.get("username") != user.name:
        raise PermissionDeniedException("Not the owner of this resource")
