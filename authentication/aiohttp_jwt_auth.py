"""JWT bearer authentication middleware for aiohttp."""
import os

import jwt
from aiohttp import web

PUBLIC_PATHS = {"/health"}


def _decode(token: str) -> dict:
    return jwt.decode(
        token,
        os.environ["JWT_SECRET_KEY"],
        algorithms=["HS256"],
        audience=os.environ.get("JWT_AUDIENCE", "aiohttp-api"),
    )


@web.middleware
async def jwt_auth_middleware(request: web.Request, handler):
    if request.path in PUBLIC_PATHS:
        return await handler(request)
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        raise web.HTTPUnauthorized(headers={"WWW-Authenticate": "Bearer"})
    try:
        request["user"] = _decode(header.removeprefix("Bearer "))
    except jwt.PyJWTError:
        raise web.HTTPUnauthorized(headers={"WWW-Authenticate": "Bearer"})
    return await handler(request)
