"""Relationship-based authorization with Oso Cloud."""
import os
from functools import wraps

from flask import abort, g
from oso_cloud import Oso, Value

oso = Oso(url=os.environ.get("OSO_URL", "https://cloud.osohq.com"), api_key=os.environ["OSO_AUTH"])


def is_allowed(user_id: str, action: str, resource_type: str, resource_id: str) -> bool:
    return oso.authorize(Value("User", user_id), action, Value(resource_type, resource_id))


def oso_authorize(action: str, resource_type: str, id_arg: str):
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if not is_allowed(g.user_id, action, resource_type, str(kwargs[id_arg])):
                abort(403)
            return view(*args, **kwargs)

        return wrapper

    return decorator
