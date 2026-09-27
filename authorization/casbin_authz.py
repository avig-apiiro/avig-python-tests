"""RBAC/ABAC policy enforcement with PyCasbin."""
from pathlib import Path

import casbin
from fastapi import HTTPException, Request, status

_HERE = Path(__file__).parent
enforcer = casbin.Enforcer(str(_HERE / "casbin_model.conf"), str(_HERE / "casbin_policy.csv"))


def enforce(subject: str, request: Request) -> None:
    if not enforcer.enforce(subject, request.url.path, request.method):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden by policy")
