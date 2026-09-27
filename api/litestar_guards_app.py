from litestar import Litestar, delete, get
from litestar.middleware.base import DefineMiddleware

from authentication.litestar_auth import ApiKeyAuthMiddleware
from authorization.litestar_guards import owner_or_admin_guard, requires_role


@get("/reports", guards=[requires_role("reader")])
async def list_reports() -> dict:
    return {"reports": []}


@delete("/reports/{report_id:int}", guards=[requires_role("admin")])
async def delete_report(report_id: int) -> None:
    return None


@get("/users/{username:str}/settings", guards=[owner_or_admin_guard])
async def user_settings(username: str) -> dict:
    return {"username": username, "settings": {}}


app = Litestar(
    route_handlers=[list_reports, delete_report, user_settings],
    middleware=[DefineMiddleware(ApiKeyAuthMiddleware)],
)
