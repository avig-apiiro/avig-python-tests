from aiohttp import web

from authentication.aiohttp_jwt_auth import jwt_auth_middleware

routes = web.RouteTableDef()


@routes.get("/health")
async def health(request: web.Request):
    return web.json_response({"status": "ok"})


@routes.get("/api/tickets")
async def list_tickets(request: web.Request):
    return web.json_response({"user": request["user"]["sub"], "tickets": []})


def create_app() -> web.Application:
    app = web.Application(middlewares=[jwt_auth_middleware])
    app.add_routes(routes)
    return app


if __name__ == "__main__":
    web.run_app(create_app())
