from contextlib import asynccontextmanager

from fastapi import FastAPI, Security
from fastapi_azure_auth.user import User

from authentication.azure_entra import OPENAPI_CLIENT_ID, azure_scheme, load_azure_openid_config


@asynccontextmanager
async def lifespan(app: FastAPI):
    await load_azure_openid_config()
    yield


app = FastAPI(
    lifespan=lifespan,
    swagger_ui_init_oauth={"usePkceWithAuthorizationCodeGrant": True, "clientId": OPENAPI_CLIENT_ID},
)


@app.get("/api/me", dependencies=[Security(azure_scheme)])
async def me(user: User = Security(azure_scheme)):
    return {"oid": user.oid, "name": user.name, "roles": user.roles}
