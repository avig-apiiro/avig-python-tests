from typing import Annotated

from fastapi import Depends, FastAPI

from authentication.auth0_jwt import verify_auth0_token

app = FastAPI()


@app.get("/api/private")
def private(claims: Annotated[dict, Depends(verify_auth0_token)]):
    return {"sub": claims["sub"], "permissions": claims.get("permissions", [])}
