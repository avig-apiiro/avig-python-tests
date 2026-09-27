from typing import Annotated

from fastapi import Depends, FastAPI

from authentication.okta_jwt import verify_okta_token

app = FastAPI()


@app.get("/api/messages")
async def messages(claims: Annotated[dict, Depends(verify_okta_token)]):
    return {"user": claims.get("sub"), "messages": []}
