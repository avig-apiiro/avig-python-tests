from typing import Annotated

from fastapi import Depends, FastAPI

from authentication.keycloak_auth import verify_keycloak_token

app = FastAPI()


@app.get("/api/projects")
def projects(token_info: Annotated[dict, Depends(verify_keycloak_token)]):
    return {"user": token_info.get("preferred_username"), "projects": []}
