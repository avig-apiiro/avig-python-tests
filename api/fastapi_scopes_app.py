from typing import Annotated

from fastapi import FastAPI, Security

from authorization.fastapi_scopes import require_scopes

app = FastAPI()


@app.get("/items")
def list_items(user: Annotated[dict, Security(require_scopes, scopes=["items:read"])]):
    return {"owner": user["username"], "items": []}


@app.post("/items")
def create_item(item: dict, user: Annotated[dict, Security(require_scopes, scopes=["items:write"])]):
    return {"created_by": user["username"], "item": item}
