from typing import Annotated

from fastapi import Depends, FastAPI, Request

from authentication.fastapi_http_basic import get_current_username
from authorization.casbin_authz import enforce

app = FastAPI()


def casbin_guard(request: Request, username: Annotated[str, Depends(get_current_username)]) -> str:
    enforce(username, request)
    return username


@app.get("/documents/{doc_id}")
def read_document(doc_id: int, user: Annotated[str, Depends(casbin_guard)]):
    return {"doc_id": doc_id, "reader": user}


@app.delete("/documents/{doc_id}")
def delete_document(doc_id: int, user: Annotated[str, Depends(casbin_guard)]):
    return {"deleted": doc_id, "by": user}
