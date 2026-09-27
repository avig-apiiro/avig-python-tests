from typing import Annotated

from fastapi import Depends, FastAPI

from authentication.fastapi_oauth2_jwt import get_current_user
from authorization.aws_verified_permissions import require_permission

app = FastAPI()


@app.get("/documents/{document_id}")
def view_document(document_id: str, user: Annotated[dict, Depends(get_current_user)]):
    require_permission(user["username"], "ViewDocument", "Document", document_id)
    return {"document_id": document_id, "viewer": user["username"]}
