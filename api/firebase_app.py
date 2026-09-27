from typing import Annotated

from fastapi import Depends, FastAPI

from authentication.firebase_auth import verify_firebase_token

app = FastAPI()


@app.get("/api/notes")
def notes(claims: Annotated[dict, Depends(verify_firebase_token)]):
    return {"uid": claims["uid"], "notes": []}
