from typing import Annotated

from fastapi import Depends, FastAPI

from authentication.fastapi_http_basic import get_current_username

app = FastAPI()


@app.get("/users/me")
def read_current_user(username: Annotated[str, Depends(get_current_username)]):
    return {"username": username}
