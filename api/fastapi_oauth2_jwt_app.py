from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

from authentication.fastapi_oauth2_jwt import authenticate_user, create_access_token, get_current_user

app = FastAPI()


@app.post("/token")
def issue_token(form: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user = authenticate_user(form.username, form.password)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    granted = [s for s in form.scopes if s in user["scopes"]]
    return {"access_token": create_access_token(user["username"], granted), "token_type": "bearer"}


@app.get("/users/me")
def read_me(current_user: Annotated[dict, Depends(get_current_user)]):
    return current_user
