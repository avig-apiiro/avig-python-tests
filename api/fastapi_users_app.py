from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI

from authentication.fastapi_users_auth import (
    User,
    UserCreate,
    UserRead,
    auth_backend,
    create_db_and_tables,
    current_active_user,
    fastapi_users,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await create_db_and_tables()
    yield


app = FastAPI(lifespan=lifespan)
app.include_router(fastapi_users.get_auth_router(auth_backend), prefix="/auth/jwt", tags=["auth"])
app.include_router(fastapi_users.get_register_router(UserRead, UserCreate), prefix="/auth", tags=["auth"])


@app.get("/authenticated-route")
async def authenticated_route(user: User = Depends(current_active_user)):
    return {"message": f"Hello {user.email}"}
