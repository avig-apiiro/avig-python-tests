from django.urls import path
from ninja import NinjaAPI

from authentication.django_ninja_auth import JWTBearer, ServiceApiKey

api = NinjaAPI(urls_namespace="ninja", auth=JWTBearer())


@api.get("/me")
def me(request):
    return {"username": request.auth.username}


@api.get("/internal/stats", auth=ServiceApiKey())
def stats(request):
    return {"caller": request.auth, "users": 42}


urlpatterns = [
    path("", api.urls),
]
