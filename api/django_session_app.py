import json

from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.urls import path
from django.views.decorators.http import require_GET, require_POST

from authentication.django_session_auth import end_session, login_with_password


@require_POST
def login_view(request):
    body = json.loads(request.body or "{}")
    if not login_with_password(request, body.get("username", ""), body.get("password", "")):
        return JsonResponse({"error": "invalid credentials"}, status=401)
    return JsonResponse({"message": "logged in"})


@require_POST
@login_required
def logout_view(request):
    end_session(request)
    return JsonResponse({"message": "logged out"})


@require_GET
@login_required
def profile_view(request):
    return JsonResponse({"username": request.user.username})


urlpatterns = [
    path("login", login_view),
    path("logout", logout_view),
    path("profile", profile_view),
]
