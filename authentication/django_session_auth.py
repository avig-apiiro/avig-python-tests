"""Session authentication with django.contrib.auth."""
from django.contrib.auth import authenticate, login, logout
from django.http import HttpRequest


def login_with_password(request: HttpRequest, username: str, password: str) -> bool:
    user = authenticate(request, username=username, password=password)
    if user is None or not user.is_active:
        return False
    login(request, user)
    return True


def end_session(request: HttpRequest) -> None:
    logout(request)
