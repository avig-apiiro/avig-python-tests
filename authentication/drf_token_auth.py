"""Opaque DB-backed tokens with Django REST framework TokenAuthentication."""
from rest_framework.authentication import TokenAuthentication
from rest_framework.authtoken.models import Token


class BearerTokenAuthentication(TokenAuthentication):
    keyword = "Bearer"


def issue_token(user) -> str:
    token, _ = Token.objects.get_or_create(user=user)
    return token.key


def revoke_token(user) -> None:
    Token.objects.filter(user=user).delete()
