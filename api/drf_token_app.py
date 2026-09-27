from django.contrib.auth import authenticate
from django.urls import path
from rest_framework import status
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response

from authentication.drf_token_auth import BearerTokenAuthentication, issue_token, revoke_token


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
def obtain_token(request):
    user = authenticate(request, username=request.data.get("username"), password=request.data.get("password"))
    if user is None:
        return Response({"error": "invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)
    return Response({"token": issue_token(user)})


@api_view(["POST"])
@authentication_classes([BearerTokenAuthentication])
@permission_classes([IsAuthenticated])
def logout(request):
    revoke_token(request.user)
    return Response(status=status.HTTP_204_NO_CONTENT)


@api_view(["GET"])
@authentication_classes([BearerTokenAuthentication])
@permission_classes([IsAuthenticated])
def whoami(request):
    return Response({"username": request.user.username})


urlpatterns = [
    path("token", obtain_token),
    path("logout", logout),
    path("whoami", whoami),
]
