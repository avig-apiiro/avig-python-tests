from django.urls import include, path
from oauth2_provider.contrib.rest_framework import TokenHasReadWriteScope
from rest_framework.response import Response
from rest_framework.views import APIView

from authentication.django_oauth_toolkit_auth import OAuth2BearerAuthentication


class ProfileView(APIView):
    authentication_classes = [OAuth2BearerAuthentication]
    permission_classes = [TokenHasReadWriteScope]

    def get(self, request):
        return Response({"username": request.user.username, "scope": request.auth.scope})


urlpatterns = [
    path("o/", include("oauth2_provider.urls", namespace="oauth2_provider")),
    path("profile", ProfileView.as_view()),
]
