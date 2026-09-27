from django.urls import path
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from authentication.drf_simplejwt_auth import RoleClaimTokenSerializer


class LoginView(TokenObtainPairView):
    serializer_class = RoleClaimTokenSerializer


class OrdersView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({"owner": request.user.username, "roles": request.auth.get("roles", []), "orders": []})


urlpatterns = [
    path("token", LoginView.as_view()),
    path("token/refresh", TokenRefreshView.as_view()),
    path("orders", OrdersView.as_view()),
]
