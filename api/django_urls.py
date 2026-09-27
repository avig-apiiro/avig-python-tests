from django.urls import include, path

urlpatterns = [
    path("session/", include("api.django_session_app")),
    path("drf-token/", include("api.drf_token_app")),
    path("drf-jwt/", include("api.drf_simplejwt_app")),
    path("oauth/", include("api.django_oauth_toolkit_app")),
    path("ninja/", include("api.django_ninja_app")),
    path("owner/", include("api.drf_object_permissions_app")),
    path("guardian/", include("api.django_guardian_app")),
]
