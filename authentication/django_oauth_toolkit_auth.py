"""OAuth2 provider + bearer-token authentication with django-oauth-toolkit."""
from oauth2_provider.contrib.rest_framework import OAuth2Authentication


class OAuth2BearerAuthentication(OAuth2Authentication):
    def authenticate_header(self, request):
        return 'Bearer realm="api"'
