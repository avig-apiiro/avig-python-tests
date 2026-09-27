"""OAuth2 resource-server protection (RFC 9068 JWT access tokens) with Authlib."""
import os

import requests
from authlib.integrations.flask_oauth2 import ResourceProtector
from authlib.jose import JsonWebKey
from authlib.oauth2.rfc9068 import JWTBearerTokenValidator

ISSUER = os.environ["OIDC_ISSUER"]
AUDIENCE = os.environ["OIDC_AUDIENCE"]


class IssuerJWTValidator(JWTBearerTokenValidator):
    def get_jwks(self):
        metadata = requests.get(f"{ISSUER}/.well-known/openid-configuration", timeout=5).json()
        return JsonWebKey.import_key_set(requests.get(metadata["jwks_uri"], timeout=5).json())


require_oauth = ResourceProtector()
require_oauth.register_token_validator(IssuerJWTValidator(issuer=ISSUER, resource_server=AUDIENCE))
