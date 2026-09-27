"""Microsoft Entra ID (Azure AD) bearer-token validation with fastapi-azure-auth."""
import os

from fastapi_azure_auth import SingleTenantAzureAuthorizationCodeBearer

APP_CLIENT_ID = os.environ["AZURE_APP_CLIENT_ID"]
TENANT_ID = os.environ["AZURE_TENANT_ID"]
OPENAPI_CLIENT_ID = os.environ.get("AZURE_OPENAPI_CLIENT_ID", "")

azure_scheme = SingleTenantAzureAuthorizationCodeBearer(
    app_client_id=APP_CLIENT_ID,
    tenant_id=TENANT_ID,
    scopes={f"api://{APP_CLIENT_ID}/user_impersonation": "user_impersonation"},
)


async def load_azure_openid_config() -> None:
    await azure_scheme.openid_config.load_config()
