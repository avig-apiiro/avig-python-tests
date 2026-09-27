"""Cedar-policy authorization with Amazon Verified Permissions (boto3)."""
import os

import boto3
from fastapi import HTTPException, status

POLICY_STORE_ID = os.environ["AVP_POLICY_STORE_ID"]
avp = boto3.client("verifiedpermissions", region_name=os.environ.get("AWS_REGION", "us-east-1"))


def is_authorized(user_id: str, action: str, resource_type: str, resource_id: str) -> bool:
    response = avp.is_authorized(
        policyStoreId=POLICY_STORE_ID,
        principal={"entityType": "MyApp::User", "entityId": user_id},
        action={"actionType": "MyApp::Action", "actionId": action},
        resource={"entityType": f"MyApp::{resource_type}", "entityId": resource_id},
    )
    return response["decision"] == "ALLOW"


def require_permission(user_id: str, action: str, resource_type: str, resource_id: str) -> None:
    if not is_authorized(user_id, action, resource_type, resource_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Denied by Verified Permissions")
