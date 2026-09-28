"""Bedrock per-user budget monthly reset.

Runs once a month (day 1, 00:05 UTC, via EventBridge cron). Clears the
DynamoDB blocklist table and removes this system's Deny statement
(Sid=DENY_SID) from the IAM Identity Center permission set's inline policy,
so last month's blocks don't carry over into the new month.

See src/enforcer/index.py's module docstring, the CloudFormation template's
header comment, and the project README for the full architecture rationale.
This function intentionally shares the same wait_for_provisioning() polling
logic as the enforcer -- duplicated rather than shared via a Lambda layer,
since it's small and the two functions are otherwise independent. If this
grows, moving it into a shared layer is the natural next step.
"""

import json
import os
import time

import boto3

ssoadmin = boto3.client("sso-admin")
ddb = boto3.resource("dynamodb")
sns = boto3.client("sns")

TABLE_NAME = os.environ["BLOCKED_TABLE"]
INSTANCE_ARN = os.environ["SSO_INSTANCE_ARN"]
PERMISSION_SET_ARN = os.environ["PERMISSION_SET_ARN"]
DENY_SID = os.environ.get("DENY_SID", "BedrockBudgetHardStopPerUser")
TOPIC_ARN = os.environ.get("ALERT_TOPIC_ARN")

table = ddb.Table(TABLE_NAME)


def wait_for_provisioning(request_id):
    for _ in range(30):
        resp = ssoadmin.describe_permission_set_provisioning_status(
            InstanceArn=INSTANCE_ARN,
            ProvisionPermissionSetRequestId=request_id,
        )
        status = resp["PermissionSetProvisioningStatus"]["Status"]
        if status == "SUCCEEDED":
            return
        if status == "FAILED":
            reason = resp["PermissionSetProvisioningStatus"].get("FailureReason", "unknown")
            raise RuntimeError(f"Permission set provisioning failed: {reason}")
        time.sleep(2)
    raise RuntimeError("Permission set provisioning did not finish in time")


def lambda_handler(event, context):
    items = table.scan().get("Items", [])
    for item in items:
        table.delete_item(Key={"username": item["username"]})

    resp = ssoadmin.get_inline_policy_for_permission_set(
        InstanceArn=INSTANCE_ARN,
        PermissionSetArn=PERMISSION_SET_ARN,
    )
    raw = resp.get("InlinePolicy") or ""
    removed = False

    if raw:
        doc = json.loads(raw)
        statements = doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        remaining = [s for s in statements if s.get("Sid") != DENY_SID]
        if len(remaining) != len(statements):
            removed = True
            doc["Statement"] = remaining
            if remaining:
                ssoadmin.put_inline_policy_to_permission_set(
                    InstanceArn=INSTANCE_ARN,
                    PermissionSetArn=PERMISSION_SET_ARN,
                    InlinePolicy=json.dumps(doc),
                )
            else:
                ssoadmin.delete_inline_policy_from_permission_set(
                    InstanceArn=INSTANCE_ARN,
                    PermissionSetArn=PERMISSION_SET_ARN,
                )
            provision = ssoadmin.provision_permission_set(
                InstanceArn=INSTANCE_ARN,
                PermissionSetArn=PERMISSION_SET_ARN,
                TargetType="ALL_PROVISIONED_ACCOUNTS",
            )
            wait_for_provisioning(provision["PermissionSetProvisioningStatus"]["RequestId"])

    if TOPIC_ARN:
        sns.publish(
            TopicArn=TOPIC_ARN,
            Subject="Bedrock: monthly block reset",
            Message=(
                f"Cleared {len(items)} blocked users from last month. "
                f"Deny statement removed from permission set: {removed}."
            ),
        )

    return {"cleared_users": len(items), "policy_statement_removed": removed}
