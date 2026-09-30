"""Bedrock per-user budget enforcer.

Runs on a schedule (every EvaluationRateMinutes, via EventBridge). Each run:

  1. Reads Bedrock model invocation logs (CloudWatch Logs Insights) for the
     current calendar month, grouped by session (identity.arn) and modelId.
  2. Extracts each user's username from their session's RoleSessionName
     (IAM Identity Center fills this with the person's username/email).
  3. Prices each user's token usage using MODEL_PRICING_JSON (USD per 1,000
     tokens, keyed by the EXACT modelId string as logged).
  4. Skips/self-heals any username listed in EXEMPT_USERNAMES.
  5. Records anyone at or over MONTHLY_CAP_USD in DynamoDB, then rewrites the
     IAM Identity Center permission set's inline policy so its Deny
     statement (Sid=DENY_SID) matches the full current blocklist. This is
     self-healing: it only writes+provisions when the permission set's
     actual state differs from DynamoDB's desired state, so a prior run that
     updated DynamoDB but crashed before provisioning gets corrected here
     automatically.

See the CloudFormation template's header comment and the project README for
the full architecture rationale (why the Permission Set and not the IAM role
directly, the sso: IAM action prefix, the org delegated-administrator
requirement, etc.) -- this file is intentionally just the runtime logic.
"""

import json
import os
import re
import time
from datetime import datetime, timezone

import boto3

logs_client = boto3.client("logs")
ssoadmin = boto3.client("sso-admin")
ddb = boto3.resource("dynamodb")
sns = boto3.client("sns")

TABLE_NAME = os.environ["BLOCKED_TABLE"]
LOG_GROUP = os.environ["BEDROCK_LOG_GROUP"]
INSTANCE_ARN = os.environ["SSO_INSTANCE_ARN"]
PERMISSION_SET_ARN = os.environ["PERMISSION_SET_ARN"]
DENY_SID = os.environ.get("DENY_SID", "BedrockBudgetHardStopPerUser")
CAP_USD = float(os.environ["MONTHLY_CAP_USD"])
PRICING = json.loads(os.environ["MODEL_PRICING_JSON"])
TOPIC_ARN = os.environ.get("ALERT_TOPIC_ARN")
EXEMPT_USERNAMES = {
    u.strip() for u in os.environ.get("EXEMPT_USERNAMES", "").split(",") if u.strip()
}

table = ddb.Table(TABLE_NAME)

DENIED_ACTIONS = [
    "bedrock:InvokeModel",
    "bedrock:InvokeModelWithResponseStream",
    "bedrock:Converse",
    "bedrock:ConverseStream",
]


def extract_username(principal_arn):
    """From the assumed-role session ARN, extract the RoleSessionName
    (which Identity Center fills with the user's username/email). Falls
    back to other ARN shapes if needed."""
    m = re.search(r"assumed-role/[^/]+/(.+)$", principal_arn)
    if m:
        return m.group(1)
    m2 = re.search(r":user/(.+)$", principal_arn)
    if m2:
        return m2.group(1)
    return principal_arn


def month_start_epoch_seconds():
    now = datetime.now(timezone.utc)
    start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    return int(start.timestamp())


def run_insights_query(start_s, end_s):
    query = (
        "fields identity.arn as principal, modelId as model, "
        "input.inputTokenCount as inTok, output.outputTokenCount as outTok "
        "| stats sum(inTok) as totalIn, sum(outTok) as totalOut by principal, model"
    )
    started = logs_client.start_query(
        logGroupName=LOG_GROUP,
        startTime=start_s,
        endTime=end_s,
        queryString=query,
        limit=10000,
    )
    query_id = started["queryId"]
    result = {"status": "Running"}
    for _ in range(45):
        result = logs_client.get_query_results(queryId=query_id)
        if result["status"] in ("Complete", "Failed", "Cancelled"):
            break
        time.sleep(2)
    if result["status"] != "Complete":
        raise RuntimeError(f"Logs Insights query did not complete: {result['status']}")
    return result["results"]


def rows_to_dicts(rows):
    parsed = []
    for row in rows:
        parsed.append({f["field"]: f["value"] for f in row})
    return parsed


def get_current_policy():
    """Reads the permission set's current inline policy. Returns
    (doc_without_our_statement, usernames_currently_blocked)."""
    resp = ssoadmin.get_inline_policy_for_permission_set(
        InstanceArn=INSTANCE_ARN,
        PermissionSetArn=PERMISSION_SET_ARN,
    )
    raw = resp.get("InlinePolicy") or ""
    if not raw:
        return {"Version": "2012-10-17", "Statement": []}, set()

    doc = json.loads(raw)
    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    current_usernames = set()
    other_statements = []
    for stmt in statements:
        if stmt.get("Sid") == DENY_SID:
            values = stmt.get("Condition", {}).get("StringLike", {}).get("aws:userid", [])
            if isinstance(values, str):
                values = [values]
            for v in values:
                current_usernames.add(v.split(":", 1)[-1] if ":" in v else v)
        else:
            other_statements.append(stmt)

    doc["Statement"] = other_statements
    return doc, current_usernames


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


def apply_blocklist(all_blocked):
    """Rewrites the permission set's inline policy so our Deny statement
    reflects exactly all_blocked, preserving every other statement
    untouched. Self-healing no-op if already correct -- this also repairs a
    previous run that updated DynamoDB but failed before writing the
    policy."""
    base_doc, current_usernames = get_current_policy()

    if set(all_blocked) == current_usernames:
        return False

    statements = base_doc.get("Statement", [])
    if all_blocked:
        statements.append({
            "Sid": DENY_SID,
            "Effect": "Deny",
            "Action": DENIED_ACTIONS,
            "Resource": "*",
            "Condition": {
                "StringLike": {
                    "aws:userid": [f"*:{u}" for u in all_blocked]
                }
            },
        })
    base_doc["Statement"] = statements

    if statements:
        # IAM Identity Center rejects an inline policy with an empty
        # Statement array -- only PUT when there's at least one statement
        # left (ours, and/or whatever else was already in the inline
        # policy slot).
        ssoadmin.put_inline_policy_to_permission_set(
            InstanceArn=INSTANCE_ARN,
            PermissionSetArn=PERMISSION_SET_ARN,
            InlinePolicy=json.dumps(base_doc),
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
    return True


def lambda_handler(event, context):
    now_s = int(time.time())
    start_s = month_start_epoch_seconds()

    raw_rows = run_insights_query(start_s, now_s)
    rows = rows_to_dicts(raw_rows)

    cost_by_user = {}
    unpriced_models = set()

    for r in rows:
        principal = r.get("principal", "")
        model = r.get("model", "")
        total_in = float(r.get("totalIn", 0) or 0)
        total_out = float(r.get("totalOut", 0) or 0)

        if not model:
            # Logs Insights emits one all-null result row per query when any
            # log entry lacks both identity.arn and modelId (e.g. non-invoke
            # entries sharing this log group). That's not a real model to
            # price -- skip it silently instead of flagging it as unpriced,
            # so the alert stays a real signal for actual new/renamed models.
            continue

        price = PRICING.get(model)
        if not price:
            unpriced_models.add(model)
            continue

        cost = (total_in / 1000.0) * price.get("input", 0) + \
               (total_out / 1000.0) * price.get("output", 0)

        username = extract_username(principal)
        cost_by_user[username] = cost_by_user.get(username, 0) + cost

    newly_blocked = []
    for username, cost in cost_by_user.items():
        if username in EXEMPT_USERNAMES:
            continue
        if cost >= CAP_USD:
            existing = table.get_item(Key={"username": username}).get("Item")
            if not existing:
                table.put_item(Item={
                    "username": username,
                    "blockedAt": datetime.now(timezone.utc).isoformat(),
                    "costAtBlock": str(round(cost, 2)),
                })
                newly_blocked.append((username, cost))

    # Self-heal: an exempt username should never stay blocked, even if it
    # got added before ExemptUsernames included it (or before this
    # parameter existed at all).
    newly_unblocked_exempt = []
    for exempt_user in EXEMPT_USERNAMES:
        existing = table.get_item(Key={"username": exempt_user}).get("Item")
        if existing:
            table.delete_item(Key={"username": exempt_user})
            newly_unblocked_exempt.append(exempt_user)

    all_blocked = [item["username"] for item in table.scan().get("Items", [])]

    policy_changed = apply_blocklist(all_blocked)

    if newly_blocked and TOPIC_ARN:
        lines = [f"- {u}: ${c:.2f}" for u, c in newly_blocked]
        sns.publish(
            TopicArn=TOPIC_ARN,
            Subject=f"Bedrock: users blocked (cap ${CAP_USD:.0f}/month)",
            Message="Bedrock access was blocked for:\n" + "\n".join(lines),
        )

    if unpriced_models and TOPIC_ARN:
        sns.publish(
            TopicArn=TOPIC_ARN,
            Subject="Bedrock budget: models missing a price entry",
            Message=(
                "These modelId values showed up in the logs but have no "
                "entry in MODEL_PRICING_JSON, so their cost is NOT being "
                "counted:\n" + "\n".join(sorted(unpriced_models))
            ),
        )

    return {
        "evaluated_users": len(cost_by_user),
        "newly_blocked": [u for u, _ in newly_blocked],
        "newly_unblocked_exempt": newly_unblocked_exempt,
        "total_blocked": all_blocked,
        "permission_set_policy_updated": policy_changed,
        "unpriced_models": list(unpriced_models),
    }
