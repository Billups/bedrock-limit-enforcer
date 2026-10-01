"""Bedrock per-user budget enforcer.

Runs on a schedule (every EvaluationRateMinutes, via EventBridge). Each run:

  1. Reads Bedrock model invocation logs (CloudWatch Logs Insights) for the
     current calendar month, grouped by session (identity.arn) and modelId.
  2. Extracts each user's username from their session's RoleSessionName
     (IAM Identity Center fills this with the person's username/email).
  3. Prices each user's token usage -- input, output, and (since Claude
     prompt caching bills these as separate line items) cache-write and
     cache-read tokens -- using the pricing table fetched fresh from S3
     (MODEL_PRICING_BUCKET/MODEL_PRICING_KEY) on every run, so pricing edits
     take effect without a redeploy. Cache-write is priced at the 5-minute
     TTL rate; the invocation log doesn't distinguish 5-minute from 1-hour
     cache writes, so 1-hour usage (if any) is undercounted -- see the
     project README for how to validate/adjust this.
  4. Skips/self-heals any username listed in EXEMPT_USERNAMES.
  5. Upserts every evaluated user into DynamoDB with their current
     month-to-date usage, whether they're exempt, and whether they're
     blocked -- the table is a live usage ledger, not just a blocklist. Each
     user's effective cap defaults to MONTHLY_CAP_USD, but if their existing
     DynamoDB item already has a capUsd value, that value is preserved and
     used instead, so a per-user override (set by hand, or by future tooling)
     sticks across runs.
  6. Records anyone at or over their effective cap, then rewrites the IAM
     Identity Center permission set's inline policy so its Deny statement
     (Sid=DENY_SID) matches the full current blocklist. This is
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
s3 = boto3.client("s3")

TABLE_NAME = os.environ["BLOCKED_TABLE"]
LOG_GROUP = os.environ["BEDROCK_LOG_GROUP"]
INSTANCE_ARN = os.environ["SSO_INSTANCE_ARN"]
PERMISSION_SET_ARN = os.environ["PERMISSION_SET_ARN"]
DENY_SID = os.environ.get("DENY_SID", "BedrockBudgetHardStopPerUser")
CAP_USD = float(os.environ["MONTHLY_CAP_USD"])
PRICING_BUCKET = os.environ["MODEL_PRICING_BUCKET"]
PRICING_KEY = os.environ["MODEL_PRICING_KEY"]
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
        "input.inputTokenCount as inTok, output.outputTokenCount as outTok, "
        "input.cacheReadInputTokenCount as cacheReadTok, "
        "input.cacheWriteInputTokenCount as cacheWriteTok "
        "| stats sum(inTok) as totalIn, sum(outTok) as totalOut, "
        "sum(cacheReadTok) as totalCacheRead, sum(cacheWriteTok) as totalCacheWrite "
        "by principal, model"
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

    # Fetched fresh every run (not cached at module load) so a pricing edit
    # in S3 takes effect on the next scheduled run, no redeploy needed.
    pricing = json.loads(s3.get_object(Bucket=PRICING_BUCKET, Key=PRICING_KEY)["Body"].read())

    raw_rows = run_insights_query(start_s, now_s)
    rows = rows_to_dicts(raw_rows)

    cost_by_user = {}
    unpriced_models = set()
    unpriced_cache_models = set()

    for r in rows:
        principal = r.get("principal", "")
        model = r.get("model", "")
        total_in = float(r.get("totalIn", 0) or 0)
        total_out = float(r.get("totalOut", 0) or 0)
        total_cache_read = float(r.get("totalCacheRead", 0) or 0)
        total_cache_write = float(r.get("totalCacheWrite", 0) or 0)

        if not model:
            # Logs Insights emits one all-null result row per query when any
            # log entry lacks both identity.arn and modelId (e.g. non-invoke
            # entries sharing this log group). That's not a real model to
            # price -- skip it silently instead of flagging it as unpriced,
            # so the alert stays a real signal for actual new/renamed models.
            continue

        price = pricing.get(model)
        if not price:
            unpriced_models.add(model)
            continue

        cost = (total_in / 1000.0) * price.get("input", 0) + \
               (total_out / 1000.0) * price.get("output", 0)

        # Claude prompt caching bills cache-write/cache-read as separate line
        # items from ordinary input/output tokens. cache-write is priced at
        # the 5-minute TTL rate -- the invocation log has no field
        # distinguishing a 5-minute from a 1-hour cache write, so 1-hour
        # usage (if any) is undercounted here. See README for how this was
        # validated.
        if (total_cache_read or total_cache_write) and (
            "cacheRead" not in price or "cacheWrite5m" not in price
        ):
            unpriced_cache_models.add(model)
        else:
            cost += (total_cache_read / 1000.0) * price.get("cacheRead", 0) + \
                    (total_cache_write / 1000.0) * price.get("cacheWrite5m", 0)

        username = extract_username(principal)
        cost_by_user[username] = cost_by_user.get(username, 0) + cost

    # Every evaluated user (blocked or not, exempt or not) gets an upsert
    # here with their current month-to-date usage -- this makes the table a
    # live ledger of everyone's spend, not just a blocklist, so "who's close
    # to the cap" is a plain scan away. blockedAt/costAtBlock are preserved
    # from the first time a given user actually crossed the cap rather than
    # being overwritten on every run. capUsd is likewise preserved once set:
    # a per-user override in DDB (e.g. hand-edited to raise/lower one
    # person's cap) sticks across runs instead of being reset back to the
    # global MONTHLY_CAP_USD, which only applies to users with no override.
    now_iso = datetime.now(timezone.utc).isoformat()
    newly_blocked = []
    for username, cost in cost_by_user.items():
        is_exempt = username in EXEMPT_USERNAMES

        existing = table.get_item(Key={"username": username}).get("Item") or {}
        was_blocked = bool(existing.get("blocked"))
        try:
            effective_cap = float(existing["capUsd"]) if "capUsd" in existing else CAP_USD
        except (TypeError, ValueError):
            effective_cap = CAP_USD

        should_block = (not is_exempt) and cost >= effective_cap

        item = {
            "username": username,
            "currentUsageUsd": str(round(cost, 2)),
            "capUsd": str(effective_cap),
            "lastUpdated": now_iso,
            "exempt": is_exempt,
            "blocked": should_block,
        }
        if should_block:
            item["blockedAt"] = existing.get("blockedAt") if was_blocked else now_iso
            item["costAtBlock"] = existing.get("costAtBlock") if was_blocked else str(round(cost, 2))

        table.put_item(Item=item)

        if should_block and not was_blocked:
            newly_blocked.append((username, cost, effective_cap))

    # Self-heal: an exempt username should never stay blocked, even if it
    # got added before ExemptUsernames included it (or before this parameter
    # existed at all), or if it had no usage this run (so the loop above
    # never touched it). Unlike before, this no longer deletes the row --
    # exempt users' usage stays tracked, only the block itself is cleared.
    newly_unblocked_exempt = []
    for exempt_user in EXEMPT_USERNAMES:
        existing = table.get_item(Key={"username": exempt_user}).get("Item")
        if existing and existing.get("blocked"):
            table.update_item(
                Key={"username": exempt_user},
                UpdateExpression="SET blocked = :f, exempt = :t REMOVE blockedAt, costAtBlock",
                ExpressionAttributeValues={":f": False, ":t": True},
            )
            newly_unblocked_exempt.append(exempt_user)

    all_blocked = [
        item["username"] for item in table.scan().get("Items", [])
        if item.get("blocked")
    ]

    policy_changed = apply_blocklist(all_blocked)

    if newly_blocked and TOPIC_ARN:
        lines = [f"- {u}: ${c:.2f} (cap ${cap:.0f})" for u, c, cap in newly_blocked]
        sns.publish(
            TopicArn=TOPIC_ARN,
            Subject=f"Bedrock: users blocked (default cap ${CAP_USD:.0f}/month)",
            Message="Bedrock access was blocked for:\n" + "\n".join(lines),
        )

    if unpriced_models and TOPIC_ARN:
        sns.publish(
            TopicArn=TOPIC_ARN,
            Subject="Bedrock budget: models missing a price entry",
            Message=(
                "These modelId values showed up in the logs but have no "
                "entry in model-pricing.json, so their cost is NOT being "
                "counted:\n" + "\n".join(sorted(unpriced_models))
            ),
        )

    if unpriced_cache_models and TOPIC_ARN:
        sns.publish(
            TopicArn=TOPIC_ARN,
            Subject="Bedrock budget: models missing cache pricing",
            Message=(
                "These modelId values logged cache-read/cache-write tokens "
                "but their model-pricing.json entry has no cacheRead/"
                "cacheWrite5m rate, so that cache usage is NOT being "
                "counted (input/output usage for them still is):\n"
                + "\n".join(sorted(unpriced_cache_models))
            ),
        )

    return {
        "evaluated_users": len(cost_by_user),
        "newly_blocked": [u for u, _, _ in newly_blocked],
        "newly_unblocked_exempt": newly_unblocked_exempt,
        "total_blocked": all_blocked,
        "permission_set_policy_updated": policy_changed,
        "unpriced_models": list(unpriced_models),
        "unpriced_cache_models": list(unpriced_cache_models),
    }
