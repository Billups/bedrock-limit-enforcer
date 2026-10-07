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
  5. Resolves each user's effective cap from budget-config.json (fetched
     from S3 every run, like the pricing table): the cap of the tier the
     user is assigned to (or defaultTier), plus any bonusUsd on their
     DynamoDB item. The tier is re-resolved on every run, so moving a user
     to another tier takes effect on the next run in either direction --
     including unblocking them if the new cap is above their spend.
     bonusUsd is a temporary top-up (negative values lower the cap) that
     only the monthly reset clears. An invalid or missing config stops the
     run before anything is written (SNS alert + Lambda error), leaving the
     current blocks exactly as they are. Every evaluated user's DynamoDB
     item is updated with their month-to-date usage, tier, and effective
     cap -- the table is a live usage ledger, not just a blocklist. capUsd
     on the item is written for visibility only and never read back.
  6. Records anyone at or over their effective cap, then rewrites the IAM
     Identity Center permission set's inline policy so its Deny statement
     (Sid=DENY_SID) matches the full current blocklist. This is
     self-healing: it only writes+provisions when the permission set's
     actual state differs from DynamoDB's desired state, so a prior run that
     updated DynamoDB but crashed before provisioning gets corrected here
     automatically.
  7. Also emails the affected user directly via SES (if SES_SENDER_EMAIL is
     set) -- once at WARN_THRESHOLD_FRACTION of their cap (re-armed if the
     cap changes), once the moment they're newly blocked, and once when a
     cap increase unblocks them -- independent of the batched admin SNS
     alert above. A username that isn't a valid email (e.g. a service
     account) is silently skipped, and an SES failure is logged but never
     allowed to abort the run.

See the CloudFormation template's header comment and the project README for
the full architecture rationale (why the Permission Set and not the IAM role
directly, the sso: IAM action prefix, the org delegated-administrator
requirement, etc.) -- this file is intentionally just the runtime logic.
"""

import json
import logging
import os
import re
import time
from datetime import datetime, timezone

import boto3

from budget_config import ConfigError, parse_config

logger = logging.getLogger()
logger.setLevel(logging.INFO)

logs_client = boto3.client("logs")
ssoadmin = boto3.client("sso-admin")
ddb = boto3.resource("dynamodb")
sns = boto3.client("sns")
s3 = boto3.client("s3")
ses = boto3.client("ses")

TABLE_NAME = os.environ["BLOCKED_TABLE"]
LOG_GROUP = os.environ["BEDROCK_LOG_GROUP"]
INSTANCE_ARN = os.environ["SSO_INSTANCE_ARN"]
PERMISSION_SET_ARN = os.environ["PERMISSION_SET_ARN"]
DENY_SID = os.environ.get("DENY_SID", "BedrockBudgetHardStopPerUser")
PRICING_BUCKET = os.environ["MODEL_PRICING_BUCKET"]
PRICING_KEY = os.environ["MODEL_PRICING_KEY"]
BUDGET_CONFIG_KEY = os.environ["BUDGET_CONFIG_KEY"]
TOPIC_ARN = os.environ.get("ALERT_TOPIC_ARN")
SES_SENDER_EMAIL = os.environ.get("SES_SENDER_EMAIL")
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

# Fixed by design, not a CFN parameter -- this is a notification-timing
# detail nobody has asked to tune, unlike the tier caps.
WARN_THRESHOLD_FRACTION = 0.75

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


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


def is_valid_email(username):
    """True only if username looks like a real email address. Service
    account usernames (e.g. audrai_ai_agent) deliberately fail this check
    silently -- they're not emails and have no inbox to notify."""
    return bool(EMAIL_RE.match(username))


def send_user_email(username, subject, body):
    """Best-effort per-user notification via SES. Must never raise -- an
    SES error (sandbox restriction, unverified recipient, throttling,
    missing SES_SENDER_EMAIL) is logged and swallowed so it can't abort
    enforcement; DynamoDB writes and the permission-set Deny rewrite have
    to happen either way."""
    if not SES_SENDER_EMAIL or not is_valid_email(username):
        return
    try:
        ses.send_email(
            Source=SES_SENDER_EMAIL,
            Destination={"ToAddresses": [username]},
            Message={
                "Subject": {"Data": subject},
                "Body": {"Text": {"Data": body}},
            },
        )
    except Exception:
        logger.exception("Failed to send SES notification to %s", username)


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


def load_budget_config():
    """Fetches and validates budget-config.json. Any failure (missing
    object, bad JSON, failed validation) alerts and re-raises, so the run
    stops before touching DynamoDB or the permission set -- existing blocks
    stay exactly as they are, and nobody new is blocked or unblocked until
    the config is fixed."""
    try:
        raw = s3.get_object(Bucket=PRICING_BUCKET, Key=BUDGET_CONFIG_KEY)["Body"].read()
        return parse_config(raw, EXEMPT_USERNAMES)
    except Exception as e:
        logger.exception("Could not load budget config")
        if TOPIC_ARN:
            sns.publish(
                TopicArn=TOPIC_ARN,
                Subject="Bedrock budget: enforcement stopped, invalid budget config",
                Message=(
                    f"s3://{PRICING_BUCKET}/{BUDGET_CONFIG_KEY} could not be "
                    f"loaded, so this enforcement run was skipped entirely. "
                    f"Current blocks are left in place; no one will be newly "
                    f"blocked or unblocked until it's fixed.\n\n"
                    f"{type(e).__name__}: {e}"
                ),
            )
        raise


def parse_bonus(username, existing):
    """bonusUsd is hand-edited (or written by admin tooling), so it may be
    stored as either a DynamoDB number or a string. An unparseable value is
    treated as 0 -- the stricter outcome -- rather than failing the run."""
    if "bonusUsd" not in existing:
        return 0.0
    try:
        return float(existing["bonusUsd"])
    except (TypeError, ValueError):
        logger.warning("Ignoring unparseable bonusUsd %r for %s", existing["bonusUsd"], username)
        return 0.0


def update_user_item(username, sets, removes):
    """Writes only the attributes the enforcer owns. An UpdateItem (not a
    PutItem of the whole item) so a bonusUsd an admin sets between this
    run's GetItem and this write can't be overwritten."""
    names = {}
    values = {}
    set_parts = []
    for i, (attr, value) in enumerate(sets.items()):
        names[f"#s{i}"] = attr
        values[f":s{i}"] = value
        set_parts.append(f"#s{i} = :s{i}")
    expr = "SET " + ", ".join(set_parts)
    if removes:
        remove_parts = []
        for i, attr in enumerate(removes):
            names[f"#r{i}"] = attr
            remove_parts.append(f"#r{i}")
        expr += " REMOVE " + ", ".join(remove_parts)
    table.update_item(
        Key={"username": username},
        UpdateExpression=expr,
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
    )


def lambda_handler(event, context):
    now_s = int(time.time())
    start_s = month_start_epoch_seconds()

    # Loaded first so an invalid config stops the run before the (slow)
    # Logs Insights query.
    budget = load_budget_config()

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

        # modelId can be logged as a bare model/profile id or as the full
        # inference-profile ARN -- both forms carry the same price, so match
        # on the substring after the last "/" (unchanged if there is none).
        price = pricing.get(model.rsplit("/", 1)[-1])
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
    # being overwritten on every run. The effective cap is always recomputed
    # from budget-config.json + bonusUsd; the capUsd written here is only a
    # snapshot for whoever reads the table.
    now_iso = datetime.now(timezone.utc).isoformat()
    newly_blocked = []
    newly_warned = []
    newly_unblocked = []
    for username, cost in cost_by_user.items():
        is_exempt = username in EXEMPT_USERNAMES

        existing = table.get_item(Key={"username": username}).get("Item") or {}
        was_blocked = bool(existing.get("blocked"))
        tier = budget.tier_for(username)
        tier_cap = budget.tier_caps[tier]
        effective_cap = tier_cap + parse_bonus(username, existing)
        # The warning is tied to the cap it was sent against: if the cap
        # changes (tier move, bonus), it re-arms. Items warned before
        # warnedAtCapUsd existed are assumed to match, so deploying this
        # doesn't re-send this month's warnings.
        try:
            was_warned = bool(existing.get("warnedAt")) and (
                "warnedAtCapUsd" not in existing
                or float(existing["warnedAtCapUsd"]) == effective_cap
            )
        except (TypeError, ValueError):
            was_warned = False

        should_block = (not is_exempt) and cost >= effective_cap
        is_unblocking = was_blocked and not should_block
        over_warn_line = (
            (not is_exempt)
            and not should_block
            and cost >= WARN_THRESHOLD_FRACTION * effective_cap
        )
        # Only warn on the way up to the cap -- a user who jumps straight
        # from under 75% to over 100% in one evaluation cycle gets just the
        # block email below, not a redundant warning first. A user being
        # unblocked into the warning zone gets the unblock email instead,
        # which already states their usage against the new cap.
        should_warn = over_warn_line and not was_warned and not is_unblocking

        sets = {
            "currentUsageUsd": str(round(cost, 2)),
            "tier": tier,
            "tierCapUsd": str(tier_cap),
            "capUsd": str(effective_cap),
            "lastUpdated": now_iso,
            "exempt": is_exempt,
            "blocked": should_block,
        }
        removes = []
        if should_block and not was_blocked:
            sets["blockedAt"] = now_iso
            sets["costAtBlock"] = str(round(cost, 2))
        elif not should_block:
            removes += ["blockedAt", "costAtBlock"]
        if over_warn_line and not was_warned:
            sets["warnedAt"] = now_iso
            sets["warnedAtCapUsd"] = str(effective_cap)
        elif not over_warn_line and not was_warned:
            # Below the line for the current cap (or blocked/exempt): clear
            # any warning sent against an older cap so it can fire again.
            removes += ["warnedAt", "warnedAtCapUsd"]

        update_user_item(username, sets, removes)

        if should_warn:
            newly_warned.append((username, cost, effective_cap))
            send_user_email(
                username,
                subject="Bedrock usage notice: you're near your monthly budget",
                body=(
                    f"Your personal Amazon Bedrock usage this month is "
                    f"${cost:.2f}, which has reached "
                    f"{WARN_THRESHOLD_FRACTION * 100:.0f}% of your "
                    f"${effective_cap:.0f}/month cap. This is based on your own "
                    f"usage only, not a shared/team alert. If you reach the "
                    f"full cap, your Bedrock access will be automatically "
                    f"blocked for the rest of the calendar month."
                ),
            )

        if should_block and not was_blocked:
            newly_blocked.append((username, cost, effective_cap, tier))
            send_user_email(
                username,
                subject="Bedrock access blocked: monthly budget reached",
                body=(
                    f"Your personal Amazon Bedrock usage this month reached "
                    f"${cost:.2f}, at or above your ${effective_cap:.0f}/month "
                    f"cap. Your Bedrock access has been blocked for the rest "
                    f"of the calendar month. This is based on your own usage "
                    f"only, not a team-wide limit. Access resets "
                    f"automatically on the 1st."
                ),
            )

        if is_unblocking and not is_exempt:
            # Emailed only after apply_blocklist() succeeds below, so the
            # email never arrives before the Deny is actually gone.
            newly_unblocked.append((username, cost, effective_cap))

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

    for username, cost, effective_cap in newly_unblocked:
        send_user_email(
            username,
            subject="Bedrock access restored",
            body=(
                f"Your Amazon Bedrock monthly cap has been raised to "
                f"${effective_cap:.0f}, and your access has been restored. "
                f"Your usage so far this month is ${cost:.2f}. If you reach "
                f"the new cap, your access will be blocked again for the "
                f"rest of the calendar month."
            ),
        )

    if newly_blocked and TOPIC_ARN:
        lines = [
            f"- {u}: ${c:.2f} (cap ${cap:.0f}, tier {tier})"
            for u, c, cap, tier in newly_blocked
        ]
        sns.publish(
            TopicArn=TOPIC_ARN,
            Subject="Bedrock: users blocked",
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
        "newly_blocked": [u for u, _, _, _ in newly_blocked],
        "newly_warned": [u for u, _, _ in newly_warned],
        "newly_unblocked": [u for u, _, _ in newly_unblocked],
        "newly_unblocked_exempt": newly_unblocked_exempt,
        "total_blocked": all_blocked,
        "permission_set_policy_updated": policy_changed,
        "unpriced_models": list(unpriced_models),
        "unpriced_cache_models": list(unpriced_cache_models),
    }
