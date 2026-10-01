#!/usr/bin/env python3
"""Ad-hoc Bedrock usage/cost report for one UTC day, by user.

Runs the same CloudWatch Logs Insights query shape as the enforcer, but
scoped to a single day instead of month-to-date, and prices it with the
same model-pricing.json (fetched from S3) the enforcer uses -- including
cache-write/cache-read tokens, priced at the 5-minute TTL rate. Read-only
-- doesn't touch DynamoDB or the SSO permission set. Shells out to the AWS
CLI (no boto3 needed).

Usage:
    python3 scripts/usage_report.py 2026-09-29
    python3 scripts/usage_report.py 2026-09-29 --user jdoe
    python3 scripts/usage_report.py 2026-09-29 --log-group /aws/bedrock/invocations \
        --pricing-bucket bedrock-budget-hardstop-396026123718 --region us-west-2
"""

import argparse
import json
import re
import subprocess
import time
from datetime import datetime, timedelta, timezone

DEFAULT_LOG_GROUP = "/aws/bedrock/invocations"
DEFAULT_PRICING_BUCKET = "bedrock-budget-hardstop-396026123718"
DEFAULT_PRICING_KEY = "model-pricing.json"
DEFAULT_REGION = "us-west-2"


def aws(*args):
    result = subprocess.run(
        ["aws", *args, "--region", REGION, "--output", "json"],
        capture_output=True, text=True, check=True,
    )
    return json.loads(result.stdout)


def fetch_pricing(bucket, key):
    result = subprocess.run(
        ["aws", "s3", "cp", f"s3://{bucket}/{key}", "-", "--region", REGION],
        capture_output=True, text=True, check=True,
    )
    return json.loads(result.stdout)


def extract_username(principal_arn):
    m = re.search(r"assumed-role/[^/]+/(.+)$", principal_arn)
    if m:
        return m.group(1)
    m2 = re.search(r":user/(.+)$", principal_arn)
    if m2:
        return m2.group(1)
    return principal_arn


def day_bounds_epoch(date_str):
    day = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    return int(day.timestamp()), int((day + timedelta(days=1)).timestamp())


def run_insights_query(log_group, start_s, end_s):
    query = (
        "fields identity.arn as principal, modelId as model, "
        "input.inputTokenCount as inTok, output.outputTokenCount as outTok, "
        "input.cacheReadInputTokenCount as cacheReadTok, "
        "input.cacheWriteInputTokenCount as cacheWriteTok "
        "| stats sum(inTok) as totalIn, sum(outTok) as totalOut, "
        "sum(cacheReadTok) as totalCacheRead, sum(cacheWriteTok) as totalCacheWrite "
        "by principal, model"
    )
    started = aws(
        "logs", "start-query",
        "--log-group-name", log_group,
        "--start-time", str(start_s),
        "--end-time", str(end_s),
        "--query-string", query,
        "--limit", "10000",
    )
    query_id = started["queryId"]
    result = {"status": "Running"}
    for _ in range(45):
        result = aws("logs", "get-query-results", "--query-id", query_id)
        if result["status"] in ("Complete", "Failed", "Cancelled"):
            break
        time.sleep(2)
    if result["status"] != "Complete":
        raise RuntimeError(f"Logs Insights query did not complete: {result['status']}")
    return [{f["field"]: f["value"] for f in row} for row in result["results"]]


def main():
    global REGION
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("date", help="UTC day to report on, YYYY-MM-DD")
    parser.add_argument("--user", help="Only show this username (substring match)")
    parser.add_argument("--log-group", default=DEFAULT_LOG_GROUP)
    parser.add_argument("--pricing-bucket", default=DEFAULT_PRICING_BUCKET)
    parser.add_argument("--pricing-key", default=DEFAULT_PRICING_KEY)
    parser.add_argument("--region", default=DEFAULT_REGION)
    args = parser.parse_args()
    REGION = args.region

    start_s, end_s = day_bounds_epoch(args.date)

    pricing = fetch_pricing(args.pricing_bucket, args.pricing_key)
    rows = run_insights_query(args.log_group, start_s, end_s)

    cost_by_user = {}
    cache_write_cost_total = 0.0
    cache_read_cost_total = 0.0
    unpriced = set()
    unpriced_cache = set()
    for r in rows:
        model = r.get("model", "")
        if not model:
            continue
        username = extract_username(r.get("principal", ""))
        if args.user and args.user not in username:
            continue
        price = pricing.get(model)
        if not price:
            unpriced.add(model)
            continue
        total_in = float(r.get("totalIn", 0) or 0)
        total_out = float(r.get("totalOut", 0) or 0)
        total_cache_read = float(r.get("totalCacheRead", 0) or 0)
        total_cache_write = float(r.get("totalCacheWrite", 0) or 0)

        cost = (total_in / 1000.0) * price.get("input", 0) + (total_out / 1000.0) * price.get("output", 0)

        if (total_cache_read or total_cache_write) and (
            "cacheRead" not in price or "cacheWrite5m" not in price
        ):
            unpriced_cache.add(model)
        else:
            read_cost = (total_cache_read / 1000.0) * price.get("cacheRead", 0)
            write_cost = (total_cache_write / 1000.0) * price.get("cacheWrite5m", 0)
            cache_read_cost_total += read_cost
            cache_write_cost_total += write_cost
            cost += read_cost + write_cost

        cost_by_user[username] = cost_by_user.get(username, 0) + cost

    print(f"Usage for {args.date} (UTC):")
    for username, cost in sorted(cost_by_user.items(), key=lambda kv: kv[1], reverse=True):
        print(f"  {cost:>8.2f}  {username}")

    print(f"\nCache-write cost (5-min TTL rate): {cache_write_cost_total:.2f}")
    print(f"Cache-read cost: {cache_read_cost_total:.2f}")

    if unpriced:
        print("\nModels with no pricing entry (cost NOT counted above):")
        for m in sorted(unpriced):
            print(f"  {m}")
    if unpriced_cache:
        print("\nModels with cache usage but no cache pricing entry (cache cost NOT counted above):")
        for m in sorted(unpriced_cache):
            print(f"  {m}")


if __name__ == "__main__":
    main()
