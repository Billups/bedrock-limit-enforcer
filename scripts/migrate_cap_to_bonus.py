#!/usr/bin/env python3
"""One-off migration: per-user capUsd overrides -> bonusUsd top-ups.

Before tiers, the enforcer read capUsd back from each user's DynamoDB item
as a per-user override. It now ignores capUsd (it's written for visibility
only) and computes the cap as tier cap (budget-config.json) + bonusUsd. This
converts every existing override into the equivalent bonus, so nobody's
cap changes when the new code goes live:

    bonusUsd = capUsd - <cap of the user's tier in budget-config.json>

Items whose capUsd equals --old-default (the previous MonthlyCapUSD) are
not overrides -- the old enforcer just copied the default in -- and are
skipped, as are items that already have a bonusUsd.

Must run while the OLD enforcer is paused: the old code PutItem's the whole
item every run, which would erase the bonusUsd written here. Order:

    aws events disable-rule --name bedrock-budget-hardstop-enforcer-schedule --region us-west-2
    python3 scripts/migrate_cap_to_bonus.py            # dry run, review
    python3 scripts/migrate_cap_to_bonus.py --apply
    ./deploy.sh
    aws events enable-rule --name bedrock-budget-hardstop-enforcer-schedule --region us-west-2

--apply refuses to run while the schedule is enabled. Validates the LOCAL
budget-config.json (the one deploy.sh is about to upload). Shells out to
the AWS CLI (no boto3 needed), like scripts/usage_report.py.
"""

import argparse
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "enforcer"))
from budget_config import parse_config  # noqa: E402

DEFAULT_TABLE = "bedrock-budget-hardstop-blocked-users"
DEFAULT_RULE = "bedrock-budget-hardstop-enforcer-schedule"
DEFAULT_REGION = "us-west-2"


def aws(*args):
    result = subprocess.run(
        ["aws", *args, "--region", REGION, "--output", "json"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        sys.exit(f"aws {args[0]} {args[1]} failed:\n{result.stderr.strip()}")
    return json.loads(result.stdout) if result.stdout.strip() else {}


def plain(attr):
    # {"S": "150"} / {"N": "150"} / {"BOOL": true} -> python value
    return list(attr.values())[0]


def main():
    global REGION
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--config", default="budget-config.json")
    parser.add_argument("--old-default", type=float, default=150.0,
                        help="Previous MonthlyCapUSD value (default 150).")
    parser.add_argument("--table", default=DEFAULT_TABLE)
    parser.add_argument("--rule", default=DEFAULT_RULE)
    parser.add_argument("--region", default=DEFAULT_REGION)
    parser.add_argument("--apply", action="store_true", help="Write changes (default: dry run).")
    args = parser.parse_args()
    REGION = args.region

    with open(args.config) as f:
        config = parse_config(f.read())

    if args.apply:
        state = aws("events", "describe-rule", "--name", args.rule).get("State")
        if state != "DISABLED":
            sys.exit(f"Refusing --apply: rule {args.rule} is {state}. Disable it first (see --help).")

    items = aws("dynamodb", "scan", "--table-name", args.table).get("Items", [])
    to_migrate = []
    for item in items:
        username = plain(item["username"])
        if "capUsd" not in item or "bonusUsd" in item:
            continue
        cap = float(plain(item["capUsd"]))
        if cap == args.old_default:
            continue
        tier = config.tier_for(username)
        bonus = round(cap - config.tier_caps[tier], 2)
        if bonus == 0:
            continue
        to_migrate.append((username, cap, tier, bonus))

    if not to_migrate:
        print("Nothing to migrate.")
        return

    for username, cap, tier, bonus in to_migrate:
        print(f"{username}: capUsd {cap:g} -> tier {tier} ({config.tier_caps[tier]:g}) + bonusUsd {bonus:+g}")
        if args.apply:
            aws(
                "dynamodb", "update-item",
                "--table-name", args.table,
                "--key", json.dumps({"username": {"S": username}}),
                "--update-expression", "SET bonusUsd = :b",
                "--condition-expression", "attribute_not_exists(bonusUsd)",
                "--expression-attribute-values", json.dumps({":b": {"N": str(bonus)}}),
            )

    print(f"\n{len(to_migrate)} item(s) {'migrated' if args.apply else 'would be migrated (dry run)'}.")


if __name__ == "__main__":
    main()
