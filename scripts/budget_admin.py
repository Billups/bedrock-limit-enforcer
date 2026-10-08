#!/usr/bin/env python3
"""Day-to-day admin for this month's budget exceptions.

budget-config.json is the permanent policy (tiers, teams); this script only
edits the temporary per-user exceptions in DynamoDB that the monthly reset
wipes -- bonusUsd and teamBypass -- and shows where everyone stands. It
replaces hand-typed `aws dynamodb update-item` calls, and resolves the
username case-insensitively against existing items, so a top-up can't land
on a differently-cased key the enforcer never reads.

Usage:
    python3 scripts/budget_admin.py status
    python3 scripts/budget_admin.py status --team data-science
    python3 scripts/budget_admin.py status --user ana@billups.com
    python3 scripts/budget_admin.py topup ana@billups.com 50          # adds $50 this month
    python3 scripts/budget_admin.py topup ana@billups.com 200 --set  # bonus becomes exactly $200
    python3 scripts/budget_admin.py clear-topup ana@billups.com
    python3 scripts/budget_admin.py bypass ana@billups.com            # off the team cap this month
    python3 scripts/budget_admin.py bypass ana@billups.com --off

topup/clear-topup/bypass take --now to invoke the enforcer right away
instead of waiting for the next scheduled run (unblocks land in ~1-2 min).
Shells out to the AWS CLI (no boto3 needed), like scripts/usage_report.py.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "enforcer"))
from budget_config import parse_config  # noqa: E402

DEFAULT_TABLE = "bedrock-budget-hardstop-blocked-users"
DEFAULT_FUNCTION = "bedrock-budget-hardstop-enforcer"
DEFAULT_REGION = "us-west-2"
TEAM_KEY_PREFIX = "team#"


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


def scan_items():
    items = aws("dynamodb", "scan", "--table-name", TABLE).get("Items", [])
    return [{k: plain(v) for k, v in item.items()} for item in items]


def resolve_username(typed, items):
    """Returns the key to write to: an existing item's exact casing if one
    matches case-insensitively, else what was typed (with a warning --
    the enforcer only ever reads the exact session-name casing)."""
    matches = [
        i["username"] for i in items
        if i["username"].lower() == typed.lower() and not i["username"].startswith(TEAM_KEY_PREFIX)
    ]
    if len(matches) > 1:
        sys.exit(f"Several items match {typed!r} case-insensitively: {matches}. Fix the table first.")
    if matches:
        if matches[0] != typed:
            print(f"Using existing item {matches[0]!r}")
        return matches[0]
    print(
        f"Note: {typed!r} has no usage this month yet. Writing it as typed -- "
        f"make sure the casing matches their SSO username exactly."
    )
    return typed


def update(username, expression, values=None):
    args = [
        "dynamodb", "update-item",
        "--table-name", TABLE,
        "--key", json.dumps({"username": {"S": username}}),
        "--update-expression", expression,
    ]
    if values:
        args += ["--expression-attribute-values", json.dumps(values)]
    aws(*args)


def run_enforcer_now():
    print(f"Invoking {FUNCTION} (can take a minute or two)...")
    with tempfile.NamedTemporaryFile(suffix=".json") as out:
        aws("lambda", "invoke", "--function-name", FUNCTION, "--cli-read-timeout", "300", out.name)
        result = json.load(open(out.name))
    if "errorMessage" in result:
        sys.exit(f"Enforcer run failed: {result['errorMessage']}")
    for key in ("newly_unblocked", "newly_blocked", "teams_over_budget", "total_blocked"):
        print(f"  {key}: {result.get(key, [])}")


def fmt_money(value):
    try:
        return f"{float(value):.2f}"
    except (TypeError, ValueError):
        return "-"


def cmd_status(args):
    items = scan_items()
    teams = sorted((i for i in items if i["username"].startswith(TEAM_KEY_PREFIX)), key=lambda i: i["username"])
    users = [i for i in items if not i["username"].startswith(TEAM_KEY_PREFIX)]

    if args.team:
        teams = [t for t in teams if t["username"] == TEAM_KEY_PREFIX + args.team]
        users = [u for u in users if u.get("team") == args.team]
    if args.user:
        teams = []
        users = [u for u in users if u["username"].lower() == args.user.lower()]

    if teams:
        print("TEAMS")
        for t in teams:
            state = "OVER BUDGET" if t.get("overBudget") else ""
            print(f"  {t['username'][len(TEAM_KEY_PREFIX):]:<24} {fmt_money(t.get('currentUsageUsd')):>9} / "
                  f"{fmt_money(t.get('capUsd')):<9} members={t.get('memberCount', '-'):<4} {state}")
        print()

    users.sort(key=lambda u: float(u.get("currentUsageUsd", 0) or 0), reverse=True)
    print("USERS")
    if not users:
        print("  (none with usage this month)")
    for u in users:
        flags = []
        if u.get("blocked"):
            flags.append(f"BLOCKED({u.get('blockReason', '?')})")
        if u.get("exempt"):
            flags.append("exempt")
        if "bonusUsd" in u:
            flags.append(f"bonus {float(u['bonusUsd']):+g}")
        if u.get("teamBypass") in (True, "true", "True"):
            flags.append(f"team-bypass (counted {fmt_money(u.get('teamContributionUsd'))})")
        # An exempt account's capUsd is just the default tier's -- not a real limit.
        cap = "-" if u.get("exempt") else fmt_money(u.get("capUsd"))
        print(f"  {u['username']:<36} {u.get('tier', '-'):<9} {u.get('team', '-'):<16} "
              f"{fmt_money(u.get('currentUsageUsd')):>9} / {cap:<9} {' '.join(flags)}")


def cmd_topup(args):
    username = resolve_username(args.user, scan_items())
    if args.set:
        update(username, "SET bonusUsd = :b", {":b": {"N": str(args.amount)}})
    else:
        update(username, "SET bonusUsd = if_not_exists(bonusUsd, :z) + :b",
               {":b": {"N": str(args.amount)}, ":z": {"N": "0"}})
    print(f"{'Set' if args.set else 'Added'} bonus {args.amount:+g} for {username} (until the monthly reset).")
    if args.now:
        run_enforcer_now()


def cmd_clear_topup(args):
    username = resolve_username(args.user, scan_items())
    update(username, "REMOVE bonusUsd")
    print(f"Removed bonus for {username}.")
    if args.now:
        run_enforcer_now()


def cmd_bypass(args):
    with open(args.config) as f:
        config = parse_config(f.read())
    team = config.team_for(args.user)
    if not args.off and not team:
        sys.exit(f"{args.user!r} isn't in any team in {args.config} -- there's no team cap to bypass.")
    username = resolve_username(args.user, scan_items())
    if args.off:
        # Dropping teamContributionUsd puts their full month's spend back on
        # the team, matching what the enforcer does when the flag goes away.
        update(username, "REMOVE teamBypass, teamContributionUsd")
        print(f"{username} is back on {'team ' + team.name if team else 'their team'}'s cap (full month's spend counts again).")
    else:
        update(username, "SET teamBypass = :t", {":t": {"BOOL": True}})
        print(f"{username} is off team {team.name}'s cap until the monthly reset. Their own cap still applies.")
    if args.now:
        run_enforcer_now()


def main():
    global REGION, TABLE, FUNCTION
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--table", default=DEFAULT_TABLE)
    parser.add_argument("--function", default=DEFAULT_FUNCTION, help="Enforcer Lambda, for --now.")
    parser.add_argument("--region", default=DEFAULT_REGION)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("status", help="Show teams and users with usage this month.")
    p.add_argument("--team")
    p.add_argument("--user")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("topup", help="Add (or --set) a bonus to a user's cap until the monthly reset.")
    p.add_argument("user")
    p.add_argument("amount", type=float)
    p.add_argument("--set", action="store_true", help="Replace the bonus instead of adding to it.")
    p.add_argument("--now", action="store_true", help="Run the enforcer immediately.")
    p.set_defaults(func=cmd_topup)

    p = sub.add_parser("clear-topup", help="Remove a user's bonus.")
    p.add_argument("user")
    p.add_argument("--now", action="store_true", help="Run the enforcer immediately.")
    p.set_defaults(func=cmd_clear_topup)

    p = sub.add_parser("bypass", help="Exempt a user from their team's cap until the monthly reset.")
    p.add_argument("user")
    p.add_argument("--off", action="store_true", help="Put them back on the team's cap.")
    p.add_argument("--config", default="budget-config.json", help="Used to check team membership.")
    p.add_argument("--now", action="store_true", help="Run the enforcer immediately.")
    p.set_defaults(func=cmd_bypass)

    args = parser.parse_args()
    REGION, TABLE, FUNCTION = args.region, args.table, args.function
    args.func(args)


if __name__ == "__main__":
    main()
