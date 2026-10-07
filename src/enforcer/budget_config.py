"""Loading and validation for budget-config.json (tiers and user
assignments).

Kept free of boto3 and environment-variable reads so the exact same
validation runs in three places: the enforcer Lambda on every run,
deploy.sh before uploading the file, and scripts/migrate_cap_to_bonus.py.

budget-config.json is the permanent policy (which tiers exist, what each
one's monthly cap is, which tier each user is in). The DynamoDB table only
holds this month's temporary exceptions on top of it (bonusUsd), which the
monthly reset wipes -- see the project README.

Validation is deliberately strict (unknown keys, duplicate keys, and
usernames that only differ by case are all errors): the enforcer stops the
whole run on an invalid config rather than guessing, so a typo surfaces as
an alert instead of as someone silently getting the wrong cap.

Shape:

    {
      "defaultTier": "standard",
      "tiers": {
        "basic":    {"monthlyCapUsd": 70},
        "standard": {"monthlyCapUsd": 150}
      },
      "users": {
        "someone@billups.com": {"tier": "basic"}
      }
    }

Exempt usernames are NOT part of this file -- they stay in the
EXEMPT_USERNAMES env var (CloudFormation ExemptUsernames parameter), since
they're infrastructure (application/service accounts outside the budget
system) rather than budget policy. Listing an exempt username under
"users" is rejected, so the two sources can't contradict each other.
"""

import json

TOP_LEVEL_KEYS = {"defaultTier", "tiers", "users"}
TIER_KEYS = {"monthlyCapUsd"}
USER_KEYS = {"tier"}


class ConfigError(ValueError):
    pass


class BudgetConfig:
    def __init__(self, default_tier, tier_caps, user_tiers):
        self.default_tier = default_tier
        # tier name -> monthly cap in USD
        self.tier_caps = tier_caps
        # lowercased username -> tier name
        self.user_tiers = user_tiers

    def tier_for(self, username):
        """Usernames are matched case-insensitively -- the session name
        IAM Identity Center puts in the logs isn't guaranteed to use the
        same casing as whoever typed the config entry."""
        return self.user_tiers.get(username.lower(), self.default_tier)

    def tier_cap_for(self, username):
        return self.tier_caps[self.tier_for(username)]


def _reject_duplicate_keys(pairs):
    # json.loads silently keeps the last of two duplicate keys -- a user
    # accidentally listed twice would get whichever entry came last with no
    # warning, so treat it as an error instead.
    result = {}
    for key, value in pairs:
        if key in result:
            raise ConfigError(f"duplicate key {key!r}")
        result[key] = value
    return result


def _is_number(value):
    # bool is a subclass of int in Python -- "monthlyCapUsd": true must not
    # pass as a cap of $1.
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _check_keys(obj, allowed, where):
    if not isinstance(obj, dict):
        raise ConfigError(f"{where} must be a JSON object")
    unknown = set(obj) - allowed
    if unknown:
        raise ConfigError(f"{where} has unknown key(s): {', '.join(sorted(unknown))}")


def parse_config(raw, exempt_usernames=()):
    """Parses and validates budget-config.json's raw text. Raises
    ConfigError describing the first problem found."""
    try:
        doc = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as e:
        raise ConfigError(f"invalid JSON: {e}") from e

    _check_keys(doc, TOP_LEVEL_KEYS, "config")

    tiers = doc.get("tiers")
    if not isinstance(tiers, dict) or not tiers:
        raise ConfigError("'tiers' must be a non-empty object")
    tier_caps = {}
    for name, tier in tiers.items():
        _check_keys(tier, TIER_KEYS, f"tier {name!r}")
        cap = tier.get("monthlyCapUsd")
        if not _is_number(cap) or cap <= 0:
            raise ConfigError(f"tier {name!r}: monthlyCapUsd must be a number > 0")
        tier_caps[name] = float(cap)

    default_tier = doc.get("defaultTier")
    if default_tier not in tier_caps:
        raise ConfigError(f"defaultTier {default_tier!r} is not a defined tier")

    users = doc.get("users", {})
    if not isinstance(users, dict):
        raise ConfigError("'users' must be an object")
    exempt_lower = {u.lower() for u in exempt_usernames}
    user_tiers = {}
    for username, entry in users.items():
        _check_keys(entry, USER_KEYS, f"user {username!r}")
        key = username.lower()
        if key in user_tiers:
            raise ConfigError(f"user {username!r} is listed more than once (usernames are case-insensitive)")
        if key in exempt_lower:
            raise ConfigError(f"user {username!r} is in ExemptUsernames and must not also be assigned a tier")
        tier = entry.get("tier")
        if tier not in tier_caps:
            raise ConfigError(f"user {username!r}: tier {tier!r} is not a defined tier")
        user_tiers[key] = tier

    return BudgetConfig(default_tier, tier_caps, user_tiers)


if __name__ == "__main__":
    # Used by deploy.sh: python3 src/enforcer/budget_config.py <path>
    import sys

    with open(sys.argv[1]) as f:
        cfg = parse_config(f.read())
    print(
        f"OK: {len(cfg.tier_caps)} tier(s), default {cfg.default_tier!r}, "
        f"{len(cfg.user_tiers)} user assignment(s)"
    )
