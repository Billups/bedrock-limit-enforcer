#!/usr/bin/env python3
"""Checks model-pricing.json against the AWS Price List API.

For every key in model-pricing.json -- plus any modelId seen in the Bedrock
invocation logs over the last --days days that has no entry yet -- looks up
the us-west-2 standard on-demand price (input, output, cache read, 5-minute
and 1-hour cache write) and prints what differs. Read-only by default:
--write rewrites model-pricing.json locally, and nothing is ever uploaded --
review the diff, open a PR, and upload to S3 as usual (see the README's
"Model pricing table" section).

Prices are matched to keys through MODEL_NAMES below (Price List model name
per logged model ID, without its region-group prefix), which has to be
extended by hand when a new model shows up -- the script reports those as
UNMAPPED rather than guessing. A "global." prefix gets the Global
cross-region price; "us." and no prefix get the standard (Geo / In-region)
price, matching how the file is already priced. Batch, flex, priority,
reserved, long-context and "mantle" (OpenAI-compatible endpoint) prices are
ignored.

Usage:
    python3 scripts/update_pricing.py                # show differences
    python3 scripts/update_pricing.py --write        # also rewrite model-pricing.json
    python3 scripts/update_pricing.py --check        # exit 1 if anything would change (for CI)
    python3 scripts/update_pricing.py --days 0       # skip the log scan

Shells out to the AWS CLI (no boto3 needed), like scripts/usage_report.py.
"""

import argparse
import json
import re
import subprocess
import sys
import time

DEFAULT_PRICING_FILE = "model-pricing.json"
DEFAULT_LOG_GROUP = "/aws/bedrock/invocations"
DEFAULT_REGION = "us-west-2"
PRICE_LIST_REGION = "us-east-1"  # the Price List API is only served from a few regions
REGION_PREFIXES = ("global.", "us.", "eu.", "apac.")
FIELD_ORDER = ("input", "output", "cacheWrite5m", "cacheWrite1h", "cacheRead")
BIG_CHANGE = 0.25  # flag price moves of 25% or more for a closer look
IGNORED_USAGE = ("batch", "flex", "priority", "reserved", "provisioned", "tpm",
                 "latency", "long", "mantle", "custom")

CLAUDE = "AmazonBedrockFoundationModels"  # Marketplace-billed models (Claude, OpenAI GPT-6)
OPEN_WEIGHT = "AmazonBedrock"

# Logged model ID (region-group prefix stripped) -> (Price List service, model name).
MODEL_NAMES = {
    "anthropic.claude-opus-5-5": (CLAUDE, "Claude Opus 5.5"),
    "anthropic.claude-opus-5": (CLAUDE, "Claude Opus 5"),
    "anthropic.claude-sonnet-5-5": (CLAUDE, "Claude Sonnet 5.5"),
    "anthropic.claude-sonnet-5": (CLAUDE, "Claude Sonnet 5"),
    "anthropic.claude-fable-5-1": (CLAUDE, "Claude Fable 5.1"),
    "anthropic.claude-opus-4-8": (CLAUDE, "Claude Opus 4.8"),
    "anthropic.claude-opus-4-7": (CLAUDE, "Claude Opus 4.7"),
    "anthropic.claude-opus-4-6-v1": (CLAUDE, "Claude Opus 4.6"),
    "anthropic.claude-sonnet-4-6": (CLAUDE, "Claude Sonnet 4.6"),
    "anthropic.claude-opus-4-5-20251101-v1:0": (CLAUDE, "Claude Opus 4.5"),
    "anthropic.claude-sonnet-4-5-20250929-v1:0": (CLAUDE, "Claude Sonnet 4.5"),
    "anthropic.claude-haiku-4-5-20251001-v1:0": (CLAUDE, "Claude Haiku 4.5"),
    "anthropic.claude-sonnet-4-20250514-v1:0": (CLAUDE, "Claude Sonnet 4"),
    "anthropic.claude-opus-4-1-20250805-v1:0": (CLAUDE, "Claude Opus 4.1"),
    "deepseek.v3.2": (OPEN_WEIGHT, "DeepSeek v3.2"),
    "deepseek.r1-v1:0": (OPEN_WEIGHT, "R1"),
    "qwen.qwen3-235b-a22b-2507-v1:0": (OPEN_WEIGHT, "Qwen3 235B A22B 2507"),
    "qwen.qwen3-coder-480b-a35b-v1:0": (OPEN_WEIGHT, "Qwen3 Coder 480B A35B"),
    "qwen.qwen3-32b-v1:0": (OPEN_WEIGHT, "Qwen3 32B"),
}

# Priced by hand because the Price List has no usable us-west-2 entry.
MANUAL = {
    "openai.gpt-5.6-luna": "no us-west-2 entry in the Price List; priced from its model card (see README)",
}


def aws(*args, region):
    result = subprocess.run(
        ["aws", *args, "--region", region, "--output", "json"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        sys.exit(f"aws {args[0]} {args[1]} failed:\n{result.stderr.strip()}")
    return json.loads(result.stdout)


def split_key(key):
    for prefix in REGION_PREFIXES:
        if key.startswith(prefix):
            return prefix, key[len(prefix):]
    return "", key


def classify(usage_type, want_global):
    """Maps a Price List usage type to a model-pricing.json field, or None.
    Newer models use e.g. USW2_cache_write_tokens_1h_global_standard, older
    ones USW2_CacheWrite1hInputTokenCount_Global, open-weight ones
    USW2-Qwen3-32B-input-tokens -- normalising underscores and case covers all three."""
    u = usage_type.lower()
    if any(word in u for word in IGNORED_USAGE) or ("global" in u) != want_global:
        return None
    u = u.replace("_", "").replace("-", "")
    if "cacheread" in u:
        return "cacheRead"
    if "cachewrite" in u:
        return "cacheWrite1h" if "1h" in u else "cacheWrite5m"
    if "input" in u:
        return "input"
    if "output" in u:
        return "output"
    return None


def fetch_prices(service, name, region):
    """Returns {field: set of USD-per-1K-token prices} for one model."""
    out = aws(
        "pricing", "get-products",
        "--service-code", service,
        "--filters",
        f"Type=TERM_MATCH,Field=model,Value={name}",
        f"Type=TERM_MATCH,Field=regionCode,Value={region}",
        region=PRICE_LIST_REGION,
    )
    rows = []
    for raw in out.get("PriceList", []):
        product = json.loads(raw)
        usage_type = product["product"]["attributes"].get("usagetype", "")
        for term in product["terms"].get("OnDemand", {}).values():
            for dim in term["priceDimensions"].values():
                per = {"1K tokens": 1, "1M tokens": 1000}.get(dim["unit"])
                if per:
                    rows.append((usage_type, float(dim["pricePerUnit"]["USD"]) / per))
    return rows


def list_prices(rows, want_global):
    found = {}
    for usage_type, price in rows:
        field = classify(usage_type, want_global)
        if field:
            found.setdefault(field, set()).add(round(price, 10))
    return found


def logged_models(log_group, days, region):
    if days <= 0:
        return set()
    end = int(time.time())
    started = aws(
        "logs", "start-query",
        "--log-group-name", log_group,
        "--start-time", str(end - days * 86400),
        "--end-time", str(end),
        "--query-string", "stats count(*) by modelId",
        region=region,
    )
    while True:
        result = aws("logs", "get-query-results", "--query-id", started["queryId"], region=region)
        if result["status"] in ("Complete", "Failed", "Cancelled", "Timeout"):
            break
        time.sleep(1)
    if result["status"] != "Complete":
        sys.exit(f"Logs Insights query ended as {result['status']}")
    models = set()
    for row in result["results"]:
        fields = {f["field"]: f["value"] for f in row}
        if fields.get("modelId"):
            # Same normalisation as the enforcer's lookup: drop any ARN prefix.
            models.add(fields["modelId"].rsplit("/", 1)[-1])
    return models


def fmt_price(value):
    return f"{value:.10f}".rstrip("0").rstrip(".") if value else "0"


def entry_line(key, prices):
    fields = [f for f in FIELD_ORDER if f in prices] + [f for f in prices if f not in FIELD_ORDER]
    body = ", ".join(f'"{f}": {fmt_price(prices[f])}' for f in fields)
    return f'  "{key}": {{{body}}}'


def write_file(path, raw_text, current, proposed):
    """Rewrites only the entries that changed, keeping every other line (and
    so the hand-formatted look of the file) byte-for-byte."""
    original_lines = {}
    for line in raw_text.splitlines():
        m = re.match(r'\s*"([^"]+)"\s*:', line)
        if m:
            original_lines[m.group(1)] = line.rstrip().rstrip(",")
    lines = []
    for key, prices in proposed.items():
        unchanged = key in current and current[key] == prices and key in original_lines
        lines.append(original_lines[key] if unchanged else entry_line(key, prices))
    with open(path, "w") as f:
        f.write("{\n" + ",\n".join(lines) + "\n}\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--file", default=DEFAULT_PRICING_FILE)
    parser.add_argument("--region", default=DEFAULT_REGION, help="Region whose prices (and logs) to use.")
    parser.add_argument("--log-group", default=DEFAULT_LOG_GROUP)
    parser.add_argument("--days", type=int, default=30, help="Scan this many days of logs for new models (0 = skip).")
    parser.add_argument("--write", action="store_true", help="Rewrite --file with the proposed prices.")
    parser.add_argument("--check", action="store_true", help="Exit 1 if anything would change.")
    args = parser.parse_args()

    with open(args.file) as f:
        raw_text = f.read()
    current = json.loads(raw_text)
    keys = list(current) + sorted(logged_models(args.log_group, args.days, args.region) - set(current))

    proposed = {k: dict(v) for k, v in current.items()}
    cache = {}
    report = {"CHANGED": [], "NEW": [], "UNMAPPED": [], "NOT FOUND": [], "AMBIGUOUS": [], "MANUAL": []}
    ok = 0
    for key in keys:
        prefix, model_id = split_key(key)
        if key in MANUAL:
            report["MANUAL"].append(f"{key}: {MANUAL[key]}")
            continue
        if model_id not in MODEL_NAMES:
            where = "in model-pricing.json" if key in current else "seen in logs, not priced"
            report["UNMAPPED"].append(f"{key} ({where}) -- add it to MODEL_NAMES")
            continue
        service, name = MODEL_NAMES[model_id]
        if (service, name) not in cache:
            cache[(service, name)] = fetch_prices(service, name, args.region)
        found = list_prices(cache[(service, name)], want_global=(prefix == "global."))
        if not found:
            report["NOT FOUND"].append(f"{key} ({name!r} has no {args.region} on-demand price in {service})")
            continue

        new_prices = dict(current.get(key, {}))
        notes = []
        for field, values in found.items():
            if len(values) > 1:
                report["AMBIGUOUS"].append(f"{key} {field}: {sorted(values)} -- left as is")
                continue
            price = next(iter(values))
            old = new_prices.get(field)
            if old is None or abs(old - price) > 1e-12:
                change = f"{field} {fmt_price(old) if old is not None else '-'} -> {fmt_price(price)}"
                if old and abs(price - old) / old >= BIG_CHANGE:
                    change += f" ({(price - old) / old:+.0%}, check this)"
                notes.append(change)
                new_prices[field] = price

        if key not in current:
            proposed[key] = new_prices
            report["NEW"].append(f"{key}: " + ", ".join(f"{f} {fmt_price(v)}" for f, v in new_prices.items()))
        elif notes:
            proposed[key] = new_prices
            report["CHANGED"].append(f"{key}: " + "; ".join(notes))
        else:
            ok += 1

    print(f"{ok} entr{'y' if ok == 1 else 'ies'} match the Price List ({args.region}, per 1K tokens).")
    for label, lines in report.items():
        for line in lines:
            print(f"{label:<10} {line}")

    changed = proposed != current
    if args.write and changed:
        write_file(args.file, raw_text, current, proposed)
        print(f"\nWrote {args.file}. Review with `git diff`, then PR and upload to S3 as usual.")
    elif changed:
        print("\nRun with --write to apply the CHANGED/NEW entries to the file.")
    if args.check and changed:
        sys.exit(1)


if __name__ == "__main__":
    main()
