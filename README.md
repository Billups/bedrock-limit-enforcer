# Bedrock Per-User Budget Hard Stop (Shared SSO Permission Set)

Caps Amazon Bedrock spend per user per month — by budget tier (e.g.
**$70 / $150 / $300**, defined in `budget-config.json`) — and actually blocks access
when a user crosses their cap — not just an email alert. Built for the case
where every Bedrock user in the account assumes the **same** IAM Identity
Center (SSO) permission set, so there's no per-person IAM identity to hang
a budget on.

Stack name used in this doc: `bedrock-budget-hardstop`. Template file:
`bedrock-budget-hardstop-sso.yaml`. Account: `396026123718`, region
`us-west-2`.

## Table of contents

- [Why this exists](#why-this-exists)
- [How it works](#how-it-works)
- [What gets deployed](#what-gets-deployed)
- [Prerequisites](#prerequisites)
- [Parameters reference](#parameters-reference)
- [Model pricing table](#model-pricing-table)
- [Budget tiers](#budget-tiers)
- [Teams](#teams)
- [Deploying](#deploying)
- [Testing before you trust it](#testing-before-you-trust-it)
- [Modifying and redeploying](#modifying-and-redeploying)
- [Whitelisting a user (exempting them from the cap)](#whitelisting-a-user-exempting-them-from-the-cap)
- [Removing the block for one individual user](#removing-the-block-for-one-individual-user)
- [Monitoring](#monitoring)
- [Known limitations](#known-limitations)
- [Troubleshooting](#troubleshooting)
- [Tearing it down](#tearing-it-down)

## Why this exists

Amazon Bedrock has no native "$X per user per month" cap. AWS Budgets can
alert on spend, but doesn't block anything by itself, and it's tag-based —
it needs each request tagged by user, which requires either:

- **Application Inference Profiles** (a distinct ARN per user, tagged for
  cost allocation) — only works if your application controls which ARN it
  invokes.
- **A distinct IAM identity per user** — only works if each person has
  their own IAM user/role.

Neither applies here: everyone authenticates through IAM Identity Center
(SSO) and assumes the **same shared permission set**
(`bedrock-limited-access`). From AWS's perspective, every call comes from
the same underlying IAM role — individual people only show up as different
*sessions* of that one role.

Also ruled out during setup: `bedrock-mantle` (a separate Bedrock API
surface not covered by invocation logging) is confirmed **not** in use in
this account, so the logging-based approach below sees 100% of real traffic.

## How it works

Amazon Bedrock's model invocation logs always include an `identity.arn`
field, and when a user authenticates via IAM Identity Center, AWS
automatically sets `RoleSessionName` to that person's username/email. That's
the hook this whole design relies on: **the shared role's assumed-role ARN
already encodes who made each call**, even though the role itself is
identical for everyone.

```
AWS Budgets (native)          -->  can alert, cannot identify a session, cannot block
Application Inference Profile -->  needs per-user ARNs the app doesn't control
This solution                 -->  reads identity.arn from logs, blocks by session name
```

**The enforcement target is the IAM Identity Center Permission Set, not the
IAM role.** it manages the **Permission Set** through the `sso-admin` API, 
and let Identity Center push the change down into the real role:

1. `GetInlinePolicyForPermissionSet` — read the permission set's current
   inline policy (this is the same policy that ends up on the provisioned
   role; it holds the real Allow statements, e.g. `BedrockAPIs`, that give
   users their actual Bedrock access).
2. Strip out this system's own Deny statement if a previous run already
   added one (matched by `Sid`), leaving every other statement untouched.
3. If anyone is currently over budget, append a fresh Deny statement.
4. `PutInlinePolicyToPermissionSet` — write the combined policy back. (If
   the result has zero statements left, use
   `DeleteInlinePolicyFromPermissionSet` instead — Identity Center rejects
   an inline policy with an empty `Statement` array.)
5. `ProvisionPermissionSet` (`TargetType=ALL_PROVISIONED_ACCOUNTS`) — push
   the change from the Permission Set down into the real IAM role in every
   account it's assigned to. This is async; poll
   `DescribePermissionSetProvisioningStatus` until `SUCCEEDED`.

Pipeline, run on a schedule (every 15 minutes by default):

1. **Read.** Query CloudWatch Logs Insights over the Bedrock invocation log
   group for the current calendar month, grouped by `identity.arn` and
   `modelId`, summing input, output, cache-write, and cache-read token
   counts.
2. **Attribute.** Extract the username from each `identity.arn`'s
   `RoleSessionName` (the part after `assumed-role/<role>/`).
3. **Price.** Convert each user's token totals to USD using a per-model
   price table fetched from S3 each run, summed across all models they used
   this month. Cache-write is priced at the 5-minute TTL rate — see
   [Model pricing table](#model-pricing-table) for why.
4. **Exempt.** Skip anyone in `ExemptUsernames` entirely (see
   [Whitelisting](#whitelisting-a-user-exempting-them-from-the-cap)), and
   proactively unblock them if they're already blocked.
5. **Enforce.** Each user's cap is their tier's cap from `budget-config.json`
   plus any temporary `bonusUsd` on their DynamoDB item (see
   [Budget tiers](#budget-tiers)), recomputed every run. Team members are
   also blocked when their team's combined spend reaches the team's cap
   (see [Teams](#teams)). Any non-exempt user at or over a limit gets recorded
   in DynamoDB. The Lambda then rewrites the permission set's inline policy
   so its Deny statement's `aws:userid` condition matches `*:<username>` for
   every currently-blocked user. An explicit Deny always wins over the
   permission set's other Allow statements, so this reliably blocks Bedrock
   calls for that person without touching anyone else sharing the set.
6. **Self-heal.** Every run recomputes the desired blocked-user set from
   DynamoDB and compares it against what's *actually* in the permission
   set's policy right now — it only writes + provisions when they differ.
   That makes the system resilient to a run that updates DynamoDB but then
   fails before provisioning (network blip, throttling, etc.): the next
   cycle corrects it automatically.
7. **Reset.** On the 1st of each month, a second Lambda clears the blocked
   list (and with it every `bonusUsd` top-up) and removes the Deny
   statement, so last month's blocks and exceptions don't carry over —
   everyone starts the month on their tier's cap.

Why `aws:userid` and not a tag or a separate role: for an assumed-role
session, `aws:userid` has the form `<role-unique-id>:<RoleSessionName>`.
Matching `*:<username>` (wildcard on the role-id part) means the condition
survives the underlying role being reprovisioned, and doesn't require
Identity Center attribute-based access control (session tags) to already be
configured.

**Org-boundary requirement:** the `sso-admin`/`sso:` admin APIs used above
only work when called from the AWS Organizations **management account**, or
from an account registered as **delegated administrator** for IAM Identity
Center. A plain member account — even with full `AdministratorAccess` —
gets `AccessDeniedException` on every `sso:*` call otherwise. See
[Prerequisites](#prerequisites).

## What gets deployed

| Resource | Purpose |
|---|---|
| `BlockedUsersTable` (DynamoDB) | Live per-user usage ledger for the current month (everyone the enforcer has seen, not just blocked users) and source of truth for who's currently blocked. |
| `AlertTopic` (SNS) + email subscription | Notifies on new blocks, monthly reset, and models missing a price entry. |
| `EnforcerFunctionRole` (IAM Role) | Lets the enforcer read Bedrock logs, manage the permission set's inline policy via `sso:*`, and read/write the DynamoDB table. |
| `EnforcerFunction` (Lambda, Python 3.12) | Runs the read → attribute → price → exempt → enforce → self-heal loop. |
| `EnforcerSchedule` (EventBridge rule) | Triggers the enforcer every `EvaluationRateMinutes`. |
| `ResetFunctionRole` (IAM Role) | Same `sso:*` permissions, scoped to the reset Lambda's needs. |
| `ResetFunction` (Lambda) | Clears the blocklist and removes the Deny statement from the permission set. |
| `ResetSchedule` (EventBridge rule) | Cron `5 0 1 * ? *` — 00:05 UTC on the 1st of each month. |

Nothing here touches Bedrock itself, the doIT billing relationship, or
anyone else's access — it only ever adds/removes one `Sid`-tagged Deny
statement (`BedrockBudgetHardStopPerUser`) inside the
`bedrock-limited-access` permission set's inline policy, leaving every
other statement (the real Bedrock Allow grants) untouched.

## Prerequisites

These must be done once, before the first deploy — the stack assumes they
already exist:

1. **This account must be a delegated administrator for IAM Identity
   Center**, or be the Organizations management account. Without this,
   every `sso:*` call the Lambdas make fails with `AccessDeniedException`
   no matter what IAM permissions the caller has. Registration must be run
   **from the management account** (`872515258828`) by someone with access
   to it:
   ```bash
   aws organizations register-delegated-administrator \
     --account-id 396026123718 --service-principal sso.amazonaws.com
   ```
   This account (`396026123718`) was registered on 2026-09-17. If this
   stack is ever redeployed into a fresh account, redo this step first.

2. **Bedrock model invocation logging enabled**, CloudWatch Logs only,
   pointing at log group `/aws/bedrock/invocations` (Bedrock console →
   Settings → Model invocation logging):
   ```bash
   aws bedrock put-model-invocation-logging-configuration \
     --logging-config '{"cloudWatchConfig":{"logGroupName":"/aws/bedrock/invocations","roleArn":"arn:aws:iam::396026123718:role/service-role/BedrockLoggingRole"}}'
   ```
   Recommended config:
   - Data types (Text/Image/Embedding/Video): **leave unchecked**. The
     fields this system needs — `identity.arn`, `modelId`,
     `input.inputTokenCount`, `output.outputTokenCount` — are metadata
     that Bedrock logs unconditionally. The checkboxes only control whether
     the *raw prompt/response content* is also stored, which multiplies log
     volume (and cost) for no benefit here, and stores user prompts you
     don't need.
   - Retention: 60 days is enough (the system only ever looks at the
     current month).
   - Log class: Infrequent Access.

3. **Know the SSO instance ARN and the target permission set's ARN.** Find
   both with (always with `--region` matching the instance's
   `PrimaryRegion`):
   ```bash
   aws sso-admin list-instances --region us-west-2
   aws sso-admin list-permission-sets --instance-arn <instance-arn> --region us-west-2
   aws sso-admin describe-permission-set --instance-arn <instance-arn> \
     --permission-set-arn <permission-set-arn> --region us-west-2
   ```
   Already pre-filled as the defaults for `SSOInstanceArn` /
   `PermissionSetArn` below, for the `bedrock-limited-access` permission
   set in this account.

4. **A deploy-capable AWS CLI profile.** The permission set your users call
   Bedrock with (`bedrock-limited-access`) is *not* enough to deploy this
   stack — it only grants Bedrock actions. Deploying needs IAM, Lambda,
   DynamoDB, SNS, and EventBridge permissions (e.g. an admin/power-user
   permission set). Set it up with:
   ```bash
   aws sso login --sso-session my-sso-session
   aws configure sso   # pick an admin-capable permission set, not bedrock-limited-access
   export AWS_PROFILE=<the-profile-name-you-just-created>
   aws sts get-caller-identity   # sanity check: Account should be 396026123718
   ```

   source lives in `src/enforcer/` and `src/reset/`, not inline in the
   template, so `deploy.sh` needs somewhere to upload the zipped code to
   before the stack deploy runs — this bucket is just scratch space
   (CloudFormation only reads from it during deploy) and can't be created
   *by* the same template that needs it to already exist, so it's a
   one-time manual step, separate from the stack:
   ```bash
   aws s3api create-bucket \
     --bucket bedrock-budget-hardstop-396026123718 \
     --region us-west-2 \
     --create-bucket-configuration LocationConstraint=us-west-2
   ```
   `bedrock-budget-hardstop-396026123718` already exists in this
   account and is `deploy.sh`'s default — you only need this step if that
   bucket is ever deleted or you're deploying into a different account.

5. **(Optional) SES sending identity verified, if using per-user emails.**
   `SesSenderEmail` sends warning/block notifications directly to each
   user via Amazon SES. SES requires the *sending* identity (the address
   or domain in `SesSenderEmail`) to be verified, and by default new SES
   accounts are in the **sandbox**, which also requires every *recipient*
   address to be individually verified before SES will deliver to it —
   a non-starter for arbitrary per-user corporate email addresses. Before
   relying on this feature in production, request SES production access
   (AWS Console → SES → Account dashboard → "Request production access")
   for this account/region. Until that's granted, per-user emails to
   unverified recipients fail silently from the enforcer's perspective
   (caught, logged to CloudWatch, enforcement is unaffected) — check
   `/aws/lambda/bedrock-budget-hardstop-enforcer` logs for `Failed to
   send SES notification to ...` if users report not receiving expected
   emails. Leave `SesSenderEmail` as `""` to skip this entirely and rely
   on the existing admin SNS alert only.
   ```bash
   aws ses verify-email-identity --email-address <sender>@yourdomain.com --region us-west-2
   aws ses get-send-quota --region us-west-2   # sandbox: Max24HourSend is 200
   ```

## Parameters reference

All have working defaults baked into the template for this account — you
only need `--parameter-overrides` when you want to change one.

| Parameter | Default | Notes |
|---|---|---|
| `SSOInstanceArn` | `arn:aws:sso:::instance/ssoins-79072388697bbe8d` | IAM Identity Center instance ARN. |
| `PermissionSetArn` | `arn:aws:sso:::permissionSet/ssoins-79072388697bbe8d/ps-7907c9a4bea503c7` | The `bedrock-limited-access` permission set whose inline policy gets rewritten. |
| `BedrockLogGroupName` | `/aws/bedrock/invocations` | Must match what Bedrock is actually configured to log to. |
| `EvaluationRateMinutes` | `15` | How often the enforcer runs. Lower = faster blocking, more Logs Insights scan cost. |
| `AlertEmail` | `oscar.gutierrez@billups.com` | Set to `""` to skip the email subscription. |
| `ExemptUsernames` | `audrai_ai_agent` | Comma-separated usernames/session-names that are never blocked. See [Whitelisting](#whitelisting-a-user-exempting-them-from-the-cap). |
| `SesSenderEmail` | `""` | Verified SES sending identity used to email each user directly at 75%/100% of their personal cap. Leave `""` to disable per-user emails (the admin SNS alert on `AlertTopic` is unaffected either way). See [Prerequisites](#prerequisites) for SES sandbox mode. |

Model pricing is **not** a CloudFormation parameter — it's `model-pricing.json`
(repo root), uploaded by `deploy.sh` to the staging S3 bucket (`StagingBucketName`)
after every deploy. The enforcer reads it from S3 fresh on every run, so editing the file + re-running
`deploy.sh` updates pricing without a Lambda code change. See
[Model pricing table](#model-pricing-table). The per-user caps work the same
way: they're `budget-config.json`, not a parameter (the old `MonthlyCapUSD`
parameter was replaced by the config's `standard` tier) — see
[Budget tiers](#budget-tiers).

## Model pricing table

Prices live in `model-pricing.json` (repo root) — USD per **1,000 tokens**
(AWS's own pricing pages quote per **1,000,000** — divide by 1000 when
copying from there). The lookup key is the logged `modelId` with any
`arn:aws:bedrock:...:inference-profile/` prefix stripped — i.e. matched on
the substring after the last `/`, so a full inference-profile ARN and its
bare model/profile-id equivalent share one entry instead of needing a
duplicate. Still an exact-match lookup on that trailing segment (see
[Known limitations](#known-limitations)) — just no longer tied to a
specific account ID or region baked into an ARN. Each model entry has
`input`, `output`, `cacheRead`, `cacheWrite5m`, and `cacheWrite1h` rates.

Sourcing notes:

- Almost all the Anthropic prices are the **Geo and In-region Cross-region Inference**
  tier for `us-west-2` (Oeste de EE. UU./Oregón), confirmed directly against
  <https://aws.amazon.com/bedrock/pricing/> on 2026-09-17. This tier runs ~10% above
  the "Global Cross-region Inference" tier; using the Global price for a
  model actually invoked through Geo/In-region CRIS silently undercounts
  cost. **Exception:** Opus 4.6 (v1) is the only model actually observed
  being called through *both* tiers in this account's logs (`global.`-
  prefixed `modelId` shapes as well as the `us.`-prefixed ones), so its two
  `global.`-prefixed keys are intentionally priced at the Global tier
  instead — see its `global.`-prefixed entries in `model-pricing.json`.
- GPT-5.6 Luna's price came from its dedicated model-card page
  (`docs.aws.amazon.com/bedrock/latest/userguide/model-card-openai-gpt-56-luna.html`),
  since it isn't in the main pricing page's summary table. Its logged
  `modelId` (`openai.gpt-5.6-luna`) carries no region-group prefix, which
  matches the **In-Region**, short-context (≤272K input tokens) row —
  confirmed identical to the Geo CRIS row for this model and region on the
  Spanish pricing page ($0.22 / $1.32 per 1M).
- If a model shows up in the logs with a shape not listed above (e.g. a
  bare model ID for a model that's only ever been seen via ARN, or a brand
  new model), add it as a new key with the same price as its sibling
  shapes — see [Modifying and redeploying](#modifying-and-redeploying). If
  the new shape is a full inference-profile ARN, key it by just the
  substring after the last `/` (e.g. `us.anthropic.claude-...`), not the
  whole ARN — the lookup strips the ARN prefix before matching, so a
  full-ARN key would just be dead weight.

## Budget tiers

Caps live in `budget-config.json` (repo root), uploaded by `deploy.sh` to the
staging bucket next to `model-pricing.json` and read fresh by the enforcer
every run:

```json
{
  "defaultTier": "standard",
  "tiers": {
    "basic":    { "monthlyCapUsd": 70 },
    "standard": { "monthlyCapUsd": 150 },
    "power":    { "monthlyCapUsd": 300 }
  },
  "users": {
    "someone@billups.com": { "tier": "power" }
  }
}
```

- Anyone not listed under `users` is on `defaultTier`.
- Usernames are the session names that show up in the logs (usually the
  person's email), matched case-insensitively.
- Tiers are a map — add or rename one by editing the file; nothing in the
  code knows the tier names.

**The file is the permanent policy; DynamoDB only holds this month's
exceptions.** Each user's effective cap is recomputed every run as:

```
cap = tiers[user's tier].monthlyCapUsd + bonusUsd (from their DynamoDB item, default 0)
```

| To… | Do this | Lasts |
|---|---|---|
| Move someone to another tier | Edit `users` in `budget-config.json`, run `./deploy.sh` | Until the file changes. Takes effect on the next run, in both directions — moving a blocked user to a tier above their spend unblocks them. |
| Change a tier's cap | Edit `tiers` in `budget-config.json`, run `./deploy.sh` | Until the file changes. Affects everyone on that tier. |
| Give one person extra budget this month | Set `bonusUsd` on their DynamoDB item (see [Removing the block for one individual user](#removing-the-block-for-one-individual-user)) | Until the monthly reset. |

**Validation.** `deploy.sh` validates the file before uploading it, and the
enforcer validates it again on every load: unknown keys, duplicate keys, a
user listed twice (including differing only by case), an undefined tier, a
non-positive cap, or a username that's also in `ExemptUsernames` are all
errors. **An invalid or missing config stops the enforcer run entirely**
before anything is written — an SNS alert ("enforcement stopped, invalid
budget config") goes out and the Lambda errors (and is retried by
EventBridge, so expect repeat alerts until it's fixed). Current blocks stay in
place; nobody is newly blocked or unblocked until the file is fixed.

**Migrating from per-user `capUsd` overrides.** Before tiers, a hand-edited
`capUsd` on an item was a per-user override. The enforcer now ignores
`capUsd` (it's written for display only), so existing overrides have to be
converted to `bonusUsd` once, while the old enforcer is paused (it rewrites
whole items and would erase the new attribute):

```bash
aws events disable-rule --name bedrock-budget-hardstop-enforcer-schedule --region us-west-2
python3 scripts/migrate_cap_to_bonus.py            # dry run — review the output
python3 scripts/migrate_cap_to_bonus.py --apply
./deploy.sh
aws events enable-rule --name bedrock-budget-hardstop-enforcer-schedule --region us-west-2
```

Items whose `capUsd` equals the old default (`--old-default`, 150) were
never overrides and are skipped. Deploying right after a monthly reset makes
this a no-op, since the reset deletes every item.

## Teams

Teams are an optional extra limit on a group's **combined** spend, defined
in the same `budget-config.json`:

```json
"teams": {
  "data-science": {
    "monthlyCapUsd": 1500,
    "owner": "lead@billups.com",
    "members": ["ana@billups.com", "bob@billups.com"]
  }
}
```

- A team's spend is the sum of its members' month-to-date spend. When it
  reaches `monthlyCapUsd`, every member with usage this month is blocked.
- Members keep their own tier cap. A user is blocked if **either** their
  team is over budget **or** they're over their own cap (tier +
  `bonusUsd`). The team is checked first, which only decides the recorded
  `blockReason` (`team` / `user`) and which block email they get.
- A user can be in only one team. Exempt usernames can't be in a team. Both
  are validation errors (the run stops, same as any invalid config).
- `owner` is optional. The owner is emailed at 75% of the team budget and
  when the team is blocked. Being the owner doesn't make them a member;
  list them in `members` too if their spend should count.
- Each team has a ledger item in the same DynamoDB table, keyed
  `team#<name>` (`currentUsageUsd`, `capUsd`, `overBudget`, ...). The
  monthly reset clears it with everything else.

**When a team is blocked**

| Situation | Do this | Lasts |
|---|---|---|
| One member needs to keep working, and is still under their own cap | Set `teamBypass` on their item (below) | Until the monthly reset; they're back on the team on the 1st |
| One member needs to keep working, and is also over their own cap | Set `teamBypass` **and** a `bonusUsd` on their item | Until the monthly reset |
| The whole team needs more | Raise the team's `monthlyCapUsd` in `budget-config.json` and run `./deploy.sh` | Permanent (it's the config). Next run unblocks every member except anyone over their own cap |
| Someone should leave the team for good | Remove them from `members` in `budget-config.json` | Permanent |

```bash
aws dynamodb update-item \
  --table-name bedrock-budget-hardstop-blocked-users \
  --key '{"username": {"S": "<their-username-or-email>"}}' \
  --update-expression "SET teamBypass = :t" \
  --expression-attribute-values '{":t": {"BOOL": true}}' \
  --region us-west-2
```

A bypassed member's spend **stops counting toward the team from that
point on**. The first run that sees `teamBypass` freezes their team
contribution at their spend so far (`teamContributionUsd`), so a later team
budget increase isn't used up by them, and what they'd already spent stays
on the team (the team doesn't get unblocked just because someone was
bypassed). Removing `teamBypass` mid-month puts their full month's spend
back on the team.

## Deploying

The Lambda source lives in `src/enforcer/index.py` and `src/reset/index.py`,
not inline in the template — its `Code:` properties are local directory
paths that only `aws cloudformation package` can resolve into a real
`{S3Bucket, S3Key}` before a deploy runs. **Running `aws cloudformation
deploy` directly on `bedrock-budget-hardstop-sso.yaml` will fail** — always
go through `deploy.sh`, which wraps `validate-template` → `package` →
`deploy` in one step:

```bash
# 0) Confirm you're targeting the right account/profile
aws sts get-caller-identity

# 1) Package + deploy (creates or updates the stack — safe to re-run)
./deploy.sh

# 2) Confirm it's up
aws cloudformation describe-stacks \
  --stack-name bedrock-budget-hardstop \
  --region us-west-2 \
  --query "Stacks[0].[StackStatus,Outputs]"
```

`./deploy.sh` with no args uses the bootstrap staging bucket
(`bedrock-budget-hardstop-396026123718`) that already exists in this
account — see [Prerequisites](#prerequisites) #5. Pass a different bucket
name as the first argument only if that one is unavailable:
`./deploy.sh my-other-staging-bucket`. Pass CloudFormation parameter
overrides after `--`, with or without a custom bucket:
```bash
./deploy.sh -- ExemptUsernames="audrai_ai_agent"
./deploy.sh my-other-staging-bucket -- EvaluationRateMinutes=15
```

Then check the inbox for `AlertEmail` for AWS's subscription confirmation
message. The subscription uses the `email-json` protocol (not `email`) —
see the `AlertEmailSubscription` resource's comment in the template for
why — so this arrives as a raw JSON blob rather than a nicely formatted
"Confirm subscription" email: copy the `SubscribeURL` field's value out of
the JSON and open it in a browser. Until that's done, block/reset
notifications go nowhere. Ongoing alert emails will also show up as raw
JSON (the real content is in the `Message` field) rather than clean plain
text — that's the tradeoff for not getting silently unsubscribed by
corporate email link-scanners.

## Testing before you trust it

Don't assume it works — verify the enforcement path end to end before
relying on it:

1. **Dry run the enforcer** without waiting for the schedule:
   ```bash
   aws lambda invoke \
     --function-name bedrock-budget-hardstop-enforcer \
     --region us-west-2 \
     /tmp/out.json && cat /tmp/out.json
   ```
   With no real traffic yet, expect `"evaluated_users": 0` and no errors —
   that alone confirms the Logs Insights query and `sso:*` permissions work.

2. **Force a real block.** Give a test user a negative `bonusUsd` that
   brings their cap to almost zero (no redeploy needed, and it only affects
   that one user):
   ```bash
   aws dynamodb update-item \
     --table-name bedrock-budget-hardstop-blocked-users \
     --key '{"username": {"S": "<test-username>"}}' \
     --update-expression "SET bonusUsd = :b" \
     --expression-attribute-values '{":b": {"N": "-149.99"}}' \
     --region us-west-2
   ```
   Have the test user make one small Bedrock call, invoke the enforcer
   Lambda manually (step 1), then have that same user try again — it should
   fail with `AccessDeniedException`. Check `total_blocked` in the Lambda's
   response to confirm. (Adjust the bonus to `0.01 − <their tier's cap>` if
   they're not on a $150 tier.)

3. **Restore the real cap** by removing the bonus, then invoke the enforcer
   again — the test user should be unblocked (`newly_unblocked` in the
   response) and get the "access restored" email:
   ```bash
   aws dynamodb update-item \
     --table-name bedrock-budget-hardstop-blocked-users \
     --key '{"username": {"S": "<test-username>"}}' \
     --update-expression "REMOVE bonusUsd" \
     --region us-west-2
   ```

4. **Verify the modelId mapping** once there's real traffic:
   ```
   fields modelId | stats count() as invocations by modelId | sort invocations desc
   ```
   in CloudWatch Logs Insights on `/aws/bedrock/invocations`. Compare every
   string against the keys in `model-pricing.json`. The lookup is
   exact-match; a mismatch silently prices that model's usage at $0 and it
   will never trigger the cap, with no error anywhere except the "models
   missing a price entry" SNS alert.

## Modifying and redeploying

Edit `bedrock-budget-hardstop-sso.yaml`, then re-run `./deploy.sh` (with the
same bucket/overrides as before, if any) — `aws cloudformation deploy` diffs
against the live stack and only updates what changed. Common edits:

- **Change a cap or move a user between tiers:** edit `budget-config.json`
  and re-run `./deploy.sh` (see [Budget tiers](#budget-tiers)) — no
  CloudFormation change needed.
- **Add a new model:** add an entry to `model-pricing.json` and re-run
  `./deploy.sh` (uploads the updated file to S3 — no CloudFormation change
  needed). Get the price from <https://aws.amazon.com/bedrock/pricing/>
  (select the provider, pick region `us-west-2`, use the **Geo and
  In-region Cross-region Inference** tier for Anthropic models) and the
  exact `modelId` from a Logs Insights query as described above — never
  guess either one. If the logged shape is a full inference-profile ARN,
  key the entry by just the substring after the last `/` (see
  [Model pricing table](#model-pricing-table)), not the whole ARN. Divide
  the page's per-1M price by 1000 to get the per-1K value this file
  expects.
- **Change how often it checks:** edit `EvaluationRateMinutes`. Lower
  values catch overages faster but scan more data per run (see
  [Known limitations](#known-limitations) on cost).
- **Change/remove the alert email:** edit `AlertEmail`'s `Default` (empty
  string `""` disables the email subscription entirely).
- **Point at a different permission set, SSO instance, or log group:** edit
  `SSOInstanceArn` / `PermissionSetArn` / `BedrockLogGroupName` — only
  needed if this is redeployed against a different account or permission
  set (remember the delegated-administrator prerequisite applies to the new
  account too).

## Whitelisting a user (exempting them from the cap)

Some identities that share this SSO permission set aren't a human with a
monthly budget — for example `audrai_ai_agent`, a service account for an
application, which should never be blocked regardless of spend. That's what
`ExemptUsernames` is for.

1. Edit the `ExemptUsernames` parameter to a comma-separated list of every
   username/session-name to exempt, e.g.:
   ```yaml
   ExemptUsernames:
     Default: "audrai_ai_agent,some_other_service_account"
   ```
   or pass it on deploy without editing the file:
   ```bash
   ./deploy.sh -- ExemptUsernames="audrai_ai_agent,some_other_service_account"
   ```
2. Redeploy (either form above). This updates the Lambdas'
   `EXEMPT_USERNAMES` environment variable — no code change needed.
3. On its next scheduled run (or a manual `aws lambda invoke` of the
   enforcer), the exempt username is: never added to the blocklist going
   forward, **and** proactively removed from DynamoDB and the permission
   set's Deny statement if it was already blocked (this is the same
   self-healing check the enforcer runs every cycle, so it corrects itself
   automatically — no manual unblock step is needed for an exempt user).

Exempt usernames still show up in `evaluated_users`/cost calculations
internally (their spend is still computed from the logs), they're just
never allowed to trip the Deny. If you want to actually track/report an
exempt service account's spend separately, the DynamoDB table and Logs
Insights query results are still the source for that — exemption only
skips the block, not the accounting.

Exempt users also never receive the 75%/100% per-user SES emails, for the
same reason they're never blocked.

Exemptions deliberately stay a stack parameter rather than moving into
`budget-config.json`: they're for application/service accounts that sit
outside the budget system, they rarely change, and a mistake means unlimited
spend rather than a wrong cap — so they get the extra friction of a deploy.
**Don't exempt people**; give them a higher tier or a `bonusUsd` instead, so
they still have a ceiling. An exempt username that also appears under
`users` in `budget-config.json` is a validation error.

## Removing the block for one individual user

Deleting the DynamoDB row alone isn't durable if the user is still
genuinely over their cap — the enforcer recomputes cost from the logs every
`EvaluationRateMinutes` and re-blocks them next cycle. Options, in order of
how they're usually used:

1. **Stale/test block, they're actually under the cap** — delete the row,
   then re-invoke to confirm:
   ```bash
   aws dynamodb delete-item \
     --table-name bedrock-budget-hardstop-blocked-users \
     --key '{"username": {"S": "<their-username-or-email>"}}' \
     --region us-west-2

   aws lambda invoke --function-name bedrock-budget-hardstop-enforcer \
     --region us-west-2 /tmp/out.json && cat /tmp/out.json
   ```

2. **Give them extra budget for this month (not unlimited)** — set
   `bonusUsd` on their item. It's added on top of their tier's cap (e.g.
   `50` on a $150 tier = $200 this month), and creates the row if they
   don't have one yet:
   ```bash
   aws dynamodb update-item \
     --table-name bedrock-budget-hardstop-blocked-users \
     --key '{"username": {"S": "<their-username-or-email>"}}' \
     --update-expression "SET bonusUsd = :b" \
     --expression-attribute-values '{":b": {"N": "50"}}' \
     --region us-west-2

   aws lambda invoke --function-name bedrock-budget-hardstop-enforcer \
     --region us-west-2 /tmp/out.json
   ```
   `SET` replaces any existing bonus — to add to one, use
   `"SET bonusUsd = if_not_exists(bonusUsd, :z) + :b"` with `":z": {"N": "0"}`.
   It reverts automatically at the monthly reset. Don't edit `capUsd` — it's
   recomputed and overwritten every run.

3. **Give them unlimited access before month-end** — add to
   `ExemptUsernames` and redeploy (see
   [Whitelisting](#whitelisting-a-user-exempting-them-from-the-cap)).

4. **Wait for the monthly reset** — 00:05 UTC on the 1st.

5. **Move them to a higher tier** — permanent; edit `budget-config.json`
   and run `./deploy.sh` (see [Budget tiers](#budget-tiers)).

If their item says `blockReason: team`, raising their own cap won't help —
their team is over budget. See [Teams](#teams) for `teamBypass`.

## Monitoring

- **SNS (`AlertTopic`)** — one email when new users get blocked (with the
  cost that tripped it), one on the monthly reset, and one if any `modelId`
  shows up in the logs with no matching price entry (meaning its cost isn't
  being counted at all — treat this as a "fix `model-pricing.json` now"
  alert), one when a team reaches its budget, and one if `budget-config.json` is missing or invalid (meaning
  enforcement has stopped — fix the file and redeploy). Note: exempt-user auto-unblocks (see
  [Whitelisting](#whitelisting-a-user-exempting-them-from-the-cap)) are
  silent — check the DynamoDB table or CloudWatch Logs if you need to
  confirm one happened, no email is sent for it.
- **Per-user SES emails** (if `SesSenderEmail` is set) — sent directly to
  the affected user (not the admin) at the 75% warning threshold, at the
  moment they're newly blocked, and when a cap increase (tier move or
  `bonusUsd`, team budget raise, `teamBypass`) unblocks them — sent only
  after the Deny is actually removed. Team owners get a 75% warning and a
  "team blocked" email for their team.
  The warning is sent once per cap: if the cap changes, it can fire again
  against the new cap (tracked via `warnedAt`/`warnedAtCapUsd`). These are separate
  from, and in addition to, the batched admin SNS alert above. Exempt
  usernames (and any non-email service-account username) never receive
  these, since they fail the email-format check / are skipped by the same
  exemption logic that skips blocking them.
- **CloudWatch Logs** for the Lambdas themselves:
  `/aws/lambda/bedrock-budget-hardstop-enforcer` and
  `/aws/lambda/bedrock-budget-hardstop-reset` — check here first for any
  runtime error (`sso:*` permission issues, Logs Insights query failures,
  provisioning timeouts, etc.).
- **DynamoDB table `bedrock-budget-hardstop-blocked-users`** — live
  per-user usage ledger, refreshed every `EvaluationRateMinutes`, not just
  who's blocked. No item for a user means $0 usage this month. Schema:

  | Attribute | Meaning |
  |---|---|
  | `username` | Partition key. |
  | `currentUsageUsd` | Month-to-date cost as of `lastUpdated`. |
  | `tier` / `tierCapUsd` | Tier resolved from `budget-config.json` on the last run, and that tier's cap. |
  | `bonusUsd` | Optional, admin-set. Added to the tier cap until the monthly reset (negative lowers it). One of the two attributes meant to be hand-edited — see [Removing the block for one individual user](#removing-the-block-for-one-individual-user). |
  | `teamBypass` | Optional, admin-set (`true`). Exempts this user from their team's cap until the monthly reset — see [Teams](#teams). |
  | `team` | Team from `budget-config.json` on the last run, if any. |
  | `teamContributionUsd` | Set when `teamBypass` is first seen: the spend that stays counted toward the team. |
  | `blockReason` | `team` or `user`, while blocked. |
  | `capUsd` | Effective cap on the last run (`tierCapUsd + bonusUsd`). Display only — recomputed every run, editing it does nothing. |
  | `lastUpdated` | ISO timestamp of the last run that saw usage for this user. |
  | `exempt` | Mirrors `ExemptUsernames` membership. |
  | `blocked` | Currently blocked. |
  | `blockedAt` / `costAtBlock` | Set once, when first blocked; not overwritten on later runs. |
  | `warnedAt` / `warnedAtCapUsd` | When the 75%-threshold warning was sent, and the cap it was sent against. Cleared if the cap changes and usage is below 75% of the new one, so the warning can fire again. |

  Items keyed `team#<name>` are team ledgers, not users (see [Teams](#teams)):
  `currentUsageUsd` is the team's counted spend, `capUsd` the team cap,
  `overBudget` whether its members are blocked.

  Scan sorted by spend, highest first (piped through `python3` since
  DynamoDB's raw JSON keeps numbers as strings, so a JMESPath `sort_by`
  would sort them lexically, not numerically):
  ```bash
  aws dynamodb scan \
    --table-name bedrock-budget-hardstop-blocked-users \
    --region us-west-2 \
    --projection-expression "username, currentUsageUsd, capUsd, tier, blocked, exempt" \
    --output json \
  | python3 -c '
import json, sys
items = json.load(sys.stdin)["Items"]
rows = [{k: list(v.values())[0] for k, v in i.items()} for i in items]
rows.sort(key=lambda r: float(r["currentUsageUsd"]), reverse=True)
for r in rows:
    usage, cap, user = r["currentUsageUsd"], r["capUsd"], r["username"]
    blocked, exempt = r.get("blocked", False), r.get("exempt", False)
    tier = r.get("tier", "-")
    print(f"{usage:>8} / {cap:<6} {tier:<9} blocked={blocked!s:<5} exempt={exempt!s:<5} {user}")
'
  ```
- **Permission set's actual inline policy**, as the ground truth for what's
  really enforced right now:
  ```bash
  aws sso-admin get-inline-policy-for-permission-set \
    --instance-arn arn:aws:sso:::instance/ssoins-79072388697bbe8d \
    --permission-set-arn arn:aws:sso:::permissionSet/ssoins-79072388697bbe8d/ps-7907c9a4bea503c7 \
    --region us-west-2
  ```
  Look for a statement with `"Sid": "BedrockBudgetHardStopPerUser"` and
  check its `Condition.StringLike.aws:userid` list.

## Ad-hoc usage report

The enforcer only ever reports month-to-date totals. For a one-off question
like "what did a user actually cost on a specific day" (e.g. reconciling
against a billing SKU doIT flagged), use `scripts/usage_report.py` instead
of waiting on/trusting the running totals:

```bash
python3 scripts/usage_report.py 2026-09-29
python3 scripts/usage_report.py 2026-09-29 --user jdoe
```

Same Logs Insights query shape and pricing logic as the enforcer, scoped to
one UTC day, read-only. Useful for validating `model-pricing.json` changes
(e.g. the cache-write TTL assumption) against real billed amounts.

## Known limitations

- **Not instantaneous.** Enforcement runs on a schedule (every
  `EvaluationRateMinutes`) against CloudWatch Logs, which itself has a
  small ingestion delay, plus `ProvisionPermissionSet` is asynchronous on
  top of that. A user can overshoot the cap by a small amount before the
  Deny actually lands. Lower `EvaluationRateMinutes` to shrink this window;
  it can't be reduced to zero with this architecture.
- **Exact-match pricing.** The enforcer strips any
  `arn:aws:bedrock:...:inference-profile/` prefix off the logged `modelId`
  (matching on the substring after the last `/`) before looking it up, so
  a full inference-profile ARN and its bare model/profile-id equivalent
  share one `model-pricing.json` entry, and pricing no longer depends on
  the account ID/region baked into that ARN. It's still an exact-match
  lookup on that trailing segment, though — any other mismatch (a renamed
  model, an unexpected cross-region-inference prefix) fails silently
  (that model's usage is priced at $0, never counted, never blocked) — the
  only guardrail is the "models missing a price entry" SNS alert, so don't
  ignore it.
- **Cache-write TTL ambiguity.** The invocation log's
  `cacheWriteInputTokenCount` doesn't distinguish a 5-minute from a 1-hour
  cache write, so the enforcer prices all of it at the 5-minute rate (the
  API default). Any 1-hour-TTL usage is undercounted by the gap between the
  two rates — see [Model pricing table](#model-pricing-table).
- **Doesn't cover every Bedrock billing path.** This only prices
  `bedrock:InvokeModel`/`InvokeModelWithResponseStream`/`Converse`/
  `ConverseStream` calls seen in invocation logging. Confirmed out of scope
  for this account: `bedrock-mantle` (confirmed not in use, but worth
  re-checking periodically via CloudTrail if that ever changes), batch
  inference jobs (`CreateModelInvocationJob`, billed at a 50% discount
  through a different mechanism), and Provisioned Throughput (flat hourly
  cost, unrelated to token counts). If any of those come into use, they
  need separate cost controls.
- **The Deny statement lives inside the permission set's single inline
  policy slot**, shared with whatever other inline statements that slot
  already holds. `apply_blocklist()`/the reset Lambda only ever touch the
  statement whose `Sid` is `BedrockBudgetHardStopPerUser`, but if someone
  else's tooling also manages that same inline policy slot outside of this
  stack, the two can clobber each other. Prefer a managed/customer-managed
  policy attachment for anything else that needs to modify this permission
  set's grants, leaving the inline slot exclusively to this stack.
- **Org-boundary dependency.** All enforcement depends on this account
  remaining a delegated administrator for IAM Identity Center (or being the
  management account). If that registration is ever removed, every `sso:*`
  call starts failing with `AccessDeniedException` and enforcement silently
  stops (existing Deny statements stay in place, but new blocks/unblocks/
  resets can't happen) until someone notices via the Lambda error logs.
- **CloudFormation doesn't know about the Deny statement.** See
  [Tearing it down](#tearing-it-down).
- **Only enforces on the shared permission set.** The Deny statement is
  written into the `bedrock-limited-access` permission set, so it only
  affects sessions that assume that role. A standalone IAM user/role with
  its own Bedrock grant is invisible to enforcement — their usage still gets
  tracked (via the `:user/` ARN fallback in `extract_username`) and they can
  still be marked `blocked` in DynamoDB, but that block has no real effect,
  since neither the policy attachment nor the `aws:userid` condition
  (`<role-id>:<session-name>`, which only exists for assumed-role sessions)
  reaches them. If anyone has Bedrock access outside this permission set,
  this system can't cap them.
- **Per-user emails are best-effort.** A SES send failure (sandbox
  restriction, unverified recipient, throttling) is caught and logged, never
  blocks DynamoDB writes or the permission-set Deny rewrite, but also means
  a user is not guaranteed to actually receive any of the emails — treat the
  admin SNS alert and the DynamoDB table as the authoritative record of
  who's blocked, not the user's inbox.

- **Team members with no usage yet this month aren't blocked in advance.**
  Only users who appear in this month's logs are evaluated, so when a team
  goes over budget, a member who hasn't called Bedrock yet this month can
  still make calls until the next run blocks them — at most one evaluation
  interval of usage.
- **Team overshoot is larger than per-user overshoot.** Several members
  can keep spending during the same evaluation interval before the block
  lands, so a team can end up noticeably over its cap. Lower
  `EvaluationRateMinutes` if that matters.
- **Moving a user between teams mid-month moves their whole month's spend
  with them** (team spend is the sum of current members' spend). Make team
  moves on the 1st when possible.
- **Between 00:00 and the 00:05 UTC reset on the 1st**, the enforcer
  already sees the new month's (near-zero) usage, but last month's
  `bonusUsd`/`teamBypass`/`teamContributionUsd` are still in the table until
  the reset deletes them. This can briefly keep a team blocked or a bonus
  applied for those few minutes; the reset corrects it.
- **The Deny statement grows with every blocked person.** Each blocked user
  is one `*:<username>` entry in the permission set's inline policy, and a
  team block adds all its active members at once. The inline policy has a
  size limit; at today's scale this is far off, but a very large team (or
  org) would eventually need a different mechanism (e.g. Identity Center
  session tags with one condition per team).

## Troubleshooting

**`aws sts get-caller-identity` → `NoCredentials`**
`aws sso login` only caches an SSO token; it doesn't select a profile. Run
`aws configure sso` to create a named profile (pick an admin-capable
permission set, not `bedrock-limited-access`), then `export
AWS_PROFILE=<name>` or add `--profile <name>` to every command.

**`aws cloudformation deploy` says "No changes to deploy" after editing a
parameter's `Default` in the file**
`aws cloudformation deploy` uses `UsePreviousValue=true` for any parameter
not explicitly passed via `--parameter-overrides` on an update to an
existing stack — it does **not** pick up a changed `Default` from the
template file. Always pass the changed parameter explicitly:
`./deploy.sh -- EvaluationRateMinutes=<value>`.

**Enforcer errors with "Could not load budget config"**
`budget-config.json` is missing from the staging bucket or failed
validation — the error message names the exact problem. Fix the file and
run `./deploy.sh` (which validates it locally first). Until then no one is
blocked or unblocked.

**A user isn't getting blocked despite being over cap**
Check the enforcer's CloudWatch Logs for the run in question, and look at
its return value's `unpriced_models` field — if their `modelId` isn't in
`model-pricing.json` (or shows up with an unexpected prefix/ARN shape), their
usage is being priced at $0 and never trips the cap.

**Need to manually unblock someone before the monthly reset**
See [Removing the block for one individual user](#removing-the-block-for-one-individual-user)
— a DynamoDB delete alone only sticks if they're genuinely back under the
cap; otherwise use `ExemptUsernames`.

## Tearing it down

```bash
aws cloudformation delete-stack \
  --stack-name bedrock-budget-hardstop \
  --region us-west-2
```

This removes the Lambdas, their IAM roles, the DynamoDB table, SNS topic,
and EventBridge rules — but **not** the Deny statement inside the
permission set's inline policy, because CloudFormation never created that
statement (the enforcer Lambda manages it directly via the `sso-admin` API,
outside of CloudFormation's knowledge). If anyone was blocked when you
delete the stack, they stay blocked forever unless you remove it by hand:

```bash
# 1) Read the current inline policy and remove the
#    "BedrockBudgetHardStopPerUser" statement from its Statement array
#    (or delete the inline policy entirely if that's the only statement)
aws sso-admin get-inline-policy-for-permission-set \
  --instance-arn arn:aws:sso:::instance/ssoins-79072388697bbe8d \
  --permission-set-arn arn:aws:sso:::permissionSet/ssoins-79072388697bbe8d/ps-7907c9a4bea503c7 \
  --region us-west-2

# 2a) If other statements remain, write them back without ours:
aws sso-admin put-inline-policy-to-permission-set \
  --instance-arn arn:aws:sso:::instance/ssoins-79072388697bbe8d \
  --permission-set-arn arn:aws:sso:::permissionSet/ssoins-79072388697bbe8d/ps-7907c9a4bea503c7 \
  --inline-policy '<the remaining JSON, with our Sid removed>' \
  --region us-west-2

# 2b) If ours was the only statement, delete the inline policy instead:
aws sso-admin delete-inline-policy-from-permission-set \
  --instance-arn arn:aws:sso:::instance/ssoins-79072388697bbe8d \
  --permission-set-arn arn:aws:sso:::permissionSet/ssoins-79072388697bbe8d/ps-7907c9a4bea503c7 \
  --region us-west-2

# 3) Push the change down into the real role
aws sso-admin provision-permission-set \
  --instance-arn arn:aws:sso:::instance/ssoins-79072388697bbe8d \
  --permission-set-arn arn:aws:sso:::permissionSet/ssoins-79072388697bbe8d/ps-7907c9a4bea503c7 \
  --target-type ALL_PROVISIONED_ACCOUNTS \
  --region us-west-2

# 4) Confirm nothing's left on the real role
aws iam list-role-policies \
  --role-name AWSReservedSSO_bedrock-limited-access_e88d47efec5f6dba \
  --region us-west-2
```

Run this check any time you tear the stack down, even if you don't remember
anyone being blocked recently. `list-role-policies` should return an empty
`PolicyNames` array once step 3 finishes provisioning.
