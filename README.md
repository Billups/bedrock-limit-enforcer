# Bedrock Per-User Budget Hard Stop (Shared SSO Permission Set)

Caps Amazon Bedrock spend at **$150/user/month** and actually blocks access
when a user crosses that cap — not just an email alert. Built for the case
where every Bedrock user in the account assumes the **same** IAM Identity
Center (SSO) permission set, so there's no per-person IAM identity to hang
a budget on.

Stack name used in this doc: `bedrock-budget-hardstop`. Template file:
`bedrock-budget-hardstop-sso.yaml`. Account: `396026123718`, region
`us-west-2`.

## Repo layout

```
bedrock-budget-hardstop-sso.yaml   Infra only: DynamoDB, SNS, IAM roles,
                                    EventBridge rules, and the two Lambda
                                    *resource* definitions (runtime,
                                    handler, env vars, schedule). No Python
                                    lives in this file.
deploy.sh                          Wraps `aws cloudformation package` +
                                    `aws cloudformation deploy` into one
                                    command. Optional but recommended.
src/
  enforcer/index.py                 Enforcer Lambda's actual code.
  reset/index.py                    Reset Lambda's actual code.
```

The template's `AWS::Lambda::Function` resources point `Code:` at
`src/enforcer/` and `src/reset/` as **local directory paths**, not inline
code. `aws cloudformation package` (or `deploy.sh`, which calls it for you)
zips each directory, uploads it to an S3 staging bucket, and rewrites those
paths into real `{S3Bucket, S3Key}` values before the stack deploys. This
means the template can no longer be deployed directly with
`aws cloudformation deploy` — always package first. See
[Deploying](#deploying).

This wasn't always the layout: earlier versions of this stack had both
Lambdas' Python source inline as `ZipFile:` block scalars inside the YAML
itself. That worked, but had no linting/type-checking, no realistic way to
unit-test the handler functions, and noisy diffs on every code change.
Moving the code into real `.py` files fixed all of that at the cost of one
extra `package` step before every deploy.

## Table of contents

- [Why this exists](#why-this-exists)
- [How it works](#how-it-works)
- [What gets deployed](#what-gets-deployed)
- [Prerequisites](#prerequisites)
- [Parameters reference](#parameters-reference)
- [Model pricing table](#model-pricing-table)
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
IAM role.** An earlier version of this stack tried to attach a Deny policy
directly to the underlying role (`AWSReservedSSO_bedrock-limited-access_...`)
via `iam:PutRolePolicy`. That's impossible — AWS returns
`UnmodifiableEntityException: this role is only modifiable by AWS` for any
`AWSReservedSSO_*` role, regardless of what IAM permissions the caller has;
those roles are exclusively owned by IAM Identity Center. The fix was to
manage the **Permission Set** instead, through the `sso-admin` API
(IAM action prefix `sso:`, confusingly — not `sso-admin:`), and let Identity
Center push the change down into the real role:

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
   `modelId`, summing input/output token counts.
2. **Attribute.** Extract the username from each `identity.arn`'s
   `RoleSessionName` (the part after `assumed-role/<role>/`).
3. **Price.** Convert each user's token totals to USD using a per-model
   price table (`ModelPricingJson`), summed across all models they used
   this month.
4. **Exempt.** Skip anyone in `ExemptUsernames` entirely (see
   [Whitelisting](#whitelisting-a-user-exempting-them-from-the-cap)), and
   proactively unblock them if they're already blocked.
5. **Enforce.** Any non-exempt user at or over the monthly cap gets recorded
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
   list and removes the Deny statement, so last month's block doesn't carry
   over.

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
| `BlockedUsersTable` (DynamoDB) | Source of truth for who's currently blocked this month. |
| `AlertTopic` (SNS) + email subscription | Notifies on new blocks, exempt-user unblocks, monthly reset, and models missing a price entry. |
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
   - Log class: Standard.

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

5. **An S3 bucket to stage packaged Lambda code.** Since the Lambda source
   moved out of the template (see [Repo layout](#repo-layout)),
   `aws cloudformation package` needs somewhere in S3 to upload the zipped
   `src/enforcer/` and `src/reset/` directories to before every deploy. Any
   bucket in this account/region you can write to works — it's just a
   staging area CloudFormation reads from during deploy, not a permanent
   resource this stack depends on afterward:
   ```bash
   aws s3 mb s3://<your-staging-bucket-name> --region us-west-2
   ```
   `bedrock-budget-hardstop-cfn-staging` is used as the example bucket name
   throughout this doc — substitute your own.

## Parameters reference

All have working defaults baked into the template for this account — you
only need `--parameter-overrides` when you want to change one.

| Parameter | Default | Notes |
|---|---|---|
| `SSOInstanceArn` | `arn:aws:sso:::instance/ssoins-79072388697bbe8d` | IAM Identity Center instance ARN. |
| `PermissionSetArn` | `arn:aws:sso:::permissionSet/ssoins-79072388697bbe8d/ps-7907c9a4bea503c7` | The `bedrock-limited-access` permission set whose inline policy gets rewritten. |
| `BedrockLogGroupName` | `/aws/bedrock/invocations` | Must match what Bedrock is actually configured to log to. |
| `MonthlyCapUSD` | `150` | Cap per user, per calendar month. |
| `EvaluationRateMinutes` | `15` | How often the enforcer runs. Lower = faster blocking, more Logs Insights scan cost. |
| `ModelPricingJson` | 29 keys covering 13 models, `us-west-2`, mostly Geo/In-region Cross-region Inference tier with one confirmed Global-tier exception (see table below) | **Must** use the exact `modelId` string as it appears in the logs — see [Known limitations](#known-limitations). |
| `AlertEmail` | `oscar.gutierrez@billups.com` | Set to `""` to skip the email subscription. |
| `ExemptUsernames` | `audrai_ai_agent` | Comma-separated usernames/session-names that are never blocked. See [Whitelisting](#whitelisting-a-user-exempting-them-from-the-cap). |

## Model pricing table

`ModelPricingJson` prices are USD per **1,000 tokens** (note: AWS's own
pricing pages quote per **1,000,000** tokens — divide by 1000 when copying
from there). Bedrock logs the same model under up to three different
`modelId` shapes depending on the call path (bare model ID, full
inference-profile ARN, or the short `us.`-prefixed form), and the price
lookup is exact-match — so every shape actually seen in this account's logs
is included as its own key, all priced identically per model:

| Model | Input (per 1K) | Output (per 1K) | Logged `modelId` shapes present |
|---|---|---|---|
| Claude Opus 5 | $0.0055 | $0.0275 | bare, ARN |
| Claude Sonnet 5 | $0.0022 | $0.011 | bare, ARN |
| Claude Opus 4.8 | $0.0055 | $0.0275 | bare, ARN |
| Claude Opus 4.7 | $0.0055 | $0.0275 | bare, ARN |
| Claude Opus 4.6 (v1), Geo/In-region CRIS | $0.0055 | $0.0275 | bare, `us.` ARN |
| Claude Opus 4.6 (v1), Global CRIS | $0.005 | $0.025 | bare `global.` short, `global.` ARN — see note below |
| Claude Sonnet 4.6 | $0.0033 | $0.0165 | bare, ARN, `us.` short |
| Claude Sonnet 4.5 (`20250929-v1:0`) | $0.0033 | $0.0165 | bare, ARN, `us.` short |
| Claude Haiku 4.5 (`20251001-v1:0`) | $0.0011 | $0.0055 | bare, ARN |
| Claude Opus 4.5 (`20251101-v1:0`) | $0.0055 | $0.0275 | bare, ARN |
| Claude Sonnet 4 (`20250514-v1:0`) | $0.003 | $0.015 | bare only |
| Claude Opus 4.1 (`20250805-v1:0`) | $0.015 | $0.075 | bare, ARN |
| Claude Fable 5.1 | $0.011 | $0.055 | bare, ARN, `us.` short |
| GPT-5.6 Luna (OpenAI) | $0.00022 | $0.00132 | bare only |

Sourcing notes:

- All Anthropic prices are the **Geo and In-region Cross-region Inference**
  tier for `us-west-2` (Oeste de EE. UU./Oregón), confirmed directly against
  <https://aws.amazon.com/bedrock/pricing/> (English) and
  <https://aws.amazon.com/es/bedrock/pricing/> (Spanish — same underlying
  catalog, numbers match exactly) on 2026-09-17. This tier runs ~10% above
  the "Global Cross-region Inference" tier; using the Global price for a
  model actually invoked through Geo/In-region CRIS silently undercounts
  cost.
- Claude Fable 5.1 and Claude Sonnet 4.5 are priced the same as their
  respective base rows (`Claude Fable 5` = $11.00/$55.00 per 1M, `Claude
  Sonnet 4.5` = $3.30/$16.50 per 1M) — the AWS pricing tables don't list a
  `5.1` variant separately, and minor version bumps within the same family
  aren't priced differently on any observed row.
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
  shapes — see [Modifying and redeploying](#modifying-and-redeploying).
- **Don't assume every call goes through the same CRIS tier.** On
  2026-09-24 the "models missing a price entry" alert caught
  `arn:aws:bedrock:us-west-2:396026123718:inference-profile/global.anthropic.claude-opus-4-6-v1`
  — a `global.`-prefixed ARN, meaning that specific call was routed through
  the cheaper **Global Cross-region Inference** profile instead of
  Geo/In-region, for a model this account had so far only ever seen via the
  `us.`-prefixed (Geo/In-region) path. Global and Geo/In-region are priced
  differently, so this needed its own key at its own (lower) price rather
  than reusing the existing Opus 4.6 entry. It's worth periodically
  checking Logs Insights for any `global.`-prefixed `modelId` across
  *every* model, not just the ones that have already shown up that way:
  ```
  fields modelId | filter modelId like /global\./ | stats count() by modelId
  ```

## Deploying

Since the Lambda source lives in `src/enforcer/` and `src/reset/` (see
[Repo layout](#repo-layout)) rather than inline in the template, deploying
is a **two-step process**: package (zip + upload to S3, rewrite `Code:` to
point at the upload), then deploy. `deploy.sh` wraps both:

```bash
# 0) Confirm you're targeting the right account/profile
aws sts get-caller-identity

# 1) Package + deploy in one step
./deploy.sh bedrock-budget-hardstop-cfn-staging

# 2) Confirm it's up
aws cloudformation describe-stacks \
  --stack-name bedrock-budget-hardstop \
  --region us-west-2 \
  --query "Stacks[0].[StackStatus,Outputs]"
```

Or run the two steps by hand, if you'd rather not use the script:

```bash
# 0) Confirm you're targeting the right account/profile
aws sts get-caller-identity

# 1) Validate the template
aws cloudformation validate-template \
  --template-body file://bedrock-budget-hardstop-sso.yaml \
  --region us-west-2

# 2) Package: zips src/enforcer/ and src/reset/, uploads to S3, and writes
#    a new packaged.yaml with Code: rewritten to real {S3Bucket, S3Key}
#    values. Re-run this every time you change a .py file OR the template.
aws cloudformation package \
  --template-file bedrock-budget-hardstop-sso.yaml \
  --s3-bucket bedrock-budget-hardstop-cfn-staging \
  --output-template-file packaged.yaml \
  --region us-west-2

# 3) Deploy the packaged template (creates or updates the stack — safe to
#    re-run). Note: deploy against packaged.yaml, not the original file —
#    the original still has local paths in Code: and will fail.
aws cloudformation deploy \
  --template-file packaged.yaml \
  --stack-name bedrock-budget-hardstop \
  --capabilities CAPABILITY_IAM \
  --region us-west-2

# 4) Confirm it's up
aws cloudformation describe-stacks \
  --stack-name bedrock-budget-hardstop \
  --region us-west-2 \
  --query "Stacks[0].[StackStatus,Outputs]"
```

Then check the inbox for `AlertEmail` and click **Confirm subscription** on
the SNS email AWS sends — until that's confirmed, block/reset notifications
go nowhere.

`packaged.yaml` is a build artifact (like a compiled binary) — it's
regenerated by every `package` run and shouldn't be hand-edited or treated
as the source of truth. Always edit `bedrock-budget-hardstop-sso.yaml` (and
the files under `src/`), never `packaged.yaml` directly.

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

2. **Force a real block.** Temporarily redeploy with a near-zero cap
   (always pass it explicitly — `aws cloudformation deploy` keeps the
   *previous* value for any parameter you don't pass, even if you changed
   the template's `Default`):
   ```bash
   ./deploy.sh bedrock-budget-hardstop-cfn-staging -- MonthlyCapUSD=1
   ```
   or, without the script:
   ```bash
   aws cloudformation package \
     --template-file bedrock-budget-hardstop-sso.yaml \
     --s3-bucket bedrock-budget-hardstop-cfn-staging \
     --output-template-file packaged.yaml \
     --region us-west-2
   aws cloudformation deploy \
     --template-file packaged.yaml \
     --stack-name bedrock-budget-hardstop \
     --capabilities CAPABILITY_IAM \
     --region us-west-2 \
     --parameter-overrides MonthlyCapUSD=1
   ```
   Have a test user make one small Bedrock call, invoke the enforcer Lambda
   manually (step 1), then have that same user try again — it should fail
   with `AccessDeniedException`. Check `total_blocked` in the Lambda's
   response to confirm.

3. **Restore the real cap:**
   ```bash
   ./deploy.sh bedrock-budget-hardstop-cfn-staging -- MonthlyCapUSD=150
   ```
   Note: this does **not** automatically unblock the test user — they stay
   blocked until the monthly reset runs, or until you remove them (see
   [Removing the block for one individual user](#removing-the-block-for-one-individual-user)).

4. **Verify the modelId mapping** once there's real traffic:
   ```
   fields modelId | stats count() as invocations by modelId | sort invocations desc
   ```
   in CloudWatch Logs Insights on `/aws/bedrock/invocations`. Compare every
   string against the keys in `ModelPricingJson`. The lookup is exact-match;
   a mismatch silently prices that model's usage at $0 and it will never
   trigger the cap, with no error anywhere except the "models missing a
   price entry" SNS alert.

## Modifying and redeploying

Two kinds of edits now, depending on what changed:

- **Template/parameter changes** (anything in `bedrock-budget-hardstop-sso.yaml`
  outside the Lambda `Code:` properties): edit the file, then re-run
  `./deploy.sh <staging-bucket>` (or the manual `package` + `deploy` pair).
- **Lambda logic changes** (anything in `src/enforcer/index.py` or
  `src/reset/index.py`): edit the `.py` file directly — real Python, so
  your editor's linting/syntax checking works normally — then run the same
  `./deploy.sh <staging-bucket>`. `package` re-zips and re-uploads whichever
  directory changed; `deploy` only updates the Lambda(s) whose code
  actually differs.

In both cases, `aws cloudformation deploy` diffs against the live stack
and only updates what changed. Common edits:

- **Change the cap:** edit `MonthlyCapUSD`'s `Default`, or pass
  `./deploy.sh <bucket> -- MonthlyCapUSD=<value>` without editing the file
  (remember: pass it explicitly, editing the `Default` alone isn't picked
  up for an existing stack).
- **Add a new model:** add an entry to the `ModelPricingJson` default in
  the template (or override it wholesale via `--parameter-overrides`). Get
  the price from <https://aws.amazon.com/bedrock/pricing/> (select the
  provider, pick region `us-west-2`) and the exact `modelId` from a Logs
  Insights query as described above — never guess either one. Check
  **which CRIS tier** the call actually used (the `us.`/`global.` prefix in
  the ARN) before picking a price — see the Opus 4.6 sourcing note above;
  don't assume every model uses the same tier. Divide the page's per-1M
  price by 1000 to get the per-1K value this template expects.
- **Change enforcement logic:** edit `src/enforcer/index.py` (e.g.
  `apply_blocklist()`, `extract_username()`) or `src/reset/index.py`
  directly, then redeploy as above. Consider adding a quick local sanity
  check before deploying, e.g. `python3 -m py_compile src/enforcer/index.py
  src/reset/index.py`, or a small pytest file that imports the module with
  mocked env vars/boto3 clients if this grows further.
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
$150/month budget — for example `audrai_ai_agent`, a service account for an
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
   ./deploy.sh bedrock-budget-hardstop-cfn-staging -- \
     ExemptUsernames="audrai_ai_agent,some_other_service_account"
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

## Removing the block for one individual user

There's an important distinction here: **deleting the DynamoDB entry alone
is not durable** if the user is still genuinely over the monthly cap. The
enforcer recomputes cost from the logs every `EvaluationRateMinutes` and
will re-block them the very next cycle if their month-to-date spend is
still ≥ `MonthlyCapUSD`. Manually deleting the row only helps for a user who
was blocked based on stale/incorrect data (e.g. a test run, or a pricing
bug that's since been fixed) and is genuinely under the cap once
recalculated.

Your real options, in order of how they're usually used:

1. **They're actually under the cap now** (a pricing bug was fixed, or this
   was a test block) — delete the DynamoDB row, and the self-healing check
   removes the Deny statement on the next run (or force it immediately):
   ```bash
   aws dynamodb delete-item \
     --table-name bedrock-budget-hardstop-blocked-users \
     --key '{"username": {"S": "<their-username-or-email>"}}' \
     --region us-west-2

   aws lambda invoke \
     --function-name bedrock-budget-hardstop-enforcer \
     --region us-west-2 \
     /tmp/out.json && cat /tmp/out.json
   ```
   Check the response's `total_blocked` list no longer includes them.

2. **They're genuinely over budget but need access restored anyway before
   month-end** — add them to `ExemptUsernames` and redeploy (see
   [Whitelisting](#whitelisting-a-user-exempting-them-from-the-cap)). This
   is a policy decision (you're choosing to let them exceed the cap), so
   treat it deliberately — e.g. remove them from `ExemptUsernames` again at
   the start of the next month once you've decided how to handle it going
   forward.

3. **Wait for the monthly reset** — happens automatically at 00:05 UTC on
   the 1st of the month; no action needed.

4. **Raise `MonthlyCapUSD`** — a global change (affects every user, not
   just this one), only appropriate if the $150 cap itself needs revisiting.

There is no per-user cap override in this template — options 2 and 4 are
the only ways to change enforcement for less than "everyone" or "wait for
reset."

## Monitoring

- **SNS (`AlertTopic`)** — one email when new users get blocked (with the
  cost that tripped it), one when an exempt user is proactively unblocked,
  one on the monthly reset, and one if any `modelId` shows up in the logs
  with no matching price entry (meaning its cost isn't being counted at
  all — treat this as a "fix `ModelPricingJson` now" alert).
- **CloudWatch Logs** for the Lambdas themselves:
  `/aws/lambda/bedrock-budget-hardstop-enforcer` and
  `/aws/lambda/bedrock-budget-hardstop-reset` — check here first for any
  runtime error (`sso:*` permission issues, Logs Insights query failures,
  provisioning timeouts, etc.).
- **DynamoDB table `bedrock-budget-hardstop-blocked-users`** — the live
  list of who's blocked this month and what they were spending when it
  happened (`costAtBlock`).
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

## Known limitations

- **Not instantaneous.** Enforcement runs on a schedule (every
  `EvaluationRateMinutes`) against CloudWatch Logs, which itself has a
  small ingestion delay, plus `ProvisionPermissionSet` is asynchronous on
  top of that. A user can overshoot the cap by a small amount before the
  Deny actually lands. Lower `EvaluationRateMinutes` to shrink this window;
  it can't be reduced to zero with this architecture.
- **Exact-match pricing.** `ModelPricingJson` keys must match the logged
  `modelId` string byte-for-byte, including any cross-region-inference
  prefix or ARN form. A mismatch fails silently (that model's usage is
  priced at $0, never counted, never blocked) — the only guardrail is the
  "models missing a price entry" SNS alert, so don't ignore it.
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

## Troubleshooting

**`aws sts get-caller-identity` → `NoCredentials`**
`aws sso login` only caches an SSO token; it doesn't select a profile. Run
`aws configure sso` to create a named profile (pick an admin-capable
permission set, not `bedrock-limited-access`), then `export
AWS_PROFILE=<name>` or add `--profile <name>` to every command.

**`ValidateTemplate` → `'Description' length is greater than 1024`**
CloudFormation's top-level `Description` field has a hard 1024-character
cap. Long design notes belong in a `#` comment at the top of the file
instead of the `Description:` field — those aren't sent to AWS and don't
count against the limit.

**`aws cloudformation deploy` says "No changes to deploy" after editing a
parameter's `Default` in the file**
`aws cloudformation deploy` uses `UsePreviousValue=true` for any parameter
not explicitly passed via `--parameter-overrides` on an update to an
existing stack — it does **not** pick up a changed `Default` from the
template file. Always pass the changed parameter explicitly:
`--parameter-overrides MonthlyCapUSD=<value>`.

**Deploying fails with something like "Property `Code` cannot have both
`S3Bucket`/`S3Key` and a local path" or the Lambda ends up with literally
`src/enforcer/` as its code**
This means `aws cloudformation deploy` was run directly against
`bedrock-budget-hardstop-sso.yaml` instead of against the packaged output.
`Code: src/enforcer/` (and `src/reset/`) are local paths that only mean
something to `aws cloudformation package` — always run `package` first (or
use `deploy.sh`, which does this for you) and deploy the resulting
`packaged.yaml`, never the original template.

**Edited `src/enforcer/index.py` or `src/reset/index.py`, redeployed, but
the running Lambda's behavior didn't change**
Almost always means `package` wasn't re-run after the code edit, so
`deploy` pushed the same (stale) S3 object it already knew about. `package`
re-zips and re-uploads on every run, so re-running the full `./deploy.sh
<bucket>` (not just `aws cloudformation deploy` on an old `packaged.yaml`)
picks up the change. If you're scripting this yourself without
`deploy.sh`, double check you're re-running `package` before `deploy`
every time, not just re-running `deploy` against a previously generated
`packaged.yaml`.

**`AccessDeniedException` on any `sso:*` call
(`GetInlinePolicyForPermissionSet`, `ProvisionPermissionSet`, etc.), even
though the Lambda's IAM policy looks correct**
Two independent causes, both seen during setup:
- *Wrong IAM action prefix.* The `sso-admin` boto3/CLI **service** name is
  not the IAM **action** prefix — the actual required prefix is `sso:`, not
  `sso-admin:`. The Lambda's own error message will show the correct prefix
  it was denied on (e.g. `"is not authorized to perform:
  sso:GetInlinePolicyForPermissionSet"`) — trust that over the service name.
- *Not a delegated administrator.* These APIs only work from the
  Organizations management account or a delegated administrator account for
  IAM Identity Center (see [Prerequisites](#prerequisites)). A member
  account's local `AdministratorAccess` is not sufficient — this produces
  the identical `AccessDeniedException`, so don't assume it's an IAM policy
  bug without checking this first.

**`403` specifically on `ProvisionPermissionSet`, with everything else
working**
This action requires authorization on the target **account** resource too,
not just `SSOInstanceArn`/`PermissionSetArn`. Make sure the Lambda role's
`sso:*` statement's `Resource` list includes
`arn:aws:sso:::account/${AWS::AccountId}` (already present in this
template's roles) — if the permission set is ever assigned to additional
accounts, add each of those accounts' ARNs too.

**`ValidationException: Invalid PermissionsPolicy Document {"Statement":
[]}`**
IAM Identity Center rejects `PutInlinePolicyToPermissionSet` with an empty
`Statement` array. This happens naturally when removing the last statement
from the inline policy slot (e.g. the reset Lambda clearing the only Deny
statement that was ever in there). Use
`DeleteInlinePolicyFromPermissionSet` instead whenever the resulting
statement list is empty — both Lambdas in this template already do this.

**`UnmodifiableEntityException` on `iam:PutRolePolicy`/similar direct IAM
role calls**
This means something is trying to modify the underlying
`AWSReservedSSO_*` role directly. That's permanently blocked by AWS for any
caller — manage the Permission Set via `sso-admin`/`sso:` APIs instead (see
[How it works](#how-it-works)). Not expected to occur with this template's
current code, but worth knowing if this is ever extended.

**A user isn't getting blocked despite being over cap**
Check the enforcer's CloudWatch Logs for the run in question, and look at
its return value's `unpriced_models` field — if their `modelId` isn't in
`ModelPricingJson` (or shows up with an unexpected prefix/ARN shape), their
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
