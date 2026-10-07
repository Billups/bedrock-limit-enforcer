#!/usr/bin/env bash
# Package (upload src/enforcer and src/reset to S3) and deploy the
# bedrock-budget-hardstop CloudFormation stack in one step.
#
# Usage:
#   ./deploy.sh [staging-s3-bucket] [-- <extra --parameter-overrides args>]
#
# Examples:
#   ./deploy.sh
#   ./deploy.sh -- ExemptUsernames="audrai_ai_agent"
#   ./deploy.sh my-other-staging-bucket -- EvaluationRateMinutes=15
#
# Requires: AWS CLI configured (AWS_PROFILE / --profile), region us-west-2.
# The staging bucket just needs to be any bucket in the same account/region
# you can write to -- CloudFormation only reads from it during deploy, it's
# not a permanent part of the stack. Defaults to the bootstrap bucket created
# for this account; pass a different bucket name as the first arg to override.

set -euo pipefail

STACK_NAME="bedrock-budget-hardstop"
REGION="us-west-2"
TEMPLATE="bedrock-budget-hardstop-sso.yaml"
PACKAGED="packaged.yaml"
PRICING_FILE="model-pricing.json"
PRICING_KEY="model-pricing.json"
BUDGET_CONFIG_FILE="budget-config.json"
BUDGET_CONFIG_KEY="budget-config.json"

BUCKET="bedrock-budget-hardstop-396026123718"
if [[ "${1:-}" != "" && "${1}" != "--" ]]; then
  BUCKET="$1"
  shift
fi

if [[ "${1:-}" == "--" ]]; then
  shift
fi
# StagingBucketName must match $BUCKET -- it's how the enforcer's IAM policy
# knows which bucket to allow s3:GetObject on for model-pricing.json. Put it
# first so an explicit override in "$@" (if ever needed) still wins.
PARAM_OVERRIDES=("StagingBucketName=${BUCKET}" "$@")

echo "==> Validating model pricing JSON"
python3 -c "import json; json.load(open('${PRICING_FILE}'))"

echo "==> Validating budget config"
# Same validation the enforcer runs on every load. It can't check for
# overlap with ExemptUsernames here (that's a stack parameter) -- the
# enforcer does that at runtime and stops with an SNS alert if it finds one.
python3 src/enforcer/budget_config.py "${BUDGET_CONFIG_FILE}"

echo "==> Validating template"
aws cloudformation validate-template \
  --template-body "file://${TEMPLATE}" \
  --region "${REGION}" > /dev/null

echo "==> Packaging Lambda source (src/enforcer, src/reset) to s3://${BUCKET}"
aws cloudformation package \
  --template-file "${TEMPLATE}" \
  --s3-bucket "${BUCKET}" \
  --output-template-file "${PACKAGED}" \
  --region "${REGION}"

# Uploaded BEFORE the stack deploy (unlike the pricing table): the enforcer
# stops every run if this object is missing, so it has to exist by the time
# new enforcer code goes live. Older enforcer code just ignores it.
echo "==> Uploading ${BUDGET_CONFIG_FILE} to s3://${BUCKET}/${BUDGET_CONFIG_KEY}"
aws s3 cp "${BUDGET_CONFIG_FILE}" "s3://${BUCKET}/${BUDGET_CONFIG_KEY}" --region "${REGION}" > /dev/null

echo "==> Deploying stack ${STACK_NAME}"
aws cloudformation deploy \
  --template-file "${PACKAGED}" \
  --stack-name "${STACK_NAME}" \
  --capabilities CAPABILITY_IAM \
  --region "${REGION}" \
  --parameter-overrides "${PARAM_OVERRIDES[@]}"

echo "==> Uploading ${PRICING_FILE} to s3://${BUCKET}/${PRICING_KEY}"
aws s3 cp "${PRICING_FILE}" "s3://${BUCKET}/${PRICING_KEY}" --region "${REGION}" > /dev/null

echo "==> Done. Stack outputs:"
aws cloudformation describe-stacks \
  --stack-name "${STACK_NAME}" \
  --region "${REGION}" \
  --query "Stacks[0].Outputs"
