#!/usr/bin/env bash
# Package (upload src/enforcer and src/reset to S3) and deploy the
# bedrock-budget-hardstop CloudFormation stack in one step.
#
# Usage:
#   ./deploy.sh [staging-s3-bucket] [-- <extra --parameter-overrides args>]
#
# Examples:
#   ./deploy.sh
#   ./deploy.sh -- MonthlyCapUSD=150 ExemptUsernames="audrai_ai_agent"
#   ./deploy.sh my-other-staging-bucket -- MonthlyCapUSD=150
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
