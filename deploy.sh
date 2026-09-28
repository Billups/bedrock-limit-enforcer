#!/usr/bin/env bash
# Package (upload src/enforcer and src/reset to S3) and deploy the
# bedrock-budget-hardstop CloudFormation stack in one step.
#
# Usage:
#   ./deploy.sh <staging-s3-bucket> [-- <extra --parameter-overrides args>]
#
# Examples:
#   ./deploy.sh my-cfn-staging-bucket
#   ./deploy.sh my-cfn-staging-bucket -- MonthlyCapUSD=150 ExemptUsernames="audrai_ai_agent"
#
# Requires: AWS CLI configured (AWS_PROFILE / --profile), region us-west-2.
# The staging bucket just needs to be any bucket in the same account/region
# you can write to -- CloudFormation only reads from it during deploy, it's
# not a permanent part of the stack.

set -euo pipefail

STACK_NAME="bedrock-budget-hardstop"
REGION="us-west-2"
TEMPLATE="bedrock-budget-hardstop-sso.yaml"
PACKAGED="packaged.yaml"

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <staging-s3-bucket> [-- <parameter-overrides...>]" >&2
  exit 1
fi

BUCKET="$1"
shift

PARAM_OVERRIDES=()
if [[ "${1:-}" == "--" ]]; then
  shift
  PARAM_OVERRIDES=("$@")
fi

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
if [[ ${#PARAM_OVERRIDES[@]} -gt 0 ]]; then
  aws cloudformation deploy \
    --template-file "${PACKAGED}" \
    --stack-name "${STACK_NAME}" \
    --capabilities CAPABILITY_IAM \
    --region "${REGION}" \
    --parameter-overrides "${PARAM_OVERRIDES[@]}"
else
  aws cloudformation deploy \
    --template-file "${PACKAGED}" \
    --stack-name "${STACK_NAME}" \
    --capabilities CAPABILITY_IAM \
    --region "${REGION}"
fi

echo "==> Done. Stack outputs:"
aws cloudformation describe-stacks \
  --stack-name "${STACK_NAME}" \
  --region "${REGION}" \
  --query "Stacks[0].Outputs"
