#!/usr/bin/env bash
# Creates and deploys the read-only ZeroDock member role across the complete
# AWS Organization. Run from the management account after enabling trusted
# access for CloudFormation StackSets. Service-managed permissions avoid
# creating broad custom StackSet execution roles in every member account.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE_FILE="$SCRIPT_DIR/member-role.yaml"
STACK_SET_NAME="${STACK_SET_NAME:-ZeroDockScannerMemberRole}"
STACK_SET_REGION="${AWS_REGION:-us-east-1}"
SCANNER_ACCOUNT_ID="${1:-${SCANNER_ACCOUNT_ID:-}}"

if [ -z "$SCANNER_ACCOUNT_ID" ]; then
	echo "usage: $0 <scanner-account-id>" >&2
	exit 2
fi
if [[ ! "$SCANNER_ACCOUNT_ID" =~ ^[0-9]{12}$ ]]; then
	echo "deploy-stackset.sh: scanner account ID must be exactly 12 digits" >&2
	exit 2
fi

for tool in aws; do
	if ! command -v "$tool" >/dev/null 2>&1; then
		echo "deploy-stackset.sh: required tool '$tool' not found on PATH" >&2
		exit 1
	fi
done

echo "Activating trusted AWS Organizations access for CloudFormation StackSets..."
aws cloudformation activate-organizations-access --region "$STACK_SET_REGION"

echo "Creating service-managed StackSet $STACK_SET_NAME..."
aws cloudformation create-stack-set \
	--region "$STACK_SET_REGION" \
	--stack-set-name "$STACK_SET_NAME" \
	--description "ZeroDock read-only SecurityAudit member-account role" \
	--template-body "file://$TEMPLATE_FILE" \
	--parameters "ParameterKey=ScannerAccountId,ParameterValue=$SCANNER_ACCOUNT_ID" \
	--permission-model SERVICE_MANAGED \
	--auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
	--managed-execution Active=true \
	--capabilities CAPABILITY_NAMED_IAM \
	--call-as SELF

# Targeting the organization root includes every current member and all child
# OUs. Automatic deployment above ensures accounts added later receive the
# role too. CloudFormation excludes the management account from service-managed
# StackSet instances, so its scanner role needs SecurityAudit directly.
ROOT_ID="$(aws organizations list-roots --region us-east-1 --query 'Roots[0].Id' --output text)"
if [ -z "$ROOT_ID" ] || [ "$ROOT_ID" = "None" ]; then
	echo "deploy-stackset.sh: could not determine the organization root ID" >&2
	exit 1
fi

echo "Deploying StackSet to organization root $ROOT_ID in $STACK_SET_REGION..."
aws cloudformation create-stack-instances \
	--region "$STACK_SET_REGION" \
	--stack-set-name "$STACK_SET_NAME" \
	--deployment-targets "OrganizationalUnitIds=$ROOT_ID" \
	--regions "$STACK_SET_REGION" \
	--operation-preferences FailureTolerancePercentage=0,MaxConcurrentPercentage=100 \
	--call-as SELF

echo "StackSet deployment started. New organization accounts will be included automatically."
