#!/usr/bin/env bash
# Creates and deploys the read-only ZeroDock member role across the complete
# AWS Organization. Run from the management account after enabling trusted
# access for CloudFormation StackSets. Service-managed permissions avoid
# creating broad custom StackSet execution roles in every member account.
#
# This is the manual, two-step path kept for operators who already have a
# ZeroDockScannerRole in place. The /onboard flow instead uses
# deploy/onboard.yaml, a single CloudFormation stack that creates that role
# AND this StackSet together, as one copy-paste command.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE_FILE="$SCRIPT_DIR/member-role.yaml"
SOURCE_POLICY_FILE="$SCRIPT_DIR/scanner-assume-member-policy.json"
STACK_SET_NAME="${STACK_SET_NAME:-ZeroDockScannerMemberRole}"
STACK_SET_REGION="${AWS_REGION:-us-east-1}"
SCANNER_ACCOUNT_ID="${1:-${SCANNER_ACCOUNT_ID:-}}"
TENANT_ID="${2:-${TENANT_ID:-}}"
SCANNER_ROLE_NAME="${SCANNER_ROLE_NAME:-ZeroDockScannerRole}"

if [ -z "$SCANNER_ACCOUNT_ID" ] || [ -z "$TENANT_ID" ]; then
	echo "usage: $0 <scanner-account-id> <tenant-id>" >&2
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

# Cross-account AssumeRole requires permission on both sides. The member-role
# template below supplies the destination role's trust policy. SecurityAudit
# deliberately does not grant sts:AssumeRole, so install the narrowly scoped
# source-side permission on the management account's scanner role as well.
echo "Allowing $SCANNER_ROLE_NAME to assume ZeroDock member audit roles..."
aws iam put-role-policy \
	--role-name "$SCANNER_ROLE_NAME" \
	--policy-name ZeroDockAssumeMemberAuditRoles \
	--policy-document "file://$SOURCE_POLICY_FILE"

echo "Activating trusted AWS Organizations access for CloudFormation StackSets..."
aws cloudformation activate-organizations-access --region "$STACK_SET_REGION"

echo "Creating service-managed StackSet $STACK_SET_NAME..."
aws cloudformation create-stack-set \
	--region "$STACK_SET_REGION" \
	--stack-set-name "$STACK_SET_NAME" \
	--description "ZeroDock read-only SecurityAudit member-account role" \
	--template-body "file://$TEMPLATE_FILE" \
	--parameters "ParameterKey=ScannerAccountId,ParameterValue=$SCANNER_ACCOUNT_ID" "ParameterKey=TenantId,ParameterValue=$TENANT_ID" \
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
