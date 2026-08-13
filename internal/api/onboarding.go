package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/Georgy03/zerodock/internal/providers"
	"github.com/Georgy03/zerodock/internal/store"
)

const maxOnboardingRequestBytes = 4 << 10 // 4 KiB — this body is one account ID

var accountIDPattern = regexp.MustCompile(`^[0-9]{12}$`)

// onboardingChecker is the AWS-calling half of the onboarding flow, kept
// separate from onboardingStore and swappable in tests for the same
// reason verifyFn is swappable — a status poll makes several real STS and
// Organizations calls, which handler tests should not have to make.
type onboardingChecker func(ctx context.Context, cfg aws.Config, customerAccountID, tenantID string) (providers.OnboardingStatus, error)

type createOnboardingRequest struct {
	CustomerAccountID string `json:"customer_account_id"`
}

type createOnboardingResponse struct {
	TenantID     string `json:"tenant_id"`
	StackCommand string `json:"stack_command"`
}

// handleCreateOnboarding implements POST /v1/onboard. It generates a
// tenant ID, records which customer account it belongs to (so a later
// status poll knows which account's ZeroDockScannerRole to assume into),
// and returns the single copy-paste AWS CLI command that deploys
// deploy/onboard.yaml with this tenant's ID and ZeroDock's own account ID
// pre-filled.
func (s *Server) handleCreateOnboarding(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxOnboardingRequestBytes)

	var req createOnboardingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	if !accountIDPattern.MatchString(req.CustomerAccountID) {
		writeError(w, http.StatusBadRequest, "customer_account_id must be exactly 12 digits")
		return
	}
	if s.scannerAccountID == "" {
		writeError(w, http.StatusServiceUnavailable, "onboarding is not configured on this server")
		return
	}

	ob, err := s.store.CreateOnboarding(r.Context(), req.CustomerAccountID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create onboarding: "+err.Error())
		return
	}

	command := fmt.Sprintf(
		"aws cloudformation create-stack --stack-name ZeroDockOnboarding "+
			"--template-url %s "+
			"--parameters ParameterKey=ScannerAccountId,ParameterValue=%s ParameterKey=TenantId,ParameterValue=%s "+
			"--capabilities CAPABILITY_NAMED_IAM",
		s.onboardTemplateURL, s.scannerAccountID, ob.TenantID,
	)

	writeJSON(w, http.StatusCreated, createOnboardingResponse{
		TenantID:     ob.TenantID,
		StackCommand: command,
	})
}

type onboardingStatusResponse struct {
	ManagementRoleConnected bool `json:"management_role_connected"`
	ScopeVerified           bool `json:"scope_verified"`
	NoOrganization          bool `json:"no_organization"`
	TotalAccounts           int  `json:"total_accounts"`
	ConnectedAccounts       int  `json:"connected_accounts"`
}

// handleOnboardingStatus implements GET /v1/onboard/{tenant}/status. It is
// meant to be polled — every call re-derives status live from AWS
// (CheckOnboardingStatus never reads from, or writes to, the database),
// so the counter it drives always reflects what's actually connected
// right now, not a cached snapshot.
func (s *Server) handleOnboardingStatus(w http.ResponseWriter, r *http.Request) {
	if s.scannerAccountID == "" {
		writeError(w, http.StatusServiceUnavailable, "onboarding is not configured on this server")
		return
	}

	tenantID := r.PathValue("tenant")

	ob, err := s.store.GetOnboarding(r.Context(), tenantID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "unknown tenant ID")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not look up onboarding: "+err.Error())
		return
	}

	status, err := s.onboardingCheck(r.Context(), s.awsConfig, ob.CustomerAccountID, ob.TenantID)
	if err != nil {
		writeError(w, http.StatusBadGateway, "could not check AWS connection status: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, onboardingStatusResponse{
		ManagementRoleConnected: status.ManagementRoleConnected,
		ScopeVerified:           status.ScopeVerified,
		NoOrganization:          status.NoOrganization,
		TotalAccounts:           status.TotalAccounts,
		ConnectedAccounts:       status.ConnectedAccounts,
	})
}
