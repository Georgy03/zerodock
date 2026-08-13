package diff

import (
	"testing"

	"github.com/Georgy03/zerodock/internal/checks"
	"github.com/Georgy03/zerodock/internal/report"
)

func TestReportsDetectsStatusAndFindingTransitionsDeterministically(t *testing.T) {
	previous := report.AttestedContent{AccountID: "root", Checks: map[string]report.CheckOutput{
		"aws.ebs.encryption": {Title: "EBS encryption", Accounts: map[string]checks.Result{
			"111": {Status: checks.StatusPass, Findings: []string{}},
			"222": {Status: checks.StatusFail, Findings: []string{"old finding", "resolved finding"}},
		}},
	}}
	current := report.AttestedContent{AccountID: "root", Checks: map[string]report.CheckOutput{
		"aws.ebs.encryption": {Title: "EBS encryption", Accounts: map[string]checks.Result{
			"111": {Status: checks.StatusFail, Findings: []string{"new finding"}},
			"222": {Status: checks.StatusPass, Findings: []string{"old finding"}},
		}},
		"aws.new.check": {Title: "New scanner check", Result: checks.Result{Status: checks.StatusFail}},
	}}

	got := Reports(previous, current)
	if len(got) != 4 {
		t.Fatalf("got %#v, want four changes", got)
	}
	if got[0].Kind != NewFinding || got[0].AccountID != "111" || got[0].Finding != "new finding" {
		t.Errorf("first = %#v", got[0])
	}
	if got[1].Kind != StatusChanged || got[1].AccountID != "111" || got[1].PreviousStatus != "pass" || got[1].CurrentStatus != "fail" {
		t.Errorf("second = %#v", got[1])
	}
	if got[2].Kind != ResolvedFinding || got[2].AccountID != "222" || got[2].Finding != "resolved finding" {
		t.Errorf("third = %#v", got[2])
	}
	if got[3].Kind != StatusChanged || got[3].AccountID != "222" || got[3].PreviousStatus != "fail" || got[3].CurrentStatus != "pass" {
		t.Errorf("fourth = %#v", got[3])
	}
}
