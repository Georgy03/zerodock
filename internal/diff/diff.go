// Package diff compares two attested report snapshots. It deliberately has
// no database or HTTP dependency: the exact same transition rules are mirrored
// in web/src/verify/diff.ts and run in the buyer's browser after both inputs
// have independently passed Nitro chain, signature, hash, and PCR checks.
package diff

import (
	"sort"

	"github.com/Georgy03/zerodock/internal/checks"
	"github.com/Georgy03/zerodock/internal/report"
)

type EventKind string

const (
	StatusChanged   EventKind = "status_changed"
	NewFinding      EventKind = "new_finding"
	ResolvedFinding EventKind = "resolved_finding"
)

// Event is one reproducible change between two snapshots. FirstObservedAt is
// intentionally not here: it is the current verdict's separately attested
// document timestamp, added only at presentation time by the caller.
type Event struct {
	Kind           EventKind
	CheckID        string
	CheckTitle     string
	AccountID      string
	PreviousStatus string
	CurrentStatus  string
	Finding        string
}

// Reports compares per-check, per-account results that exist in both
// snapshots. It reports status transitions plus findings added or resolved.
// A newly introduced check is not automatically a regression: older signed
// reports could not have evaluated code that did not exist yet. Likewise an
// account that appears or disappears is handled by scope.Detect, not disguised
// as a control failure.
func Reports(previous, current report.AttestedContent) []Event {
	var events []Event
	for checkID, currentCheck := range current.Checks {
		previousCheck, exists := previous.Checks[checkID]
		if !exists {
			continue
		}
		previousAccounts := accountResults(previous, previousCheck)
		currentAccounts := accountResults(current, currentCheck)
		for accountID, currentResult := range currentAccounts {
			previousResult, exists := previousAccounts[accountID]
			if !exists {
				continue
			}
			if previousResult.Status != currentResult.Status {
				events = append(events, Event{
					Kind:           StatusChanged,
					CheckID:        checkID,
					CheckTitle:     currentCheck.Title,
					AccountID:      accountID,
					PreviousStatus: previousResult.Status,
					CurrentStatus:  currentResult.Status,
				})
			}
			for _, finding := range setDifference(currentResult.Findings, previousResult.Findings) {
				events = append(events, Event{Kind: NewFinding, CheckID: checkID, CheckTitle: currentCheck.Title, AccountID: accountID, Finding: finding})
			}
			for _, finding := range setDifference(previousResult.Findings, currentResult.Findings) {
				events = append(events, Event{Kind: ResolvedFinding, CheckID: checkID, CheckTitle: currentCheck.Title, AccountID: accountID, Finding: finding})
			}
		}
	}
	sort.Slice(events, func(i, j int) bool {
		left, right := severity(events[i]), severity(events[j])
		if left != right {
			return left < right
		}
		if events[i].CheckID != events[j].CheckID {
			return events[i].CheckID < events[j].CheckID
		}
		if events[i].AccountID != events[j].AccountID {
			return events[i].AccountID < events[j].AccountID
		}
		if events[i].Kind != events[j].Kind {
			return events[i].Kind < events[j].Kind
		}
		return events[i].Finding < events[j].Finding
	})
	return events
}

func accountResults(snapshot report.AttestedContent, check report.CheckOutput) map[string]checks.Result {
	if len(check.Accounts) > 0 {
		return check.Accounts
	}
	return map[string]checks.Result{snapshot.AccountID: check.Result}
}

func setDifference(left, right []string) []string {
	rightSet := make(map[string]struct{}, len(right))
	for _, value := range right {
		rightSet[value] = struct{}{}
	}
	seen := make(map[string]struct{}, len(left))
	var out []string
	for _, value := range left {
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		if _, exists := rightSet[value]; !exists {
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}

// severity orders regressions before neutral changes and improvements, so a
// buyer sees the things needing attention first without relying on map order.
func severity(event Event) int {
	if event.Kind == NewFinding {
		return 0
	}
	if event.Kind == ResolvedFinding {
		return 2
	}
	if event.CurrentStatus == checks.StatusFail || event.CurrentStatus == checks.StatusError {
		return 0
	}
	if event.PreviousStatus == checks.StatusFail || event.PreviousStatus == checks.StatusError {
		return 2
	}
	return 1
}
