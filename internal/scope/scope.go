// Package scope detects account-inventory drift between two consecutive
// scans of the same share token: an account appearing that wasn't listed
// before, a previously listed account disappearing, or the
// scanned/listed coverage ratio dropping (the case that matters most —
// see Detect's doc comment).
//
// This logic is intentionally a pure function over two AccountsSnapshot
// values, with no database or network dependency, for two reasons: it's
// trivially unit-testable, and it mirrors exactly what
// web/src/verify/scope.ts does client-side over two independently
// verified attested verdicts. internal/store calls this at ingest time
// to decide what to log and how to classify account_history rows; the
// browser calls the equivalent TypeScript logic over signed data it has
// already verified itself, so a buyer never has to trust this package's
// output — only reproduce it.
package scope

// AccountsSnapshot is one verdict's attested account inventory: every
// account AWS Organizations reported (Listed) and every account the scan
// actually reached (Scanned, a subset of Listed).
type AccountsSnapshot struct {
	Listed  []string
	Scanned []string
}

// EventKind identifies which of the three drift transitions an Event
// represents.
type EventKind string

const (
	// AccountAdded: an account is in the current scan's Listed set but
	// was absent from the previous scan's Listed set.
	AccountAdded EventKind = "account_added"

	// AccountRemoved: an account was in the previous scan's Listed set
	// but is absent from the current scan's Listed set.
	AccountRemoved EventKind = "account_removed"

	// CoverageDecreased: the scanned/listed ratio dropped between scans.
	// This is the important one — see Detect's doc comment.
	CoverageDecreased EventKind = "coverage_decreased"
)

// Event is one detected transition. Which fields are populated depends
// on Kind: AccountID and ScannerRolePresent for AccountAdded; AccountID
// for AccountRemoved; the four counts for CoverageDecreased.
type Event struct {
	Kind EventKind

	// AccountID is set for AccountAdded and AccountRemoved.
	AccountID string

	// ScannerRolePresent is set for AccountAdded: whether the new
	// account was also in the current scan's Scanned set (the scanner
	// role already exists there) or only in Listed (AWS Organizations
	// knows about the account, but ZeroDock has no access to it yet).
	ScannerRolePresent bool

	// Populated for CoverageDecreased.
	PreviousScanned, PreviousListed int
	CurrentScanned, CurrentListed   int
}

// Detect compares previous and current AccountsSnapshot and returns
// every drift event this transition represents — zero, one, or several
// (a single scan can gain a new account AND have coverage decrease at
// the same time, if the new account has no scanner role yet).
//
// previous being the zero value (no prior scan for this share token)
// always returns nil: there is nothing to have drifted from yet, and a
// first-ever scan is not itself a "new account appeared" event for every
// account it lists.
//
// CoverageDecreased is deliberately checked by RATIO, not by raw counts,
// because that's the case an org actually needs to notice: 18 of 18
// accounts connected, then a 19th account appears in AWS Organizations
// with no scanner role deployed to it yet, becomes 18 of 19 — coverage
// dropped even though nothing about the 18 already-connected accounts
// changed, and the raw "accounts scanned" count didn't go down either.
func Detect(previous, current AccountsSnapshot) []Event {
	if len(previous.Listed) == 0 && len(previous.Scanned) == 0 {
		return nil
	}

	var events []Event

	prevListed := toSet(previous.Listed)
	currListed := toSet(current.Listed)
	currScanned := toSet(current.Scanned)

	for _, id := range current.Listed {
		if _, ok := prevListed[id]; !ok {
			_, scanned := currScanned[id]
			events = append(events, Event{Kind: AccountAdded, AccountID: id, ScannerRolePresent: scanned})
		}
	}
	for _, id := range previous.Listed {
		if _, ok := currListed[id]; !ok {
			events = append(events, Event{Kind: AccountRemoved, AccountID: id})
		}
	}

	if len(previous.Listed) > 0 && len(current.Listed) > 0 {
		prevRatio := float64(len(previous.Scanned)) / float64(len(previous.Listed))
		currRatio := float64(len(current.Scanned)) / float64(len(current.Listed))
		if currRatio < prevRatio {
			events = append(events, Event{
				Kind:            CoverageDecreased,
				PreviousScanned: len(previous.Scanned),
				PreviousListed:  len(previous.Listed),
				CurrentScanned:  len(current.Scanned),
				CurrentListed:   len(current.Listed),
			})
		}
	}

	return events
}

func toSet(ids []string) map[string]struct{} {
	set := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		set[id] = struct{}{}
	}
	return set
}
