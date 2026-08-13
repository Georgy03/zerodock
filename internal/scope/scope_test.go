package scope

import (
	"reflect"
	"sort"
	"testing"
)

func sortEvents(events []Event) {
	sort.Slice(events, func(i, j int) bool {
		if events[i].Kind != events[j].Kind {
			return events[i].Kind < events[j].Kind
		}
		return events[i].AccountID < events[j].AccountID
	})
}

func TestDetect_NoPriorScan(t *testing.T) {
	current := AccountsSnapshot{Listed: []string{"111", "222"}, Scanned: []string{"111", "222"}}
	if got := Detect(AccountsSnapshot{}, current); got != nil {
		t.Fatalf("Detect with no prior scan = %+v, want nil (nothing to have drifted from)", got)
	}
}

// TestDetect_AccountAdded also expects CoverageDecreased: adding an
// unreachable account to a 1/1-scanned scope drops the ratio to 1/2,
// which is exactly the drift this package exists to catch — the two
// events are not mutually exclusive.
func TestDetect_AccountAdded(t *testing.T) {
	previous := AccountsSnapshot{Listed: []string{"111"}, Scanned: []string{"111"}}
	current := AccountsSnapshot{Listed: []string{"111", "222"}, Scanned: []string{"111"}}

	got := Detect(previous, current)
	sortEvents(got)
	want := []Event{
		{Kind: AccountAdded, AccountID: "222", ScannerRolePresent: false},
		{Kind: CoverageDecreased, PreviousScanned: 1, PreviousListed: 1, CurrentScanned: 1, CurrentListed: 2},
	}
	sortEvents(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Detect() = %+v, want %+v", got, want)
	}
}

func TestDetect_AccountAddedWithScannerRoleAlreadyPresent(t *testing.T) {
	previous := AccountsSnapshot{Listed: []string{"111"}, Scanned: []string{"111"}}
	current := AccountsSnapshot{Listed: []string{"111", "222"}, Scanned: []string{"111", "222"}}

	got := Detect(previous, current)
	want := []Event{{Kind: AccountAdded, AccountID: "222", ScannerRolePresent: true}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Detect() = %+v, want %+v", got, want)
	}
}

func TestDetect_AccountRemoved(t *testing.T) {
	previous := AccountsSnapshot{Listed: []string{"111", "222"}, Scanned: []string{"111", "222"}}
	current := AccountsSnapshot{Listed: []string{"111"}, Scanned: []string{"111"}}

	got := Detect(previous, current)
	want := []Event{{Kind: AccountRemoved, AccountID: "222"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Detect() = %+v, want %+v", got, want)
	}
}

// TestDetect_CoverageDecreasedWithoutCountDropping is the important case
// from this package's own doc comment: 18/18 becoming 18/19. Nothing
// about the scanned count changed, but coverage measurably dropped.
func TestDetect_CoverageDecreasedWithoutCountDropping(t *testing.T) {
	listed18 := make([]string, 18)
	for i := range listed18 {
		listed18[i] = string(rune('a' + i))
	}
	listed19 := append(append([]string{}, listed18...), "new-account")

	previous := AccountsSnapshot{Listed: listed18, Scanned: listed18}
	current := AccountsSnapshot{Listed: listed19, Scanned: listed18}

	got := Detect(previous, current)
	sortEvents(got)

	want := []Event{
		{Kind: AccountAdded, AccountID: "new-account", ScannerRolePresent: false},
		{Kind: CoverageDecreased, PreviousScanned: 18, PreviousListed: 18, CurrentScanned: 18, CurrentListed: 19},
	}
	sortEvents(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Detect() = %+v, want %+v", got, want)
	}
}

func TestDetect_CoverageImprovedIsNotAnEvent(t *testing.T) {
	previous := AccountsSnapshot{Listed: []string{"111", "222"}, Scanned: []string{"111"}}
	current := AccountsSnapshot{Listed: []string{"111", "222"}, Scanned: []string{"111", "222"}}

	got := Detect(previous, current)
	if got != nil {
		t.Fatalf("Detect() with improved coverage and unchanged membership = %+v, want nil", got)
	}
}

func TestDetect_NoChangeIsNoEvents(t *testing.T) {
	previous := AccountsSnapshot{Listed: []string{"111", "222"}, Scanned: []string{"111", "222"}}
	current := AccountsSnapshot{Listed: []string{"111", "222"}, Scanned: []string{"111", "222"}}

	if got := Detect(previous, current); got != nil {
		t.Fatalf("Detect() with identical snapshots = %+v, want nil", got)
	}
}

func TestDetect_SimultaneousAddAndRemove(t *testing.T) {
	previous := AccountsSnapshot{Listed: []string{"111", "222"}, Scanned: []string{"111", "222"}}
	current := AccountsSnapshot{Listed: []string{"111", "333"}, Scanned: []string{"111", "333"}}

	got := Detect(previous, current)
	sortEvents(got)
	want := []Event{
		{Kind: AccountAdded, AccountID: "333", ScannerRolePresent: true},
		{Kind: AccountRemoved, AccountID: "222"},
	}
	sortEvents(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Detect() = %+v, want %+v", got, want)
	}
}
