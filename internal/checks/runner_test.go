package checks

import (
	"reflect"
	"testing"
)

// TestCollapseRegionErrors_SingleRegionKeepsRegionName confirms that when
// only one region hits a given error, we still name that specific region —
// collapsing shouldn't lose detail when there's nothing to collapse.
func TestCollapseRegionErrors_SingleRegionKeepsRegionName(t *testing.T) {
	in := map[string][]string{
		"AccessDenied: not authorized": {"us-east-1"},
	}
	got := collapseRegionErrors(in)
	want := []string{"us-east-1: AccessDenied: not authorized"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("collapseRegionErrors() = %v, want %v", got, want)
	}
}

// TestCollapseRegionErrors_CollapsesRepeatedMessage is the case the
// customer complaint was about: the same permissions error firing in every
// one of an account's enabled regions used to produce one line per region
// (340 lines for 20 accounts × 17 regions). This confirms it's now exactly
// one line, with a count.
func TestCollapseRegionErrors_CollapsesRepeatedMessage(t *testing.T) {
	in := map[string][]string{
		"AccessDenied: not authorized": {
			"us-east-1", "us-east-2", "us-west-1", "us-west-2",
			"eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1",
			"ap-south-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
			"ap-northeast-2", "ap-northeast-3", "ca-central-1", "sa-east-1",
			"eu-north-1",
		},
	}
	got := collapseRegionErrors(in)
	want := []string{"failed in 17 regions: AccessDenied: not authorized"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("collapseRegionErrors() = %v, want %v", got, want)
	}
}

// TestCollapseRegionErrors_DistinctMessagesStaySeparate makes sure
// collapsing only merges regions that failed with the EXACT SAME message —
// two genuinely different problems (e.g. one region access-denied, another
// throttled) must still show up as two separate findings.
func TestCollapseRegionErrors_DistinctMessagesStaySeparate(t *testing.T) {
	in := map[string][]string{
		"AccessDenied: not authorized": {"us-east-1", "us-west-2"},
		"Throttling: rate exceeded":    {"eu-west-1"},
	}
	got := collapseRegionErrors(in)
	want := []string{
		"eu-west-1: Throttling: rate exceeded",
		"failed in 2 regions: AccessDenied: not authorized",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("collapseRegionErrors() = %v, want %v", got, want)
	}
}

// TestCollapseRegionErrors_Empty confirms the empty-input edge case
// doesn't panic and returns an empty (not nil-vs-empty-ambiguous) slice.
func TestCollapseRegionErrors_Empty(t *testing.T) {
	got := collapseRegionErrors(map[string][]string{})
	if len(got) != 0 {
		t.Errorf("collapseRegionErrors(empty) = %v, want empty", got)
	}
}
