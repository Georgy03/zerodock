package providers

import (
	"reflect"
	"testing"
)

func TestIntersectRequestedRegions(t *testing.T) {
	requested := []string{"us-east-2", "eu-west-1", "us-east-1"}
	enabled := []string{"us-east-1", "us-east-2"}
	if got, want := IntersectRequestedRegions(requested, enabled), []string{"us-east-2", "us-east-1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("IntersectRequestedRegions() = %v, want %v", got, want)
	}
}

func TestUnavailableRequestedRegions(t *testing.T) {
	requested := []string{"us-east-1", "eu-west-1"}
	enabled := []string{"us-east-1"}
	if got, want := UnavailableRequestedRegions(requested, enabled), []string{"eu-west-1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("UnavailableRequestedRegions() = %v, want %v", got, want)
	}
}
