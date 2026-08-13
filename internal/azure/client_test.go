package azure

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func testClient(t *testing.T, response func(*http.Request) string) *Client {
	t.Helper()
	httpClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(response(r))), Request: r}, nil
	})}
	return NewClient(httpClient, "arm", "graph")
}

func TestEnumerateScopeCollectsManagementGroupSubscriptionsWithoutDuplicates(t *testing.T) {
	client := testClient(t, func(r *http.Request) string {
		switch r.URL.Path {
		case "/providers/Microsoft.Management/managementGroups":
			return `{"value":[{"name":"root"},{"name":"child"}]}`
		case "/providers/Microsoft.Management/managementGroups/root/subscriptions":
			return `{"value":[{"subscriptionId":"sub-b","state":"Enabled"},{"subscriptionId":"sub-a","state":"Enabled"}]}`
		case "/providers/Microsoft.Management/managementGroups/child/subscriptions":
			return `{"value":[{"subscriptionId":"sub-a","state":"Enabled"}]}`
		default:
			t.Fatalf("unexpected ARM request %s", r.URL)
			return `{}`
		}
	})
	scope, err := client.EnumerateScope(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(scope.Subscriptions, ","); got != "sub-a,sub-b" {
		t.Fatalf("subscriptions=%s", got)
	}
}

func TestEnumerateScopeRejectsSubscriptionOnlyVisibility(t *testing.T) {
	client := testClient(t, func(*http.Request) string { return `{"value":[]}` })
	_, err := client.EnumerateScope(context.Background())
	if err == nil || !strings.Contains(err.Error(), "management group") {
		t.Fatalf("scope must fail closed, got %v", err)
	}
}
