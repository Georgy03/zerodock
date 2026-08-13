package gcp

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func jsonClient(t *testing.T, responder func(*http.Request) string) *Client {
	t.Helper()
	httpClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(responder(r))), Request: r}, nil
	})}
	return NewClient(httpClient, "short-lived-token")
}

func TestEnumerateScopeRecursesFoldersAndSortsProjects(t *testing.T) {
	client := jsonClient(t, func(r *http.Request) string {
		switch {
		case r.URL.Path == "/v3/organizations:search":
			return `{"organizations":[{"name":"organizations/123"}]}`
		case r.URL.Path == "/v3/projects" && r.URL.Query().Get("parent") == "organizations/123":
			return `{"projects":[{"projectId":"z-root","state":"ACTIVE"}]}`
		case r.URL.Path == "/v3/folders" && r.URL.Query().Get("parent") == "organizations/123":
			return `{"folders":[{"name":"folders/456","state":"ACTIVE"}]}`
		case r.URL.Path == "/v3/projects" && r.URL.Query().Get("parent") == "folders/456":
			return `{"projects":[{"projectId":"a-child","state":"ACTIVE"}]}`
		case r.URL.Path == "/v3/folders" && r.URL.Query().Get("parent") == "folders/456":
			return `{"folders":[{"name":"folders/789","state":"ACTIVE"}]}`
		case r.URL.Path == "/v3/projects" && r.URL.Query().Get("parent") == "folders/789":
			return `{"projects":[{"projectId":"m-grandchild","state":"ACTIVE"}]}`
		case r.URL.Path == "/v3/folders" && r.URL.Query().Get("parent") == "folders/789":
			return `{}`
		default:
			t.Fatalf("unexpected Resource Manager request: %s", r.URL)
			return `{}`
		}
	})

	scope, err := client.EnumerateScope(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if scope.OrganizationID != "123" {
		t.Fatalf("organization ID = %q", scope.OrganizationID)
	}
	if got := strings.Join(scope.Projects, ","); got != "a-child,m-grandchild,z-root" {
		t.Fatalf("projects = %q", got)
	}
}

func TestEnumerateScopeRejectsEmptyOrganizationList(t *testing.T) {
	client := jsonClient(t, func(*http.Request) string { return `{}` })
	_, err := client.EnumerateScope(context.Background())
	if err == nil || !strings.Contains(err.Error(), "No GCP organization visible") || !strings.Contains(err.Error(), "gcloud organizations list") {
		t.Fatalf("empty organization result must fail closed, got %v", err)
	}
}
