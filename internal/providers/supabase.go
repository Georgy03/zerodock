package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

const SupabaseManagementURL = "https://api.supabase.com"

type SupabaseProject struct{ Ref, OrganizationID string }
type SupabaseClient struct {
	http  *http.Client
	token string
}

func NewSupabaseClient(client *http.Client, token string) *SupabaseClient {
	return &SupabaseClient{http: client, token: token}
}

func (c *SupabaseClient) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, SupabaseManagementURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Supabase Management API %s: %s", path, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// EnumerateSupabaseScope rejects a token that cannot list organizations. This
// is the critical anti-cherry-picking boundary: project-scoped credentials do
// not get to claim a complete estate.
func (c *SupabaseClient) EnumerateSupabaseScope(ctx context.Context) (ProjectScope, []SupabaseProject, error) {
	var orgs []struct {
		ID   string `json:"id"`
		Slug string `json:"slug"`
	}
	if err := c.get(ctx, "/v1/organizations", &orgs); err != nil {
		return ProjectScope{}, nil, fmt.Errorf("list organizations (organization-scoped token required): %w", err)
	}
	if len(orgs) == 0 {
		return ProjectScope{}, nil, fmt.Errorf("organization-scoped token returned no organizations")
	}
	allowed := map[string]struct{}{}
	scope := ProjectScope{Provider: "supabase"}
	for _, org := range orgs {
		if org.ID != "" {
			allowed[org.ID] = struct{}{}
			scope.OrganizationIDs = append(scope.OrganizationIDs, org.ID)
		}
	}
	if len(allowed) == 0 {
		return ProjectScope{}, nil, fmt.Errorf("organizations response contained no IDs")
	}
	var raw []struct {
		Ref            string `json:"ref"`
		OrganizationID string `json:"organization_id"`
	}
	if err := c.get(ctx, "/v1/projects", &raw); err != nil {
		return ProjectScope{}, nil, fmt.Errorf("list projects: %w", err)
	}
	projects := make([]SupabaseProject, 0, len(raw))
	for _, project := range raw {
		if project.Ref == "" || project.OrganizationID == "" {
			return ProjectScope{}, nil, fmt.Errorf("projects response contained a project without ref or organization_id")
		}
		if _, ok := allowed[project.OrganizationID]; !ok {
			return ProjectScope{}, nil, fmt.Errorf("project %s belongs to an organization the token did not enumerate", project.Ref)
		}
		scope.Projects = append(scope.Projects, project.Ref)
		projects = append(projects, SupabaseProject{Ref: project.Ref, OrganizationID: project.OrganizationID})
	}
	if len(projects) == 0 {
		return ProjectScope{}, nil, fmt.Errorf("organization-scoped token returned no projects")
	}
	scope.Normalize()
	sort.Slice(projects, func(i, j int) bool { return projects[i].Ref < projects[j].Ref })
	return scope, projects, nil
}

func (c *SupabaseClient) ProjectJSON(ctx context.Context, ref, path string, out any) error {
	return c.get(ctx, "/v1/projects/"+url.PathEscape(ref)+path, out)
}

// ProjectPublicKey returns the legacy anon key or current publishable key.
// It is intentionally unexported from reports: callers use it only to make
// the one active probe and must never place the value in evidence/logs.
func (c *SupabaseClient) ProjectPublicKey(ctx context.Context, ref string) (string, error) {
	var keys []struct {
		APIKey string `json:"api_key"`
		Type   string `json:"type"`
		Name   string `json:"name"`
	}
	if err := c.ProjectJSON(ctx, ref, "/api-keys?reveal=true", &keys); err != nil {
		return "", err
	}
	for _, key := range keys {
		if key.APIKey != "" && (strings.EqualFold(key.Type, "anon") || strings.Contains(strings.ToLower(key.Name), "publishable")) {
			return key.APIKey, nil
		}
	}
	return "", fmt.Errorf("project has no retrievable anon or publishable Data API key")
}
