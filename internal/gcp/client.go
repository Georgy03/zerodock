// Package gcp implements Google Cloud evidence collection using Google's REST
// APIs. It intentionally has no Google SDK dependency: all requests share the
// enclave's pinned-root HTTP client and are therefore visible in the fixed
// vsock allowlist.
package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

const (
	resourceManagerURL = "https://cloudresourcemanager.googleapis.com"
	computeURL         = "https://compute.googleapis.com"
	storageURL         = "https://storage.googleapis.com"
	iamURL             = "https://iam.googleapis.com"
	sqlAdminURL        = "https://sqladmin.googleapis.com"
	kmsURL             = "https://cloudkms.googleapis.com"
)

type Client struct {
	http  *http.Client
	token string
}

func NewClient(httpClient *http.Client, token string) *Client {
	return &Client{http: httpClient, token: token}
}

func (c *Client) request(ctx context.Context, method, endpoint string, body any, out any) error {
	var reader *strings.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = strings.NewReader(string(raw))
	} else {
		reader = strings.NewReader("")
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Google API %s: %s", endpoint, resp.Status)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *Client) get(ctx context.Context, endpoint string, out any) error {
	return c.request(ctx, http.MethodGet, endpoint, nil, out)
}
func (c *Client) post(ctx context.Context, endpoint string, body any, out any) error {
	return c.request(ctx, http.MethodPost, endpoint, body, out)
}

// Scope is the organization-bound denominator. A credential must see exactly
// one organization and every recursively discovered folder/project beneath it.
// Project-only visibility is rejected instead of becoming a misleading scope.
type Scope struct {
	OrganizationID string
	NoOrganization bool
	Projects       []string
}

func (c *Client) EnumerateScope(ctx context.Context) (Scope, error) {
	var organizations struct {
		Organizations []struct {
			Name string `json:"name"`
		} `json:"organizations"`
		Next string `json:"nextPageToken"`
	}
	if err := c.get(ctx, resourceManagerURL+"/v3/organizations:search", &organizations); err != nil {
		return Scope{}, fmt.Errorf("list organizations (organization-scoped credential required): %w", err)
	}
	if len(organizations.Organizations) != 1 {
		return Scope{}, fmt.Errorf("GCP credential sees %d organizations; configure one organization-scoped credential per scan", len(organizations.Organizations))
	}
	org := organizations.Organizations[0].Name
	if !strings.HasPrefix(org, "organizations/") {
		return Scope{}, fmt.Errorf("invalid organization name %q", org)
	}
	projects, err := c.projectsBelow(ctx, org)
	if err != nil {
		return Scope{}, err
	}
	if len(projects) == 0 {
		return Scope{}, fmt.Errorf("organization %s returned no projects", org)
	}
	sort.Strings(projects)
	return Scope{OrganizationID: strings.TrimPrefix(org, "organizations/"), Projects: projects}, nil
}

func (c *Client) projectsBelow(ctx context.Context, parent string) ([]string, error) {
	var projects []string
	var page string
	for {
		endpoint := resourceManagerURL + "/v3/projects?parent=" + url.QueryEscape(parent) + "&pageSize=1000"
		if page != "" {
			endpoint += "&pageToken=" + url.QueryEscape(page)
		}
		var response struct {
			Projects []struct {
				ProjectID string `json:"projectId"`
				State     string `json:"state"`
			} `json:"projects"`
			Next string `json:"nextPageToken"`
		}
		if err := c.get(ctx, endpoint, &response); err != nil {
			return nil, fmt.Errorf("list projects below %s: %w", parent, err)
		}
		for _, project := range response.Projects {
			if project.ProjectID != "" && (project.State == "" || project.State == "ACTIVE") {
				projects = append(projects, project.ProjectID)
			}
		}
		if response.Next == "" {
			break
		}
		page = response.Next
	}
	var folderPage string
	for {
		endpoint := resourceManagerURL + "/v3/folders?parent=" + url.QueryEscape(parent) + "&pageSize=1000"
		if folderPage != "" {
			endpoint += "&pageToken=" + url.QueryEscape(folderPage)
		}
		var response struct {
			Folders []struct {
				Name  string `json:"name"`
				State string `json:"state"`
			} `json:"folders"`
			Next string `json:"nextPageToken"`
		}
		if err := c.get(ctx, endpoint, &response); err != nil {
			return nil, fmt.Errorf("list folders below %s: %w", parent, err)
		}
		for _, folder := range response.Folders {
			if folder.Name != "" && (folder.State == "" || folder.State == "ACTIVE") {
				nested, err := c.projectsBelow(ctx, folder.Name)
				if err != nil {
					return nil, err
				}
				projects = append(projects, nested...)
			}
		}
		if response.Next == "" {
			break
		}
		folderPage = response.Next
	}
	return projects, nil
}
