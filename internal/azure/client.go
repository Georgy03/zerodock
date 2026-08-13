// Package azure gathers Azure provider-attested evidence through ARM and
// Microsoft Graph. Tokens and API traffic use the enclave's pinned-root HTTP
// client; this package never writes credentials into a report or log.
package azure

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/Georgy03/zerodock/internal/providers"
	"github.com/aws/aws-sdk-go-v2/aws"
)

const (
	armURL   = "https://management.azure.com"
	graphURL = "https://graph.microsoft.com"
)

type Credentials struct {
	TenantID             string `json:"tenant_id"`
	ClientID             string `json:"client_id"`
	ClientSecret         string `json:"client_secret"`
	ClientAssertion      string `json:"client_assertion"`
	ClientCertificatePEM string `json:"client_certificate_pem"`
	PrivateKeyPEM        string `json:"private_key_pem"`
}

// AcquireTokens obtains independent ARM and Graph tokens. client_assertion is
// the WIF path: a short-lived JWT issued by the vendor's configured external
// identity provider (for AWS, IAM Outbound Identity Federation). A client
// secret is the documented fallback. Both values live only in the vendor's AWS
// Secrets Manager secret and only in enclave memory while scanning.
func AcquireTokens(ctx context.Context, client *http.Client, cfg aws.Config, secretARN string) (string, string, error) {
	raw, err := providers.FetchVendorSecret(ctx, cfg, secretARN)
	if err != nil {
		return "", "", err
	}
	defer func() { raw = "" }()
	var credentials Credentials
	if err := json.Unmarshal([]byte(raw), &credentials); err != nil {
		return "", "", fmt.Errorf("parse Azure credential JSON: %w", err)
	}
	if credentials.TenantID == "" || credentials.ClientID == "" {
		return "", "", fmt.Errorf("Azure credential requires tenant_id and client_id")
	}
	if credentials.ClientSecret == "" && credentials.ClientAssertion == "" && credentials.PrivateKeyPEM == "" {
		return "", "", fmt.Errorf("Azure credential requires client_secret, certificate private_key_pem, or a short-lived WIF client_assertion")
	}
	arm, err := credentials.token(ctx, client, "https://management.azure.com/.default")
	if err != nil {
		return "", "", err
	}
	graph, err := credentials.token(ctx, client, "https://graph.microsoft.com/.default")
	if err != nil {
		return "", "", err
	}
	return arm, graph, nil
}
func (c Credentials) token(ctx context.Context, client *http.Client, scope string) (string, error) {
	v := url.Values{"client_id": {c.ClientID}, "scope": {scope}, "grant_type": {"client_credentials"}}
	if c.ClientAssertion != "" {
		v.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		v.Set("client_assertion", c.ClientAssertion)
	} else if c.PrivateKeyPEM != "" {
		assertion, err := c.certificateAssertion()
		if err != nil {
			return "", err
		}
		v.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		v.Set("client_assertion", assertion)
	} else {
		v.Set("client_secret", c.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://login.microsoftonline.com/"+url.PathEscape(c.TenantID)+"/oauth2/v2.0/token", strings.NewReader(v.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var out struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || out.AccessToken == "" {
		return "", fmt.Errorf("Azure token request: %s %s", out.Error, out.Description)
	}
	return out.AccessToken, nil
}

// certificateAssertion is Microsoft Entra's PS256 private_key_jwt form. The
// signed assertion and private key remain in enclave memory only.
func (c Credentials) certificateAssertion() (string, error) {
	certBlock, _ := pem.Decode([]byte(c.ClientCertificatePEM))
	if certBlock == nil {
		return "", fmt.Errorf("Azure certificate credential has no client_certificate_pem")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return "", err
	}
	keyBlock, _ := pem.Decode([]byte(c.PrivateKeyPEM))
	if keyBlock == nil {
		return "", fmt.Errorf("Azure certificate credential has no private_key_pem")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return "", err
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("Azure certificate private key is not RSA")
	}
	thumb := sha256.Sum256(cert.Raw)
	header, _ := json.Marshal(map[string]string{"alg": "PS256", "typ": "JWT", "x5t#S256": base64.RawURLEncoding.EncodeToString(thumb[:])})
	now := time.Now()
	audience := "https://login.microsoftonline.com/" + c.TenantID + "/oauth2/v2.0/token"
	claims, _ := json.Marshal(map[string]any{"aud": audience, "iss": c.ClientID, "sub": c.ClientID, "nbf": now.Add(-time.Minute).Unix(), "exp": now.Add(10 * time.Minute).Unix()})
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, digest[:], nil)
	if err != nil {
		return "", err
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

type Client struct {
	http                 *http.Client
	armToken, graphToken string
}

func NewClient(httpClient *http.Client, armToken, graphToken string) *Client {
	return &Client{http: httpClient, armToken: armToken, graphToken: graphToken}
}
func (c *Client) request(ctx context.Context, endpoint, token string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Azure API %s: %s", endpoint, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
func (c *Client) arm(ctx context.Context, path string, out any) error {
	return c.request(ctx, armURL+path, c.armToken, out)
}
func (c *Client) graph(ctx context.Context, path string, out any) error {
	return c.request(ctx, graphURL+path, c.graphToken, out)
}

type Scope struct {
	ManagementGroups []string
	Subscriptions    []string
}

func (c *Client) EnumerateScope(ctx context.Context) (Scope, error) {
	var out struct {
		Value []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"value"`
	}
	if err := c.arm(ctx, "/providers/Microsoft.Management/managementGroups?api-version=2021-04-01", &out); err != nil {
		return Scope{}, fmt.Errorf("list management groups (Reader at management-group root required): %w", err)
	}
	if len(out.Value) == 0 {
		return Scope{}, fmt.Errorf("No Azure management group visible. Either this credential is subscription-scoped, or management-group Reader is missing. ZeroDock requires Reader at the management-group root to guarantee complete coverage.")
	}
	seen := map[string]bool{}
	scope := Scope{}
	for _, group := range out.Value {
		if group.Name == "" {
			continue
		}
		scope.ManagementGroups = append(scope.ManagementGroups, group.Name)
		var subs struct {
			Value []struct {
				SubscriptionID string `json:"subscriptionId"`
				State          string `json:"state"`
			} `json:"value"`
		}
		path := "/providers/Microsoft.Management/managementGroups/" + url.PathEscape(group.Name) + "/subscriptions?api-version=2020-05-01"
		if err := c.arm(ctx, path, &subs); err != nil {
			return Scope{}, fmt.Errorf("list subscriptions below management group %s: %w", group.Name, err)
		}
		for _, sub := range subs.Value {
			if sub.SubscriptionID != "" && (sub.State == "" || strings.EqualFold(sub.State, "Enabled")) {
				seen[sub.SubscriptionID] = true
			}
		}
	}
	for sub := range seen {
		scope.Subscriptions = append(scope.Subscriptions, sub)
	}
	sort.Strings(scope.ManagementGroups)
	sort.Strings(scope.Subscriptions)
	if len(scope.Subscriptions) == 0 {
		return Scope{}, fmt.Errorf("visible Azure management groups contain no enabled subscriptions")
	}
	return scope, nil
}
