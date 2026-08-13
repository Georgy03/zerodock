package gcp

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
	"strings"
	"time"

	"github.com/Georgy03/zerodock/internal/providers"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

const cloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"

// AcquireToken is WIF-first. The audience identifies the vendor-configured AWS
// workload identity provider, not a secret. If WIF is unavailable, the only
// fallback is a service-account JSON key fetched directly from the vendor's
// AWS Secrets Manager secret ARN and held in memory for this scan only.
func AcquireToken(ctx context.Context, httpClient *http.Client, awsCfg aws.Config, audience, serviceAccountKeySecretARN string) (string, error) {
	if audience != "" {
		return exchangeAWSWorkloadIdentity(ctx, httpClient, awsCfg, audience)
	}
	if serviceAccountKeySecretARN == "" {
		return "", fmt.Errorf("GCP requires --gcp-wif-audience or --gcp-service-account-key-secret-arn")
	}
	key, err := providers.FetchVendorSecret(ctx, awsCfg, serviceAccountKeySecretARN)
	if err != nil {
		return "", fmt.Errorf("fetch vendor-owned GCP service-account key: %w", err)
	}
	defer func() { key = "" }()
	return serviceAccountToken(ctx, httpClient, key)
}

func exchangeAWSWorkloadIdentity(ctx context.Context, client *http.Client, cfg aws.Config, audience string) (string, error) {
	credentials, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return "", fmt.Errorf("retrieve AWS credentials for WIF: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://sts.us-east-1.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15", nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("x-goog-cloud-target-resource", audience)
	request.Header.Set("host", request.URL.Host)
	if err := v4.NewSigner().SignHTTP(ctx, credentials, request, "", "sts", "us-east-1", time.Now()); err != nil {
		return "", fmt.Errorf("sign AWS GetCallerIdentity WIF subject: %w", err)
	}
	type header struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	subject := struct {
		URL     string   `json:"url"`
		Method  string   `json:"method"`
		Headers []header `json:"headers"`
	}{URL: request.URL.String(), Method: request.Method}
	for key, values := range request.Header {
		for _, value := range values {
			subject.Headers = append(subject.Headers, header{Key: key, Value: value})
		}
	}
	rawSubject, err := json.Marshal(subject)
	if err != nil {
		return "", err
	}
	values := url.Values{
		"audience": {audience}, "grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"requested_token_type": {"urn:ietf:params:oauth:token-type:access_token"}, "subject_token_type": {"urn:ietf:params:aws:token-type:aws4_request"},
		"subject_token": {string(rawSubject)}, "scope": {cloudPlatformScope},
	}
	return tokenRequest(ctx, client, "https://sts.googleapis.com/v1/token", values)
}

func serviceAccountToken(ctx context.Context, client *http.Client, raw string) (string, error) {
	var key struct {
		ClientEmail string `json:"client_email"`
		PrivateKey  string `json:"private_key"`
		TokenURI    string `json:"token_uri"`
	}
	if err := json.Unmarshal([]byte(raw), &key); err != nil {
		return "", fmt.Errorf("parse service-account key JSON: %w", err)
	}
	block, _ := pem.Decode([]byte(key.PrivateKey))
	if block == nil {
		return "", fmt.Errorf("service-account key has no PEM private_key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse service-account private key: %w", err)
	}
	privateKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("service-account private key is not RSA")
	}
	now := time.Now()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claimsRaw, _ := json.Marshal(map[string]any{"iss": key.ClientEmail, "scope": cloudPlatformScope, "aud": key.TokenURI, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()})
	claims := base64.RawURLEncoding.EncodeToString(claimsRaw)
	unsigned := header + "." + claims
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return tokenRequest(ctx, client, key.TokenURI, url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)}})
}

func tokenRequest(ctx context.Context, client *http.Client, endpoint string, values url.Values) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var body struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || body.AccessToken == "" {
		return "", fmt.Errorf("Google token exchange: %s %s", body.Error, body.Description)
	}
	return body.AccessToken, nil
}
