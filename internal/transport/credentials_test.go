package transport

import "testing"

func TestParseCredentials_ValidBlob(t *testing.T) {
	raw := []byte(`{
		"access_key_id": "AKIAEXAMPLE",
		"secret_access_key": "supersecret",
		"session_token": "sometoken",
		"expiration": "2026-01-01T00:00:00Z"
	}`)

	creds, err := parseCredentials(raw)
	if err != nil {
		t.Fatalf("parseCredentials: %v", err)
	}
	if creds.AccessKeyID != "AKIAEXAMPLE" {
		t.Errorf("AccessKeyID = %q, want AKIAEXAMPLE", creds.AccessKeyID)
	}
	if creds.SecretAccessKey != "supersecret" {
		t.Errorf("SecretAccessKey = %q, want supersecret", creds.SecretAccessKey)
	}
	if creds.SessionToken != "sometoken" {
		t.Errorf("SessionToken = %q, want sometoken", creds.SessionToken)
	}
}

func TestParseCredentials_RejectsMalformedJSON(t *testing.T) {
	_, err := parseCredentials([]byte(`not json at all`))
	if err == nil {
		t.Fatal("expected an error for malformed JSON, got nil")
	}
}

// TestParseCredentials_RejectsMissingFields makes sure a JSON blob that
// merely PARSES (e.g. an empty object, or one missing the secret) is
// still rejected — we don't want to hand a half-empty, useless credential
// set to the AWS SDK and let every subsequent API call fail with a
// confusing auth error instead of a clear one right here.
func TestParseCredentials_RejectsMissingFields(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{"empty object", `{}`},
		{"missing secret", `{"access_key_id": "AKIAEXAMPLE"}`},
		{"missing access key", `{"secret_access_key": "supersecret"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseCredentials([]byte(tt.raw))
			if err == nil {
				t.Fatal("expected an error for incomplete credentials, got nil")
			}
		})
	}
}
