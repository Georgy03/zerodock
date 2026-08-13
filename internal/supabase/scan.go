// Package supabase implements ZeroDock's Supabase provider. Management API
// observations are provider_attested; rls_probe is actively_probed against
// the public PostgREST surface with a project public key held only in memory.
package supabase

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/Georgy03/zerodock/internal/checks"
	"github.com/Georgy03/zerodock/internal/providers"
)

type Output struct {
	Title    string
	Tier     checks.Tier
	Accounts map[string]checks.Result
}

var definitions = map[string]struct {
	title string
	tier  checks.Tier
}{
	"supabase.ssl_enforcement":      {"Supabase Postgres SSL enforcement", checks.ProviderAttested},
	"supabase.network_restrictions": {"Supabase database network restrictions", checks.ProviderAttested},
	"supabase.auth_config":          {"Supabase Auth configuration", checks.ProviderAttested},
	"supabase.security_advisor":     {"Supabase Security Advisor findings", checks.ProviderAttested},
	"supabase.rls_probe":            {"Supabase anonymous Data API row probe", checks.ActivelyProbed},
}

func Scan(ctx context.Context, management *providers.SupabaseClient, dataHTTP *http.Client, projects []providers.SupabaseProject) map[string]Output {
	out := map[string]Output{}
	for id, def := range definitions {
		out[id] = Output{Title: def.title, Tier: def.tier, Accounts: map[string]checks.Result{}}
	}
	for _, project := range projects {
		put(out, "supabase.ssl_enforcement", project.Ref, ssl(ctx, management, project.Ref))
		put(out, "supabase.network_restrictions", project.Ref, network(ctx, management, project.Ref))
		put(out, "supabase.auth_config", project.Ref, auth(ctx, management, project.Ref))
		put(out, "supabase.security_advisor", project.Ref, advisor(ctx, management, project.Ref))
		put(out, "supabase.rls_probe", project.Ref, rls(ctx, management, dataHTTP, project.Ref))
	}
	return out
}

func put(outputs map[string]Output, id, project string, result checks.Result) {
	output := outputs[id]
	output.Accounts[project] = result
	outputs[id] = output
}

func managementResult(ctx context.Context, c *providers.SupabaseClient, ref, path string) (map[string]any, error) {
	var payload map[string]any
	if err := c.ProjectJSON(ctx, ref, path, &payload); err != nil {
		return nil, err
	}
	return payload, nil
}
func ssl(ctx context.Context, c *providers.SupabaseClient, ref string) checks.Result {
	p, err := managementResult(ctx, c, ref, "/ssl-enforcement")
	if err != nil {
		return errResult(err)
	}
	if !anyTrue(p, "database", "enabled") && !anyTrue(p, "current_config", "database") && !anyTrue(p, "requested_config", "database") {
		return fail("Postgres SSL enforcement is disabled")
	}
	return pass(1, nil)
}
func network(ctx context.Context, c *providers.SupabaseClient, ref string) checks.Result {
	p, err := managementResult(ctx, c, ref, "/network-restrictions")
	if err != nil {
		return errResult(err)
	}
	if !hasNonEmptyArray(p, "dbAllowedCidrs") && !hasNonEmptyArray(p, "db_allowed_cidrs") {
		return fail("no database IP allowlist is configured")
	}
	if !anyTrue(p, "restrictionsAppliedSuccessfully") && !anyTrue(p, "restrictions_applied_successfully") {
		return fail("database IP allowlist exists but is not enforced")
	}
	return pass(1, nil)
}
func auth(ctx context.Context, c *providers.SupabaseClient, ref string) checks.Result {
	p, err := managementResult(ctx, c, ref, "/config/auth")
	if err != nil {
		return errResult(err)
	}
	var findings []string
	// Supabase calls this setting "autoconfirm": true means users bypass
	// email confirmation, so it is the failing state.
	if anyTrue(p, "mailer_autoconfirm") || anyTrue(p, "mailer", "autoconfirm") {
		findings = append(findings, "email confirmation is not required")
	}
	if n, ok := numberAt(p, "jwt_exp"); ok && n > 86400 {
		findings = append(findings, fmt.Sprintf("JWT expiry is %.0f seconds (over 24 hours)", n))
	}
	if !anyTrue(p, "mfa", "enabled") && !anyTrue(p, "mfa_enabled") {
		findings = append(findings, "MFA is not enabled in Auth configuration")
	}
	if len(findings) > 0 {
		return checks.Result{Status: checks.StatusFail, Findings: findings, Count: 1}
	}
	return pass(1, nil)
}
func advisor(ctx context.Context, c *providers.SupabaseClient, ref string) checks.Result {
	var p struct {
		Lints []struct{ Name, Title, Level, Detail string } `json:"lints"`
	}
	if err := c.ProjectJSON(ctx, ref, "/advisors/security", &p); err != nil {
		return errResult(err)
	}
	var findings []string
	for _, lint := range p.Lints {
		findings = append(findings, fmt.Sprintf("%s (%s): %s", lint.Title, lint.Name, lint.Detail))
	}
	if len(findings) > 0 {
		return checks.Result{Status: checks.StatusFail, Findings: findings, Count: len(p.Lints)}
	}
	return pass(0, nil)
}
func rls(ctx context.Context, c *providers.SupabaseClient, client *http.Client, ref string) checks.Result {
	key, err := c.ProjectPublicKey(ctx, ref)
	if err != nil {
		return errResult(err)
	}
	defer func() { key = "" }()
	var spec struct {
		Paths map[string]json.RawMessage `json:"paths"`
	}
	if err := c.ProjectJSON(ctx, ref, "/database/openapi?schema=public", &spec); err != nil {
		return errResult(err)
	}
	tables := make([]string, 0, len(spec.Paths))
	for path := range spec.Paths {
		if name := strings.TrimPrefix(path, "/"); name != "" && !strings.Contains(name, "/") {
			tables = append(tables, name)
		}
	}
	sort.Strings(tables)
	if len(tables) == 0 {
		return checks.Result{Status: checks.StatusNotInUse, Findings: []string{"no tables exposed via the Data API"}}
	}
	var findings []string
	for _, table := range tables {
		u := "https://" + ref + ".supabase.co/rest/v1/" + url.PathEscape(table) + "?select=*&limit=1"
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		req.Header.Set("apikey", key)
		req.Header.Set("Authorization", "Bearer "+key)
		resp, err := client.Do(req)
		if err != nil {
			return errResult(fmt.Errorf("probe table %s: %w", table, err))
		}
		var rows []json.RawMessage
		decodeErr := json.NewDecoder(resp.Body).Decode(&rows)
		resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return errResult(fmt.Errorf("probe table %s: Data API returned %s", table, resp.Status))
		}
		if decodeErr != nil {
			return errResult(fmt.Errorf("decode table %s response: %w", table, decodeErr))
		}
		if len(rows) > 0 {
			findings = append(findings, "HIGH: anon role returned a row from Data API table "+table)
		}
	}
	if len(findings) > 0 {
		return checks.Result{Status: checks.StatusFail, Findings: findings, Count: len(tables)}
	}
	return checks.Result{Status: checks.StatusPass, Findings: []string{fmt.Sprintf("anon role returned no rows across %d tables exposed via the Data API", len(tables))}, Count: len(tables)}
}
func errResult(err error) checks.Result {
	return checks.Result{Status: checks.StatusError, Findings: []string{err.Error()}}
}
func fail(s string) checks.Result {
	return checks.Result{Status: checks.StatusFail, Findings: []string{s}, Count: 1}
}
func pass(count int, evidence []string) checks.Result {
	return checks.Result{Status: checks.StatusPass, Count: count, Evidence: evidence}
}
func anyTrue(m map[string]any, path ...string) bool {
	var v any = m
	for _, part := range path {
		next, ok := v.(map[string]any)
		if !ok {
			return false
		}
		v = next[part]
	}
	b, _ := v.(bool)
	return b
}
func hasNonEmptyArray(m map[string]any, path ...string) bool {
	var v any = m
	for _, part := range path {
		next, ok := v.(map[string]any)
		if !ok {
			return false
		}
		v = next[part]
	}
	a, ok := v.([]any)
	return ok && len(a) > 0
}
func numberAt(m map[string]any, path ...string) (float64, bool) {
	var v any = m
	for _, part := range path {
		next, ok := v.(map[string]any)
		if !ok {
			return 0, false
		}
		v = next[part]
	}
	n, ok := v.(float64)
	return n, ok
}
