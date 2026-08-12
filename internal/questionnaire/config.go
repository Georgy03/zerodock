// Package questionnaire fills customer security questionnaires from a
// verified ZeroDock verdict. It deliberately treats mappings as data: the
// embedded defaults can be replaced with a JSON file, including account-level
// overrides, without rebuilding the matcher.
package questionnaire

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

//go:embed mappings.json
var defaultMappingsJSON []byte

type Mapping struct {
	CheckID           string     `json:"check_id"`
	CAIQIDs           []string   `json:"caiq_ids"`
	SOC2IDs           []string   `json:"soc2_ids"`
	KeywordGroups     [][]string `json:"keyword_groups"`
	VerifiedStatement string     `json:"verified_statement"`
}

type MappingOverride struct {
	Disabled          *bool      `json:"disabled,omitempty"`
	CAIQIDs           []string   `json:"caiq_ids,omitempty"`
	SOC2IDs           []string   `json:"soc2_ids,omitempty"`
	KeywordGroups     [][]string `json:"keyword_groups,omitempty"`
	VerifiedStatement string     `json:"verified_statement,omitempty"`
}

// EvidenceGap describes language that sounds close to a scanner check but
// requires evidence ZeroDock does not collect. Keeping these rules in the
// mapping file makes the limitation visible and customer-overridable without
// teaching the matcher unsafe equivalences in Go code.
type EvidenceGap struct {
	KeywordGroups [][]string `json:"keyword_groups"`
	Reason        string     `json:"reason"`
}

type Config struct {
	SchemaVersion    int                 `json:"schema_version"`
	FrameworkVersion string              `json:"framework_version"`
	Sources          map[string]string   `json:"sources"`
	MinutesPerAnswer int                 `json:"minutes_per_answer"`
	MinutesPerFlag   int                 `json:"minutes_per_flag"`
	RestrictedTopics map[string][]string `json:"restricted_topics"`
	// A policy mention alone is still human-only. These phrases identify the
	// compound form where the same question separately asks whether a technical
	// control is implemented, allowing ZeroDock to answer only that half.
	TechnicalImplementationPhrases []string                              `json:"technical_implementation_phrases"`
	EvidenceGaps                   []EvidenceGap                         `json:"evidence_gaps"`
	Mappings                       []Mapping                             `json:"mappings"`
	AccountOverrides               map[string]map[string]MappingOverride `json:"account_overrides"`
}

// LoadConfig reads an optional operator-supplied mapping file. An empty path
// uses the embedded defaults. This is the extension point for customer and
// per-account language without hard-coding questionnaire rules in Go.
func LoadConfig(path string) (Config, error) {
	data := defaultMappingsJSON
	if path != "" {
		var err error
		data, err = os.ReadFile(path)
		if err != nil {
			return Config{}, fmt.Errorf("read questionnaire mappings: %w", err)
		}
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("decode questionnaire mappings: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) validate() error {
	if c.SchemaVersion != 1 {
		return fmt.Errorf("questionnaire mappings: unsupported schema_version %d", c.SchemaVersion)
	}
	if c.MinutesPerAnswer <= 0 || c.MinutesPerFlag <= 0 {
		return fmt.Errorf("questionnaire mappings: time-estimate minutes must be positive")
	}
	for _, required := range []string{"policy", "human_resources", "governance", "physical_security"} {
		if len(c.RestrictedTopics[required]) == 0 {
			return fmt.Errorf("questionnaire mappings: restricted topic %q must have at least one phrase", required)
		}
	}
	for i, gap := range c.EvidenceGaps {
		if len(gap.KeywordGroups) == 0 || gap.Reason == "" {
			return fmt.Errorf("questionnaire mappings: evidence_gaps[%d] requires keyword_groups and reason", i)
		}
	}
	seen := make(map[string]bool)
	for _, m := range c.Mappings {
		if m.CheckID == "" || m.VerifiedStatement == "" {
			return fmt.Errorf("questionnaire mappings: check_id and verified_statement are required")
		}
		if seen[m.CheckID] {
			return fmt.Errorf("questionnaire mappings: duplicate check_id %q", m.CheckID)
		}
		if len(m.CAIQIDs) == 0 || len(m.SOC2IDs) == 0 || len(m.KeywordGroups) == 0 {
			return fmt.Errorf("questionnaire mappings: check %q must include CAIQ IDs, SOC 2 IDs, and keyword groups", m.CheckID)
		}
		seen[m.CheckID] = true
	}
	return nil
}

func (c Config) mappingsForAccount(accountID string) []Mapping {
	overrides := c.AccountOverrides[accountID]
	out := make([]Mapping, 0, len(c.Mappings))
	for _, base := range c.Mappings {
		override, ok := overrides[base.CheckID]
		if ok && override.Disabled != nil && *override.Disabled {
			continue
		}
		if ok {
			if override.CAIQIDs != nil {
				base.CAIQIDs = override.CAIQIDs
			}
			if override.SOC2IDs != nil {
				base.SOC2IDs = override.SOC2IDs
			}
			if override.KeywordGroups != nil {
				base.KeywordGroups = override.KeywordGroups
			}
			if override.VerifiedStatement != "" {
				base.VerifiedStatement = override.VerifiedStatement
			}
		}
		out = append(out, base)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CheckID < out[j].CheckID })
	return out
}
