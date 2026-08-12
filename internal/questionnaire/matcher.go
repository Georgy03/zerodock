package questionnaire

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/Georgy03/zerodock/internal/checks"
	"github.com/Georgy03/zerodock/internal/report"
)

type MatchMethod string

const (
	MatchExact      MatchMethod = "exact_control_id"
	MatchKeyword    MatchMethod = "keyword_semantic"
	MatchRestricted MatchMethod = "restricted_topic"
	MatchUnmatched  MatchMethod = "unmatched"
)

type RowOutcome string

const (
	OutcomeAnswered   RowOutcome = "answered"
	OutcomePartial    RowOutcome = "partial"
	OutcomeFlagged    RowOutcome = "flagged"
	OutcomeNeedsHuman RowOutcome = "needs_human"
)

type Decision struct {
	Outcome      RowOutcome  `json:"outcome"`
	MatchMethod  MatchMethod `json:"match_method"`
	ControlID    string      `json:"control_id,omitempty"`
	CheckIDs     []string    `json:"check_ids,omitempty"`
	Answer       string      `json:"answer,omitempty"`
	EvidenceURL  string      `json:"evidence_url,omitempty"`
	Reason       string      `json:"reason,omitempty"`
	RestrictedAs string      `json:"restricted_as,omitempty"`
	Confidence   string      `json:"confidence"`
}

type Engine struct {
	config Config
}

func NewEngine(cfg Config) *Engine { return &Engine{config: cfg} }

// Decide refuses organizational claims that cloud APIs cannot prove. Policy
// questions are the narrow exception only when they explicitly ask both for
// documentation and technical implementation: ZeroDock may answer the
// technical half, while marking the documentation half for a person.
func (e *Engine) Decide(accountID, controlID, question, evidenceURL string, attestedAt time.Time, coverage string, verdictChecks map[string]report.CheckOutput) Decision {
	topic, phrase := e.restrictedTopic(question)
	compoundPolicy := topic == "policy" && e.hasTechnicalImplementationLanguage(question)
	if topic != "" && !compoundPolicy {
		return Decision{Outcome: OutcomeNeedsHuman, MatchMethod: MatchRestricted, ControlID: controlID, Reason: fmt.Sprintf("%s question contains %q; ZeroDock never auto-answers this category", strings.ReplaceAll(topic, "_", " "), phrase), RestrictedAs: topic, Confidence: "None — restricted topic"}
	}

	mappings := e.config.mappingsForAccount(accountID)
	matched, method := exactMatches(mappings, controlID)
	if len(matched) == 0 {
		matched = keywordMatches(mappings, question)
		method = MatchKeyword
	}
	if len(matched) == 0 {
		if gap := e.evidenceGap(question); gap != "" {
			return Decision{Outcome: OutcomeNeedsHuman, MatchMethod: MatchUnmatched, ControlID: controlID, Reason: gap, Confidence: "None — evidence gap"}
		}
		return Decision{Outcome: OutcomeNeedsHuman, MatchMethod: MatchUnmatched, ControlID: controlID, Reason: "no trustworthy control-ID or keyword match", Confidence: "None — unmatched"}
	}

	checkIDs := make([]string, 0, len(matched))
	for _, m := range matched {
		checkIDs = append(checkIDs, m.CheckID)
	}
	sort.Strings(checkIDs)
	confidence := "Medium — keyword match"
	if method == MatchExact {
		confidence = "High — exact control ID"
	}

	var failures, errorsOut, statements, notInUseStatements []string
	notInUseCount := 0
	for _, m := range matched {
		output, ok := verdictChecks[m.CheckID]
		if !ok {
			errorsOut = append(errorsOut, m.CheckID+": check absent from latest verdict")
			continue
		}
		switch output.Result.Status {
		case checks.StatusPass:
			statements = append(statements, m.VerifiedStatement)
		case checks.StatusNotInUse:
			notInUseCount++
			if m.NotInUseStatement == "" {
				errorsOut = append(errorsOut, m.CheckID+": no not-in-use questionnaire statement is configured")
			} else {
				notInUseStatements = append(notInUseStatements, m.NotInUseStatement)
			}
		case checks.StatusFail:
			if len(output.Result.Findings) == 0 {
				failures = append(failures, output.Title+" is failing")
			} else {
				failures = append(failures, output.Result.Findings...)
			}
		default:
			finding := "check could not be completed"
			if len(output.Result.Findings) > 0 {
				finding = strings.Join(output.Result.Findings, "; ")
			}
			errorsOut = append(errorsOut, m.CheckID+": "+finding)
		}
	}

	if len(errorsOut) > 0 {
		reason := "latest verdict cannot support an answer: " + strings.Join(errorsOut, "; ")
		if compoundPolicy {
			reason += "; policy/procedure documentation also requires human input"
		}
		return Decision{Outcome: OutcomeFlagged, MatchMethod: method, ControlID: controlID, CheckIDs: checkIDs, EvidenceURL: evidenceURL, Reason: reason, RestrictedAs: restrictedLabel(compoundPolicy), Confidence: confidence}
	}
	if len(failures) > 0 {
		answer := "would answer No — " + conciseFindings(failures) + ", fix before submitting."
		reason := "mapped ZeroDock control is currently failing"
		if compoundPolicy {
			answer = "Technical portion " + answer + " Policy/procedure documentation requires human input."
			reason += "; documentation portion requires human input"
		}
		return Decision{Outcome: OutcomeFlagged, MatchMethod: method, ControlID: controlID, CheckIDs: checkIDs, Answer: answer, EvidenceURL: evidenceURL, Reason: reason, RestrictedAs: restrictedLabel(compoundPolicy), Confidence: confidence}
	}
	if coverage == "" {
		coverage = "account coverage unavailable"
	}
	if notInUseCount == len(matched) {
		verified := strings.Join(uniqueStrings(notInUseStatements), "; ") + ". Attested by ZeroDock across " + coverage + " on " + attestedAt.UTC().Format("2006-01-02") + "."
		if compoundPolicy {
			return Decision{Outcome: OutcomePartial, MatchMethod: method, ControlID: controlID, CheckIDs: checkIDs, Answer: "Partial — " + verified + " Policy/procedure documentation requires human input.", EvidenceURL: evidenceURL, Reason: "no applicable cloud resources observed; documentation portion requires human input", RestrictedAs: "policy", Confidence: confidence}
		}
		return Decision{Outcome: OutcomeAnswered, MatchMethod: method, ControlID: controlID, CheckIDs: checkIDs, Answer: "Not applicable — " + verified, EvidenceURL: evidenceURL, Reason: "no applicable AI/ML resources observed in the scanned AWS estate", Confidence: confidence}
	}
	// If some mapped services are in use and others are absent, retain both
	// facts. The positive control statement answers the question; the absence
	// statements make the service boundary explicit.
	statements = append(statements, notInUseStatements...)
	verified := strings.Join(uniqueStrings(statements), "; ") + ". Verified by ZeroDock across " + coverage + " on " + attestedAt.UTC().Format("2006-01-02") + "."
	if compoundPolicy {
		return Decision{Outcome: OutcomePartial, MatchMethod: method, ControlID: controlID, CheckIDs: checkIDs, Answer: "Partial — ZeroDock verifies the technical control is in effect: " + verified + " Policy/procedure documentation requires human input.", EvidenceURL: evidenceURL, Reason: "technical portion supported; documentation portion requires human input", RestrictedAs: "policy", Confidence: confidence}
	}
	return Decision{Outcome: OutcomeAnswered, MatchMethod: method, ControlID: controlID, CheckIDs: checkIDs, Answer: "Yes — " + verified, EvidenceURL: evidenceURL, Reason: "supported by the latest attested verdict", Confidence: confidence}
}

func restrictedLabel(compoundPolicy bool) string {
	if compoundPolicy {
		return "policy"
	}
	return ""
}

func (e *Engine) hasTechnicalImplementationLanguage(question string) bool {
	normalized := normalizeText(question)
	for _, phrase := range e.config.TechnicalImplementationPhrases {
		if containsPhrase(normalized, normalizeText(phrase)) {
			return true
		}
	}
	return false
}

func (e *Engine) evidenceGap(question string) string {
	normalized := normalizeText(question)
	for _, gap := range e.config.EvidenceGaps {
		for _, group := range gap.KeywordGroups {
			matched := len(group) > 0
			for _, keyword := range group {
				if !containsPhrase(normalized, normalizeText(keyword)) {
					matched = false
					break
				}
			}
			if matched {
				return gap.Reason
			}
		}
	}
	return ""
}

func (e *Engine) restrictedTopic(question string) (string, string) {
	normalized := normalizeText(question)
	topics := make([]string, 0, len(e.config.RestrictedTopics))
	for topic := range e.config.RestrictedTopics {
		topics = append(topics, topic)
	}
	sort.Strings(topics)
	for _, topic := range topics {
		for _, phrase := range e.config.RestrictedTopics[topic] {
			if containsPhrase(normalized, normalizeText(phrase)) {
				return topic, phrase
			}
		}
	}
	return "", ""
}

func exactMatches(mappings []Mapping, rawID string) ([]Mapping, MatchMethod) {
	wanted := normalizeControlID(rawID)
	if wanted == "" {
		return nil, MatchExact
	}
	var found []Mapping
	for _, m := range mappings {
		ids := append(append(append([]string{}, m.CAIQIDs...), m.SOC2IDs...), m.ISO42001IDs...)
		for _, id := range ids {
			if normalizeControlID(id) == wanted {
				found = append(found, m)
				break
			}
		}
	}
	return found, MatchExact
}

func keywordMatches(mappings []Mapping, question string) []Mapping {
	normalized := normalizeText(question)
	best := 0
	var found []Mapping
	for _, m := range mappings {
		score := 0
		for _, group := range m.KeywordGroups {
			groupScore := 0
			for _, keyword := range group {
				if containsPhrase(normalized, normalizeText(keyword)) {
					groupScore++
				}
			}
			if groupScore == len(group) && groupScore > score {
				score = groupScore
			}
		}
		if score == 0 {
			continue
		}
		if score > best {
			best, found = score, []Mapping{m}
		} else if score == best {
			found = append(found, m)
		}
	}
	// Ties normally stay with a human. The exception is multiple scanner
	// checks that explicitly map to the same framework control (for example,
	// EBS and RDS encryption both supporting CEK-03); those are one evidence
	// concept and must be evaluated together rather than arbitrarily choosing
	// one service.
	if len(found) > 1 && !shareCAIQControl(found) {
		return nil
	}
	return found
}

func shareCAIQControl(mappings []Mapping) bool {
	if len(mappings) < 2 {
		return len(mappings) == 1
	}
	shared := make(map[string]bool)
	for _, id := range mappings[0].CAIQIDs {
		shared[normalizeControlID(id)] = true
	}
	for _, mapping := range mappings[1:] {
		next := make(map[string]bool)
		for _, id := range mapping.CAIQIDs {
			normalized := normalizeControlID(id)
			if shared[normalized] {
				next[normalized] = true
			}
		}
		shared = next
	}
	return len(shared) > 0
}

var nonControlID = regexp.MustCompile(`[^A-Z0-9.-]`)

func normalizeControlID(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	return nonControlID.ReplaceAllString(s, "")
}

func normalizeText(s string) string {
	return strings.Join(strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	}), " ")
}

func containsPhrase(text, phrase string) bool {
	return strings.Contains(" "+text+" ", " "+phrase+" ")
}

func conciseFindings(findings []string) string {
	const max = 3
	unique := uniqueStrings(findings)
	if len(unique) <= max {
		return strings.Join(unique, "; ")
	}
	return strings.Join(unique[:max], "; ") + fmt.Sprintf("; and %d more finding(s)", len(unique)-max)
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, item := range in {
		item = strings.TrimSpace(item)
		if item != "" && !seen[item] {
			seen[item] = true
			out = append(out, item)
		}
	}
	return out
}
