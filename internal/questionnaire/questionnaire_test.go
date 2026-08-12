package questionnaire

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Georgy03/zerodock/internal/checks"
	"github.com/Georgy03/zerodock/internal/report"
	"github.com/xuri/excelize/v2"
)

var testTime = time.Date(2026, 8, 12, 17, 54, 34, 0, time.UTC)

func testEngine(t *testing.T) *Engine {
	t.Helper()
	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	return NewEngine(cfg)
}

func testChecks() map[string]report.CheckOutput {
	return map[string]report.CheckOutput{
		"aws.ebs.encryption":       {Title: "EBS encryption", Result: checks.Result{Status: checks.StatusPass, Count: 2}},
		"aws.rds.encryption":       {Title: "RDS encryption", Result: checks.Result{Status: checks.StatusPass, Count: 1}},
		"aws.rds.backup_retention": {Title: "RDS backup retention", Result: checks.Result{Status: checks.StatusPass, Count: 1}},
		"aws.s3.public":            {Title: "Public S3 buckets", Result: checks.Result{Status: checks.StatusFail, Findings: []string{"bucket customer-files allows public access"}, Count: 3}},
		"aws.rds.public_snapshots": {Title: "Public RDS snapshots", Result: checks.Result{Status: checks.StatusPass, Count: 1}},
		"aws.rds.tls_enforcement":  {Title: "RDS TLS enforcement", Result: checks.Result{Status: checks.StatusPass, Count: 2}},
		"aws.iam.root_mfa":         {Title: "Root MFA", Result: checks.Result{Status: checks.StatusError, Findings: []string{"AccessDenied"}}},
	}
}

func TestDecision_ExactIDAggregatesEveryMappedCheck(t *testing.T) {
	d := testEngine(t).Decide("123", "CEK-03.1", "Is stored customer data encrypted at rest?", "https://verify.example/share/t", testTime, "2 of 2 listed AWS accounts", testChecks())
	if d.Outcome != OutcomeAnswered || d.MatchMethod != MatchExact {
		t.Fatalf("decision = %#v", d)
	}
	if len(d.CheckIDs) != 2 || !strings.HasPrefix(d.Answer, "Yes — ") {
		t.Fatalf("expected both storage checks and a Yes answer, got %#v", d)
	}
}

func TestDecision_RestrictedTopicAlwaysStaysBlank(t *testing.T) {
	d := testEngine(t).Decide("123", "CEK-03.1", "Do you maintain an encryption policy approved by management?", "https://verify.example/share/t", testTime, "2 of 2 listed AWS accounts", testChecks())
	if d.Outcome != OutcomeNeedsHuman || d.MatchMethod != MatchRestricted || d.Answer != "" {
		t.Fatalf("restricted decision = %#v", d)
	}
}

func TestDecision_CompoundPolicyQuestionGetsOnlyPartialTechnicalAnswer(t *testing.T) {
	d := testEngine(t).Decide("123", "CEK-03.1", "Are encryption policies documented and is encryption at rest implemented?", "https://verify.example/share/t", testTime, "2 of 2 listed AWS accounts", testChecks())
	if d.Outcome != OutcomePartial || d.MatchMethod != MatchExact {
		t.Fatalf("compound decision = %#v", d)
	}
	if !strings.HasPrefix(d.Answer, "Partial — ") || strings.HasPrefix(d.Answer, "Yes") {
		t.Fatalf("compound question received an unsafe full answer: %q", d.Answer)
	}
	for _, required := range []string{"technical control is in effect", "2 of 2 listed AWS accounts", "documentation requires human input"} {
		if !strings.Contains(d.Answer, required) {
			t.Fatalf("partial answer %q does not contain %q", d.Answer, required)
		}
	}
}

func TestDecision_CompoundPolicyFailureRemainsFlagged(t *testing.T) {
	checksOut := testChecks()
	checksOut["aws.ebs.encryption"] = report.CheckOutput{Title: "EBS encryption", Result: checks.Result{Status: checks.StatusFail, Findings: []string{"unencrypted volume vol-123"}}}
	d := testEngine(t).Decide("123", "CEK-03.1", "Are encryption policies documented and is encryption at rest implemented?", "https://verify.example/share/t", testTime, "2 of 2 listed AWS accounts", checksOut)
	if d.Outcome != OutcomeFlagged || !strings.Contains(d.Answer, "would answer No") || !strings.Contains(d.Answer, "vol-123") {
		t.Fatalf("compound failing decision = %#v", d)
	}
	if !strings.Contains(d.Answer, "documentation requires human input") {
		t.Fatalf("compound failure omitted documentation split: %q", d.Answer)
	}
}

func TestDecision_EvidenceGapsExplainUnsafeNearMatches(t *testing.T) {
	tests := []struct {
		question string
		reason   string
	}{
		{"Is MFA enforced for all remote access?", "root-account MFA does not prove"},
		{"Are backups tested at least annually?", "backup retention does not prove"},
	}
	for _, tt := range tests {
		d := testEngine(t).Decide("123", "", tt.question, "https://verify.example/share/t", testTime, "2 of 2 listed AWS accounts", testChecks())
		if d.Outcome != OutcomeNeedsHuman || d.Answer != "" || d.Confidence != "None — evidence gap" || !strings.Contains(d.Reason, tt.reason) {
			t.Errorf("decision for %q = %#v", tt.question, d)
		}
	}
}

func TestDecision_TLSEnforcementMatchesEncryptionInTransit(t *testing.T) {
	d := testEngine(t).Decide("123", "", "Is data encrypted in transit using TLS?", "https://verify.example/share/t", testTime, "2 of 2 listed AWS accounts", testChecks())
	if d.Outcome != OutcomeAnswered || d.MatchMethod != MatchKeyword || len(d.CheckIDs) != 1 || d.CheckIDs[0] != "aws.rds.tls_enforcement" {
		t.Fatalf("TLS decision = %#v", d)
	}
	if !strings.Contains(d.Answer, "PostgreSQL and MySQL RDS") {
		t.Fatalf("TLS answer overstates or omits its RDS scope: %q", d.Answer)
	}
}

func TestDecision_FailingControlNeverAnswersYes(t *testing.T) {
	d := testEngine(t).Decide("123", "DSP-17", "Are storage buckets private?", "https://verify.example/share/t", testTime, "2 of 2 listed AWS accounts", testChecks())
	if d.Outcome != OutcomeFlagged {
		t.Fatalf("outcome = %q, want flagged", d.Outcome)
	}
	if !strings.HasPrefix(d.Answer, "would answer No — ") || strings.Contains(d.Answer, "Yes") || !strings.Contains(d.Answer, "customer-files") {
		t.Fatalf("unsafe failing answer: %q", d.Answer)
	}
}

func TestDecision_ExactIDTakesPriorityOverKeywords(t *testing.T) {
	// The wording resembles EBS encryption, but DSP-17 maps to public
	// storage exposure. Exact identifiers must win over fuzzy language.
	d := testEngine(t).Decide("123", "DSP-17", "Are EBS volumes encrypted?", "https://verify.example/share/t", testTime, "2 of 2 listed AWS accounts", testChecks())
	if d.MatchMethod != MatchExact || d.Outcome != OutcomeFlagged || !strings.Contains(d.Answer, "customer-files") {
		t.Fatalf("exact ID did not take priority: %#v", d)
	}
}

func TestDecision_KeywordMatchCombinesChecksForOneEvidenceConcept(t *testing.T) {
	engine := testEngine(t)
	unique := engine.Decide("123", "", "Are all EBS volumes encrypted?", "https://verify.example/share/t", testTime, "2 of 2 listed AWS accounts", testChecks())
	if unique.MatchMethod != MatchKeyword || unique.Outcome != OutcomeAnswered || len(unique.CheckIDs) != 1 || unique.CheckIDs[0] != "aws.ebs.encryption" {
		t.Fatalf("unique keyword decision = %#v", unique)
	}
	aggregated := engine.Decide("123", "", "Is customer data encrypted at rest?", "https://verify.example/share/t", testTime, "2 of 2 listed AWS accounts", testChecks())
	if aggregated.Outcome != OutcomeAnswered || len(aggregated.CheckIDs) != 2 {
		t.Fatalf("shared-control keyword decision = %#v", aggregated)
	}
}

func TestDecision_UnrelatedKeywordTieStaysHuman(t *testing.T) {
	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Mappings = []Mapping{
		{CheckID: "one", CAIQIDs: []string{"A-01"}, SOC2IDs: []string{"CC1.1"}, KeywordGroups: [][]string{{"shared phrase"}}, VerifiedStatement: "one"},
		{CheckID: "two", CAIQIDs: []string{"B-01"}, SOC2IDs: []string{"CC2.1"}, KeywordGroups: [][]string{{"shared phrase"}}, VerifiedStatement: "two"},
	}
	d := NewEngine(cfg).Decide("123", "", "Does this shared phrase apply?", "https://verify.example/share/t", testTime, "2 of 2 listed AWS accounts", map[string]report.CheckOutput{})
	if d.Outcome != OutcomeNeedsHuman || d.Answer != "" {
		t.Fatalf("unrelated tie should not auto-answer: %#v", d)
	}
}

func TestDecision_BespokeBackupWordingMatchesSemantically(t *testing.T) {
	d := testEngine(t).Decide("123", "", "Are database backups retained and recoverable?", "https://verify.example/share/t", testTime, "2 of 2 listed AWS accounts", testChecks())
	if d.MatchMethod != MatchKeyword || d.Outcome != OutcomeAnswered || len(d.CheckIDs) != 1 || d.CheckIDs[0] != "aws.rds.backup_retention" {
		t.Fatalf("backup wording was not recognized: %#v", d)
	}
}

func TestDecision_ErrorAndUnmatchedStayBlank(t *testing.T) {
	engine := testEngine(t)
	errorDecision := engine.Decide("123", "IAM-13", "Is root MFA enabled?", "https://verify.example/share/t", testTime, "2 of 2 listed AWS accounts", testChecks())
	if errorDecision.Outcome != OutcomeFlagged || errorDecision.Answer != "" {
		t.Fatalf("error decision = %#v", errorDecision)
	}
	unmatched := engine.Decide("123", "XYZ-99", "Is your legal team adequately staffed?", "https://verify.example/share/t", testTime, "2 of 2 listed AWS accounts", testChecks())
	if unmatched.Outcome != OutcomeNeedsHuman || unmatched.Answer != "" {
		t.Fatalf("unmatched decision = %#v", unmatched)
	}
}

func TestDecision_AccountOverrideIsDataDriven(t *testing.T) {
	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatal(err)
	}
	cfg.AccountOverrides["123"] = map[string]MappingOverride{
		"aws.s3.public": {CAIQIDs: []string{"CUSTOM-01"}, VerifiedStatement: "custom bucket statement"},
	}
	d := NewEngine(cfg).Decide("123", "CUSTOM-01", "Are buckets private?", "https://verify.example/share/t", testTime, "2 of 2 listed AWS accounts", testChecks())
	if d.MatchMethod != MatchExact || d.CheckIDs[0] != "aws.s3.public" {
		t.Fatalf("override was not applied: %#v", d)
	}
}

func TestMappingsCoverEveryScannerCheckAndExcludeSIG(t *testing.T) {
	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatal(err)
	}
	mapped := make(map[string]bool, len(cfg.Mappings))
	for _, mapping := range cfg.Mappings {
		mapped[mapping.CheckID] = true
	}
	for _, check := range checks.All {
		if !mapped[check.ID] {
			t.Errorf("scanner check %q has no questionnaire mapping", check.ID)
		}
	}
	data, _ := json.Marshal(cfg)
	if strings.Contains(strings.ToLower(string(data)), "shared assessments") || strings.Contains(strings.ToLower(string(data)), "sig-") {
		t.Fatal("SIG mappings must not ship before licensing is reviewed")
	}
}

func TestDetectTable_PrefersRealHeadersOverQuestionnaireTitle(t *testing.T) {
	rows := [][]string{
		{"CAIQ v4.1 STAR Security Questionnaire"},
		{"CCM Control ID", "Question", "CSP CAIQ Answer"},
		{"CEK-03", "Provide data protection at rest", ""},
	}
	cols, ok := detectTable(rows)
	if !ok || cols.headerRow != 1 || cols.control != 0 || cols.question != 1 || cols.answer != 2 {
		t.Fatalf("detected columns = %#v, ok=%v", cols, ok)
	}
}

func TestDetectTable_DoesNotTreatCoverTitleAsQuestionColumn(t *testing.T) {
	rows := [][]string{{"Vendor Security Questionnaire"}, {"Document Owner", "Security Team"}}
	if cols, ok := detectTable(rows); ok {
		t.Fatalf("cover sheet was detected as a questionnaire: %#v", cols)
	}
}

func TestDetectTable_DoesNotTreatIntroductionGlossaryAsQuestionnaire(t *testing.T) {
	rows := [][]string{
		{"CAIQ introduction"},
		{"Read these instructions before completing the workbook."},
		{"Section", "Question"},
		{"Question", "The description of the question."},
	}
	if cols, ok := detectTable(rows); ok {
		t.Fatalf("introduction glossary was detected as a questionnaire: %#v", cols)
	}
}

func TestDetectTable_AllowsOneColumnQuestionCSVAtFirstRow(t *testing.T) {
	rows := [][]string{{"Question"}, {"Are EBS volumes encrypted?"}}
	if cols, ok := detectTable(rows); !ok || cols.headerRow != 0 || cols.question != 0 {
		t.Fatalf("one-column question list was not detected: %#v, ok=%v", cols, ok)
	}
}

func TestAutofillXLSX_SIGLiteShapedHeaders(t *testing.T) {
	f := excelize.NewFile()
	sheet := f.GetSheetName(0)
	headers := []interface{}{"#", "Domain", "Question", "Response", "Yes/No/N/A", "Risk Flag", "Notes / Evidence Required", "Score"}
	if err := f.SetSheetRow(sheet, "A1", &headers); err != nil {
		t.Fatal(err)
	}
	row := []interface{}{1, "Data Protection", "Is customer data encrypted at rest (AES-256 or equivalent)?", "", "", "", "", ""}
	if err := f.SetSheetRow(sheet, "A2", &row); err != nil {
		t.Fatal(err)
	}
	var source bytes.Buffer
	if err := f.Write(&source); err != nil {
		t.Fatal(err)
	}
	checksOut := testChecks()
	checksOut["aws.ebs.encryption"] = report.CheckOutput{Title: "EBS encryption", Result: checks.Result{Status: checks.StatusFail, Findings: []string{"unencrypted volume vol-123"}}}
	result, err := testEngine(t).Autofill(AutofillInput{Filename: "sig-lite-shaped.xlsx", Data: source.Bytes(), AccountID: "123", EvidenceURL: "https://buyer.example/?token=t", AttestedAt: testTime, AccountsListed: []string{"123"}, AccountsScanned: []string{"123"}, Checks: checksOut})
	if err != nil {
		t.Fatalf("Autofill: %v", err)
	}
	out, err := excelize.OpenReader(bytes.NewReader(result.Data))
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	answer, _ := out.GetCellValue(sheet, "D2")
	if !strings.HasPrefix(answer, "would answer No — ") || !strings.Contains(answer, "vol-123") {
		t.Fatalf("SIG-shaped answer = %q", answer)
	}
	evidence, _ := out.GetCellValue(sheet, "G2")
	if evidence != "https://buyer.example/?token=t" {
		t.Fatalf("SIG-shaped evidence = %q", evidence)
	}
	confidence, _ := out.GetCellValue(sheet, "J2")
	if confidence != "Medium — keyword match" {
		t.Fatalf("SIG-shaped confidence = %q", confidence)
	}
}

func TestAutofillCSV_PreservesAnswersAndReportsEveryDisposition(t *testing.T) {
	input := "Control ID,Question,Answer\nCEK-03.1,Is data encrypted at rest?,\nDSP-17,Are S3 buckets private?,\nGRC-01.1,Does the board oversee governance?,\nXYZ-99,Do you support customer-managed widgets?,\nCEK-03.1,Already completed,Customer answer\n"
	result, err := testEngine(t).Autofill(AutofillInput{Filename: "customer.csv", Data: []byte(input), AccountID: "123", EvidenceURL: "https://verify.example/share/t", AttestedAt: testTime, AccountsListed: []string{"123", "456"}, AccountsScanned: []string{"123", "456"}, Checks: testChecks()})
	if err != nil {
		t.Fatalf("Autofill: %v", err)
	}
	if result.Report.Answered != 1 || result.Report.Flagged != 1 || result.Report.NeedsHuman != 3 || result.Report.RowsReviewed != 5 {
		t.Fatalf("report = %#v", result.Report)
	}
	records, err := csv.NewReader(bytes.NewReader(result.Data)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if records[5][2] != "Customer answer" {
		t.Fatalf("existing answer overwritten: %q", records[5][2])
	}
	if !strings.HasPrefix(records[2][2], "would answer No — ") {
		t.Fatalf("failing row = %q", records[2][2])
	}
	if records[3][2] != "" || records[4][2] != "" {
		t.Fatalf("human-only rows were filled: %#v %#v", records[3], records[4])
	}
	if got := records[1][3]; got != "https://verify.example/share/t" {
		t.Fatalf("evidence URL = %q", got)
	}
	if !strings.Contains(records[1][2], "2 of 2 listed AWS accounts") || records[1][5] != "High — exact control ID" {
		t.Fatalf("answer lacks coverage/confidence: %#v", records[1])
	}
}

func TestAutofillCSV_ReportsPartialSeparately(t *testing.T) {
	input := "Control ID,Question,Answer\nCEK-03.1,Are encryption policies documented and is encryption at rest implemented?,\n"
	result, err := testEngine(t).Autofill(AutofillInput{Filename: "compound.csv", Data: []byte(input), AccountID: "123", EvidenceURL: "https://verify.example/share/t", AttestedAt: testTime, AccountsListed: []string{"123", "456"}, AccountsScanned: []string{"123", "456"}, Checks: testChecks()})
	if err != nil {
		t.Fatalf("Autofill: %v", err)
	}
	if result.Report.Partial != 1 || result.Report.Answered != 0 || result.Report.Flagged != 0 || result.Report.NeedsHuman != 0 {
		t.Fatalf("partial report = %#v", result.Report)
	}
	records, err := csv.NewReader(bytes.NewReader(result.Data)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(records[1][2], "Partial — ") || !strings.HasPrefix(records[1][4], "partial — ") {
		t.Fatalf("partial row = %#v", records[1])
	}
}

func TestAudit_CountsCompoundPolicyAsPartial(t *testing.T) {
	input := "Control ID,Question\nCEK-03.1,Are encryption policies documented and is encryption at rest implemented?\nGRC-01,Is the security policy approved?\n"
	audit, err := testEngine(t).Audit("compound.csv", []byte(input), "123")
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if audit.Rows != 2 || audit.Partial != 1 || audit.Restricted != 1 || len(audit.Details) != 2 {
		t.Fatalf("audit = %#v", audit)
	}
}

func TestAutofillAndAudit_IgnoreQuestionnaireInstructionRows(t *testing.T) {
	input := "Question,Answer\nFill vendor name first. Answer each question.\nAre EBS volumes encrypted?,\n"
	engine := testEngine(t)
	result, err := engine.Autofill(AutofillInput{Filename: "instructions.csv", Data: []byte(input), AccountID: "123", EvidenceURL: "https://verify.example/share/t", AttestedAt: testTime, AccountsListed: []string{"123"}, AccountsScanned: []string{"123"}, Checks: testChecks()})
	if err != nil {
		t.Fatalf("Autofill: %v", err)
	}
	if result.Report.RowsReviewed != 1 || result.Report.Answered != 1 {
		t.Fatalf("instruction row affected autofill report: %#v", result.Report)
	}
	audit, err := engine.Audit("instructions.csv", []byte(input), "123")
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if audit.Rows != 1 || audit.Keyword != 1 {
		t.Fatalf("instruction row affected audit: %#v", audit)
	}
}

func TestAutofillXLSX_PreservesWorkbookFormulaAndFormat(t *testing.T) {
	f := excelize.NewFile()
	sheet := f.GetSheetName(0)
	for cell, value := range map[string]string{"A1": "Control ID", "B1": "Question", "C1": "Answer", "A2": "CEK-03.1", "B2": "Is data encrypted at rest?"} {
		if err := f.SetCellValue(sheet, cell, value); err != nil {
			t.Fatal(err)
		}
	}
	style, err := f.NewStyle(&excelize.Style{Font: &excelize.Font{Bold: true}, Fill: excelize.Fill{Type: "pattern", Color: []string{"#D9EAF7"}, Pattern: 1}})
	if err != nil {
		t.Fatal(err)
	}
	_ = f.SetCellStyle(sheet, "A1", "C1", style)
	_, _ = f.NewSheet("Calculations")
	_ = f.SetCellFormula("Calculations", "A1", "=1+1")
	var source bytes.Buffer
	if err := f.Write(&source); err != nil {
		t.Fatal(err)
	}

	result, err := testEngine(t).Autofill(AutofillInput{Filename: "customer.xlsx", Data: source.Bytes(), AccountID: "123", EvidenceURL: "https://verify.example/share/t", AttestedAt: testTime, AccountsListed: []string{"123", "456", "789"}, AccountsScanned: []string{"123", "456"}, Checks: testChecks()})
	if err != nil {
		t.Fatalf("Autofill: %v", err)
	}
	out, err := excelize.OpenReader(bytes.NewReader(result.Data))
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	answer, _ := out.GetCellValue(sheet, "C2")
	if !strings.HasPrefix(answer, "Yes — ") {
		t.Fatalf("answer = %q", answer)
	}
	if !strings.Contains(answer, "2 of 3 listed AWS accounts") {
		t.Fatalf("answer lacks partial-coverage caveat: %q", answer)
	}
	evidence, _ := out.GetCellValue(sheet, "D2")
	if evidence != "https://verify.example/share/t" {
		t.Fatalf("evidence = %q", evidence)
	}
	formula, _ := out.GetCellFormula("Calculations", "A1")
	if formula != "=1+1" {
		t.Fatalf("formula changed: %q", formula)
	}
	appendedStyle, _ := out.GetCellStyle(sheet, "D1")
	if appendedStyle != style {
		t.Fatalf("appended header style = %d, want %d", appendedStyle, style)
	}
	confidence, _ := out.GetCellValue(sheet, "F2")
	if confidence != "High — exact control ID" {
		t.Fatalf("confidence = %q", confidence)
	}
}
