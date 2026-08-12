package questionnaire

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/Georgy03/zerodock/internal/report"
	"github.com/xuri/excelize/v2"
)

const (
	maxSheets = 50
	maxRows   = 10000
)

var (
	ErrUnsupportedFormat = errors.New("questionnaire must be a .csv or .xlsx file")
	ErrNoQuestionTable   = errors.New("no questionnaire table found; expected a Question column and optionally a Control ID column")
)

type AutofillInput struct {
	Filename        string
	Data            []byte
	AccountID       string
	EvidenceURL     string
	AttestedAt      time.Time
	Checks          map[string]report.CheckOutput
	AccountsListed  []string
	AccountsScanned []string
}

type AutofillReport struct {
	Answered      int     `json:"answered"`
	Partial       int     `json:"partial"`
	Flagged       int     `json:"flagged"`
	NeedsHuman    int     `json:"needs_human"`
	HoursSaved    float64 `json:"hours_saved"`
	RowsReviewed  int     `json:"rows_reviewed"`
	Framework     string  `json:"framework"`
	EvidenceURL   string  `json:"evidence_url"`
	VerdictDate   string  `json:"verdict_date"`
	EstimateBasis string  `json:"estimate_basis"`
}

type AutofillResult struct {
	Filename    string
	ContentType string
	Data        []byte
	Report      AutofillReport
}

type tableColumns struct {
	headerRow  int
	control    int
	question   int
	answer     int
	evidence   int
	status     int
	confidence int
	max        int
}

func (e *Engine) Autofill(input AutofillInput) (AutofillResult, error) {
	ext := strings.ToLower(filepath.Ext(input.Filename))
	var result AutofillResult
	var err error
	switch ext {
	case ".csv":
		result, err = e.autofillCSV(input)
	case ".xlsx":
		result, err = e.autofillXLSX(input)
	default:
		return AutofillResult{}, ErrUnsupportedFormat
	}
	if err != nil {
		return AutofillResult{}, err
	}
	result.Report.Framework = e.config.FrameworkVersion
	result.Report.EvidenceURL = input.EvidenceURL
	result.Report.VerdictDate = input.AttestedAt.UTC().Format(time.RFC3339)
	minutes := (result.Report.Answered+result.Report.Partial)*e.config.MinutesPerAnswer + result.Report.Flagged*e.config.MinutesPerFlag
	result.Report.HoursSaved = float64(minutes) / 60
	result.Report.EstimateBasis = fmt.Sprintf("%d minutes per supported or partial answer and %d minutes per flagged control", e.config.MinutesPerAnswer, e.config.MinutesPerFlag)
	return result, nil
}

func (e *Engine) autofillCSV(input AutofillInput) (AutofillResult, error) {
	r := csv.NewReader(bytes.NewReader(input.Data))
	r.FieldsPerRecord = -1
	records, err := r.ReadAll()
	if err != nil {
		return AutofillResult{}, fmt.Errorf("parse CSV: %w", err)
	}
	cols, ok := detectTable(records)
	if !ok {
		return AutofillResult{}, ErrNoQuestionTable
	}
	ensureCSVColumns(records, &cols)
	summary := e.processRows(input, cols, len(records), func(row, col int) string {
		if row >= len(records) || col < 0 || col >= len(records[row]) {
			return ""
		}
		return records[row][col]
	}, func(row, col int, value string) {
		for len(records[row]) <= col {
			records[row] = append(records[row], "")
		}
		records[row][col] = value
	})

	var out bytes.Buffer
	w := csv.NewWriter(&out)
	if err := w.WriteAll(records); err != nil {
		return AutofillResult{}, fmt.Errorf("write CSV: %w", err)
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return AutofillResult{}, fmt.Errorf("write CSV: %w", err)
	}
	return AutofillResult{Filename: outputFilename(input.Filename), ContentType: "text/csv; charset=utf-8", Data: out.Bytes(), Report: summary}, nil
}

func ensureCSVColumns(records [][]string, cols *tableColumns) {
	header := records[cols.headerRow]
	add := func(name string) int {
		header = append(header, name)
		return len(header) - 1
	}
	if cols.answer < 0 {
		cols.answer = add("ZeroDock Answer")
	}
	if cols.evidence < 0 {
		cols.evidence = add("ZeroDock Evidence URL")
	}
	if cols.status < 0 {
		cols.status = add("ZeroDock Review Status")
	}
	if cols.confidence < 0 {
		cols.confidence = add("ZeroDock Confidence")
	}
	records[cols.headerRow] = header
}

func (e *Engine) autofillXLSX(input AutofillInput) (AutofillResult, error) {
	f, err := excelize.OpenReader(bytes.NewReader(input.Data))
	if err != nil {
		return AutofillResult{}, fmt.Errorf("parse XLSX: %w", err)
	}
	defer f.Close()

	sheets := f.GetSheetList()
	if len(sheets) > maxSheets {
		return AutofillResult{}, fmt.Errorf("XLSX has %d sheets; maximum is %d", len(sheets), maxSheets)
	}
	found := false
	total := AutofillReport{}
	for _, sheet := range sheets {
		rows, err := f.GetRows(sheet)
		if err != nil {
			return AutofillResult{}, fmt.Errorf("read XLSX sheet %q: %w", sheet, err)
		}
		if len(rows) > maxRows {
			return AutofillResult{}, fmt.Errorf("XLSX sheet %q has %d rows; maximum is %d", sheet, len(rows), maxRows)
		}
		cols, ok := detectTable(rows)
		if !ok {
			continue
		}
		found = true
		if err := ensureXLSXColumns(f, sheet, &cols); err != nil {
			return AutofillResult{}, err
		}
		summary := e.processRows(input, cols, len(rows), func(row, col int) string {
			cell, _ := excelize.CoordinatesToCellName(col+1, row+1)
			value, _ := f.GetCellValue(sheet, cell)
			return value
		}, func(row, col int, value string) {
			cell, _ := excelize.CoordinatesToCellName(col+1, row+1)
			_ = f.SetCellValue(sheet, cell, value)
		})
		total.Answered += summary.Answered
		total.Partial += summary.Partial
		total.Flagged += summary.Flagged
		total.NeedsHuman += summary.NeedsHuman
		total.RowsReviewed += summary.RowsReviewed
	}
	if !found {
		return AutofillResult{}, ErrNoQuestionTable
	}
	var out bytes.Buffer
	if err := f.Write(&out); err != nil {
		return AutofillResult{}, fmt.Errorf("write XLSX: %w", err)
	}
	return AutofillResult{Filename: outputFilename(input.Filename), ContentType: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", Data: out.Bytes(), Report: total}, nil
}

func ensureXLSXColumns(f *excelize.File, sheet string, cols *tableColumns) error {
	add := func(name string) (int, error) {
		cols.max++
		cell, _ := excelize.CoordinatesToCellName(cols.max+1, cols.headerRow+1)
		if err := f.SetCellValue(sheet, cell, name); err != nil {
			return -1, err
		}
		// Carry the neighboring header style into appended ZeroDock columns
		// so an exported customer workbook still looks like its source.
		if cols.max > 0 {
			previous, _ := excelize.CoordinatesToCellName(cols.max, cols.headerRow+1)
			style, styleErr := f.GetCellStyle(sheet, previous)
			if styleErr == nil && style != 0 {
				_ = f.SetCellStyle(sheet, cell, cell, style)
			}
		}
		return cols.max, nil
	}
	var err error
	if cols.answer < 0 {
		if cols.answer, err = add("ZeroDock Answer"); err != nil {
			return fmt.Errorf("add XLSX answer column: %w", err)
		}
	}
	if cols.evidence < 0 {
		if cols.evidence, err = add("ZeroDock Evidence URL"); err != nil {
			return fmt.Errorf("add XLSX evidence column: %w", err)
		}
	}
	if cols.status < 0 {
		if cols.status, err = add("ZeroDock Review Status"); err != nil {
			return fmt.Errorf("add XLSX status column: %w", err)
		}
	}
	if cols.confidence < 0 {
		if cols.confidence, err = add("ZeroDock Confidence"); err != nil {
			return fmt.Errorf("add XLSX confidence column: %w", err)
		}
	}
	return nil
}

func (e *Engine) processRows(input AutofillInput, cols tableColumns, rowCount int, get func(int, int) string, set func(int, int, string)) AutofillReport {
	var summary AutofillReport
	for row := cols.headerRow + 1; row < rowCount; row++ {
		question := strings.TrimSpace(get(row, cols.question))
		controlID := ""
		if cols.control >= 0 {
			controlID = strings.TrimSpace(get(row, cols.control))
		}
		if question == "" && controlID == "" {
			continue
		}
		if controlID == "" && isQuestionnaireInstruction(question) {
			continue
		}
		summary.RowsReviewed++
		if strings.TrimSpace(get(row, cols.answer)) != "" {
			summary.NeedsHuman++
			set(row, cols.status, "needs human — existing answer preserved")
			set(row, cols.confidence, "Not evaluated — existing answer")
			continue
		}
		coverage := fmt.Sprintf("%d of %d listed AWS accounts", len(input.AccountsScanned), len(input.AccountsListed))
		if len(input.AccountsListed) == 0 {
			coverage = "account coverage unavailable"
		}
		decision := e.Decide(input.AccountID, controlID, question, input.EvidenceURL, input.AttestedAt, coverage, input.Checks)
		switch decision.Outcome {
		case OutcomeAnswered:
			summary.Answered++
		case OutcomePartial:
			summary.Partial++
		case OutcomeFlagged:
			summary.Flagged++
		case OutcomeNeedsHuman:
			summary.NeedsHuman++
		}
		if decision.Answer != "" {
			set(row, cols.answer, decision.Answer)
		}
		if decision.EvidenceURL != "" {
			existingEvidence := strings.TrimSpace(get(row, cols.evidence))
			if existingEvidence == "" {
				set(row, cols.evidence, decision.EvidenceURL)
			} else if !strings.Contains(existingEvidence, decision.EvidenceURL) {
				set(row, cols.evidence, existingEvidence+" | ZeroDock evidence: "+decision.EvidenceURL)
			}
		}
		status := strings.ReplaceAll(string(decision.Outcome), "_", " ") + " — " + decision.Reason
		set(row, cols.status, status)
		set(row, cols.confidence, decision.Confidence)
	}
	return summary
}

func isQuestionnaireInstruction(question string) bool {
	normalized := normalizeText(question)
	for _, marker := range []string{"answer each question", "questionnaire instructions", "completion guidance"} {
		if containsPhrase(normalized, marker) {
			return true
		}
	}
	return false
}

func detectTable(rows [][]string) (tableColumns, bool) {
	limit := len(rows)
	if limit > 30 {
		limit = 30
	}
	bestScore := 0
	var best tableColumns
	for rowIndex := 0; rowIndex < limit; rowIndex++ {
		cols := tableColumns{headerRow: rowIndex, control: -1, question: -1, answer: -1, evidence: -1, status: -1, confidence: -1, max: len(rows[rowIndex]) - 1}
		for col, value := range rows[rowIndex] {
			header := normalizeText(value)
			switch {
			case headerMatches(header, "control id", "ccm control id", "caiq id", "question id", "control identifier"):
				cols.control = col
			case headerEquals(header, "question", "questions", "question text", "assessment question", "consensus assessment question", "control specification", "caiq question", "security question", "question requirement"):
				cols.question = col
			case headerMatches(header, "answer", "response", "vendor response", "csp caiq answer"):
				cols.answer = col
			case headerMatches(header, "evidence", "evidence url", "evidence link", "comments", "implementation description", "csp implementation description"):
				cols.evidence = col
			case headerMatches(header, "zerodock review status", "review status", "autofill status"):
				cols.status = col
			case headerMatches(header, "zerodock confidence", "match confidence", "autofill confidence"):
				cols.confidence = col
			}
		}
		if cols.question < 0 {
			continue
		}
		score := 1
		for _, col := range []int{cols.control, cols.answer, cols.evidence, cols.status, cols.confidence} {
			if col >= 0 {
				score++
			}
		}
		if score > bestScore {
			bestScore, best = score, cols
		}
	}
	// A workbook's introduction sheet can contain a glossary column literally
	// named "Question". Require a second questionnaire-shaped column unless a
	// one-column CSV-style table starts at the first row. This keeps explanatory
	// prose out of both autofill totals and mapping audits without rejecting the
	// smallest useful question list.
	return best, bestScore >= 2 || bestScore == 1 && best.headerRow == 0
}

func headerMatches(header string, candidates ...string) bool {
	for _, candidate := range candidates {
		if header == candidate || strings.Contains(header, candidate) {
			return true
		}
	}
	return false
}

func headerEquals(header string, candidates ...string) bool {
	for _, candidate := range candidates {
		if header == candidate {
			return true
		}
	}
	return false
}

func outputFilename(input string) string {
	ext := filepath.Ext(input)
	base := strings.TrimSuffix(filepath.Base(input), ext)
	base = strings.Map(func(r rune) rune {
		if r == '-' || r == '_' || r == ' ' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' {
			return r
		}
		return -1
	}, base)
	if base == "" {
		base = "questionnaire"
	}
	return base + "-zerodock-filled" + ext
}
