package questionnaire

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/xuri/excelize/v2"
)

// MappingAudit measures matcher coverage without using a verdict or writing
// answers. It exists so mapping changes can be evaluated against full,
// published questionnaire revisions instead of optimistic hand-picked rows.
type MappingAudit struct {
	Rows       int        `json:"rows"`
	Exact      int        `json:"exact"`
	Keyword    int        `json:"keyword"`
	Partial    int        `json:"partial"`
	Restricted int        `json:"restricted"`
	Unmatched  int        `json:"unmatched"`
	Details    []AuditRow `json:"details"`
}

type AuditRow struct {
	Sheet       string      `json:"sheet"`
	Row         int         `json:"row"`
	ControlID   string      `json:"control_id,omitempty"`
	Question    string      `json:"question"`
	MatchMethod MatchMethod `json:"match_method"`
	CheckIDs    []string    `json:"check_ids,omitempty"`
	Reason      string      `json:"reason,omitempty"`
	Partial     bool        `json:"partial,omitempty"`
}

func (e *Engine) Audit(filename string, data []byte, accountID string) (MappingAudit, error) {
	var audit MappingAudit
	switch strings.ToLower(filepath.Ext(filename)) {
	case ".csv":
		r := csv.NewReader(bytes.NewReader(data))
		r.FieldsPerRecord = -1
		rows, err := r.ReadAll()
		if err != nil {
			return MappingAudit{}, fmt.Errorf("parse CSV: %w", err)
		}
		cols, ok := detectTable(rows)
		if ok {
			e.auditTable(&audit, accountID, "CSV", cols, len(rows), func(row, col int) string {
				return rowValue(rows[row], col)
			})
		}
	case ".xlsx":
		f, err := excelize.OpenReader(bytes.NewReader(data))
		if err != nil {
			return MappingAudit{}, fmt.Errorf("parse XLSX: %w", err)
		}
		defer f.Close()
		for _, sheet := range f.GetSheetList() {
			rows, err := f.GetRows(sheet)
			if err != nil {
				return MappingAudit{}, fmt.Errorf("read XLSX sheet %q: %w", sheet, err)
			}
			cols, ok := detectTable(rows)
			if !ok {
				continue
			}
			e.auditTable(&audit, accountID, sheet, cols, len(rows), func(row, col int) string {
				cell, _ := excelize.CoordinatesToCellName(col+1, row+1)
				value, _ := f.GetCellValue(sheet, cell)
				return strings.TrimSpace(value)
			})
		}
	default:
		return MappingAudit{}, ErrUnsupportedFormat
	}

	if audit.Rows == 0 {
		return MappingAudit{}, ErrNoQuestionTable
	}
	return audit, nil
}

func (e *Engine) auditTable(audit *MappingAudit, accountID, sheet string, cols tableColumns, rowCount int, get func(int, int) string) {
	for row := cols.headerRow + 1; row < rowCount; row++ {
		question := get(row, cols.question)
		controlID := ""
		if cols.control >= 0 {
			controlID = get(row, cols.control)
		}
		if question == "" && controlID == "" {
			continue
		}
		if controlID == "" && isQuestionnaireInstruction(question) {
			continue
		}
		detail := e.auditRow(accountID, sheet, row+1, controlID, question)
		audit.Rows++
		if detail.Partial {
			audit.Partial++
		} else {
			switch detail.MatchMethod {
			case MatchExact:
				audit.Exact++
			case MatchKeyword:
				audit.Keyword++
			case MatchRestricted:
				audit.Restricted++
			case MatchUnmatched:
				audit.Unmatched++
			}
		}
		audit.Details = append(audit.Details, detail)
	}
}

func (e *Engine) auditRow(accountID, sheet string, row int, controlID, question string) AuditRow {
	detail := AuditRow{Sheet: sheet, Row: row, ControlID: controlID, Question: question}
	topic, phrase := e.restrictedTopic(question)
	compoundPolicy := topic == "policy" && e.hasTechnicalImplementationLanguage(question)
	if topic != "" && !compoundPolicy {
		detail.MatchMethod = MatchRestricted
		detail.Reason = fmt.Sprintf("%s: %q", topic, phrase)
		return detail
	}
	mappings := e.config.mappingsForAccount(accountID)
	matched, method := exactMatches(mappings, controlID)
	if len(matched) == 0 {
		matched, method = keywordMatches(mappings, question), MatchKeyword
	}
	if len(matched) == 0 {
		detail.MatchMethod = MatchUnmatched
		if gap := e.evidenceGap(question); gap != "" {
			detail.Reason = gap
		}
		return detail
	}
	detail.MatchMethod = method
	if compoundPolicy {
		detail.Partial = true
		detail.Reason = "technical mapping found; policy/procedure documentation requires human input"
	}
	for _, mapping := range matched {
		detail.CheckIDs = append(detail.CheckIDs, mapping.CheckID)
	}
	return detail
}

func rowValue(row []string, col int) string {
	if col < 0 || col >= len(row) {
		return ""
	}
	return strings.TrimSpace(row[col])
}
