// Command questionnaire-audit measures ZeroDock's mapping coverage against a
// full CSV/XLSX questionnaire without filling or modifying the source file.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/Georgy03/zerodock/internal/questionnaire"
)

func main() {
	input := flag.String("input", "", "path to a .xlsx or .csv questionnaire")
	mappings := flag.String("mappings", "", "optional questionnaire mappings JSON")
	accountID := flag.String("account-id", "", "optional AWS account ID for account_overrides")
	flag.Parse()
	if *input == "" {
		fmt.Fprintln(os.Stderr, "questionnaire-audit: --input is required")
		os.Exit(2)
	}
	cfg, err := questionnaire.LoadConfig(*mappings)
	if err != nil {
		fmt.Fprintln(os.Stderr, "questionnaire-audit:", err)
		os.Exit(1)
	}
	data, err := os.ReadFile(*input)
	if err != nil {
		fmt.Fprintln(os.Stderr, "questionnaire-audit: read input:", err)
		os.Exit(1)
	}
	audit, err := questionnaire.NewEngine(cfg).Audit(*input, data, *accountID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "questionnaire-audit:", err)
		os.Exit(1)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(audit); err != nil {
		fmt.Fprintln(os.Stderr, "questionnaire-audit: encode result:", err)
		os.Exit(1)
	}
}
