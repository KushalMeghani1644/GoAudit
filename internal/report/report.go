package report

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/fatih/color"
)

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityWarning  Severity = "WARNING"
)

type Finding struct {
	Severity Severity `json:"severity"`
	Type     string   `json:"type"`
	Path     string   `json:"path,omitempty"`
	Host     string   `json:"host,omitempty"`
	Port     int      `json:"port,omitempty"`
	IP       string   `json:"ip,omitempty"`
}

type Report struct {
	Verdict  Severity  `json:"verdict"`
	Findings []Finding `json:"findings"`
}

type Reporter struct {
	CIMode bool
}

func NewReporter(ciMode bool) *Reporter {
	return &Reporter{CIMode: ciMode}
}

func (r *Reporter) Fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
	os.Exit(1)
}

func (r *Reporter) PrintLiveFinding(f Finding) {
	if r.CIMode {
		return
	}
	if f.Severity == SeverityCritical {
		color.Red("[CRITICAL] File Read Detected: %s\n", f.Path)
	} else if f.Severity == SeverityWarning {
		color.Yellow("[WARNING] Network Connection: %s (%s:%d)\n", f.Host, f.IP, f.Port)
	}
}

func (r *Reporter) Report(findings []Finding) {
	verdict := SeverityWarning
	if len(findings) == 0 {
		verdict = "CLEAN"
	}
	for _, f := range findings {
		if f.Severity == SeverityCritical {
			verdict = SeverityCritical
			break
		}
	}

	if r.CIMode {
		rep := Report{
			Verdict:  verdict,
			Findings: findings,
		}
		if rep.Findings == nil {
			rep.Findings = []Finding{}
		}
		out, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Println(string(out))
	} else {
		fmt.Println("\n--- Scan Complete ---")
		if verdict == SeverityCritical {
			color.Red("Verdict: %s", verdict)
		} else if verdict == SeverityWarning {
			color.Yellow("Verdict: %s", verdict)
		} else {
			color.Green("Verdict: %s", verdict)
		}
		fmt.Printf("Total Findings: %d\n", len(findings))
	}

	if verdict == SeverityCritical {
		os.Exit(1)
	}
	os.Exit(0)
}
