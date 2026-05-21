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
	SeverityInfo     Severity = "INFO"
)

type Verdict string

const (
	VerdictClean        Verdict = "CLEAN"
	VerdictSuspicious   Verdict = "SUSPICIOUS"
	VerdictMalicious    Verdict = "MALICIOUS"
	VerdictInconclusive Verdict = "INCONCLUSIVE"
)

type Finding struct {
	Severity   Severity `json:"severity"`
	Type       string   `json:"type"`
	ReasonCode string   `json:"reasonCode,omitempty"`
	Confidence int      `json:"confidence,omitempty"`
	Path       string   `json:"path,omitempty"`
	Host       string   `json:"host,omitempty"`
	Port       int      `json:"port,omitempty"`
	IP         string   `json:"ip,omitempty"`
	Evidence   string   `json:"evidence,omitempty"`
}

type Report struct {
	Verdict    Verdict   `json:"verdict"`
	Confidence int       `json:"confidence"`
	Findings   []Finding `json:"findings"`
}

type Reporter struct {
	CIMode           bool
	seenNetworkHosts map[string]int
	networkDupCount  int
}

func NewReporter(ciMode bool) *Reporter {
	return &Reporter{
		CIMode:           ciMode,
		seenNetworkHosts: make(map[string]int),
	}
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
		if f.Type == "fs_read" {
			color.Red("[CRITICAL] File Read Detected: %s\n", f.Path)
		} else if f.Type == "fs_write" {
			color.Red("[CRITICAL] Suspicious File Write: %s\n", f.Path)
		} else if f.Type == "exec" {
			color.Red("[CRITICAL] Suspicious Process Executed: %s\n", f.Path)
		} else {
			color.Red("[CRITICAL] %s: %s\n", f.Type, f.Path)
		}
	} else if f.Severity == SeverityWarning {
		if f.Type == "network" && f.ReasonCode == "EXTERNAL_NETWORK" {
			// Deduplicate network warnings — only print first occurrence per IP.
			r.seenNetworkHosts[f.IP]++
			if r.seenNetworkHosts[f.IP] > 1 {
				r.networkDupCount++
				return
			}
			color.Yellow("[WARNING] Network Connection: %s (%s:%d)\n", f.Host, f.IP, f.Port)
		} else if f.Type == "command" {
			color.Yellow("[WARNING] Suspicious Command Pattern: %s\n", f.Path)
		} else if f.Type == "fs_write" {
			color.Yellow("[WARNING] Unexpected File Write: %s\n", f.Path)
		} else {
			color.Yellow("[WARNING] %s: %s\n", f.Type, f.Path)
		}
	} else {
		color.Cyan("[INFO] %s: %s\n", f.Type, f.Path)
	}
}

func isHardMalicious(f Finding) bool {
	return f.ReasonCode == "CREDENTIAL_READ" ||
		f.ReasonCode == "PERSISTENCE_WRITE" ||
		f.ReasonCode == "REVERSE_SHELL" ||
		f.ReasonCode == "PRIVILEGE_ESCALATION" ||
		f.ReasonCode == "FILELESS_EXEC" ||
		f.ReasonCode == "PROCESS_INJECTION"
}

func reasonWeight(reasonCode string) int {
	switch reasonCode {
	case "CREDENTIAL_READ", "PERSISTENCE_WRITE", "PRIVILEGE_ESCALATION":
		return 80
	case "STAGED_DOWNLOADER", "SUSPICIOUS_EXEC", "SCRIPT_OBFUSCATION":
		return 55
	case "FILELESS_EXEC", "PROCESS_INJECTION", "SYMLINK_SENSITIVE_PATH":
		return 85
	case "BACKDOOR_LISTENER":
		return 55
	case "CURL_PIPE_SHELL":
		return 35
	// Generic lifecycle warnings — always fire for any npm/pnpm/bun install.
	// Low weight because they carry no package-specific signal.
	case "NPM_LIFECYCLE_SCRIPTS", "PNPM_LIFECYCLE_SCRIPTS", "BUN_INSTALL_SCRIPTS":
		return 10
	// Package-specific lifecycle metadata — noteworthy but common for legit packages.
	case "NPM_LIFECYCLE_SCRIPT_METADATA", "PNPM_LIFECYCLE_SCRIPT_METADATA", "BUN_LIFECYCLE_SCRIPT_METADATA":
		return 20
	case "NPM_NON_REGISTRY_SOURCE", "PNPM_NON_REGISTRY_SOURCE", "BUN_NON_REGISTRY_SOURCE":
		return 45
	case "NPM_RECENT_PACKAGE", "PNPM_RECENT_PACKAGE", "BUN_RECENT_PACKAGE":
		return 20
	case "UNEXPECTED_WRITE":
		return 30
	// External network — expected during package installs. Low individual weight.
	case "EXTERNAL_NETWORK":
		return 5
	case "RUNTIME_MISSING_TOOL", "RUNTIME_PREP_FAILURE":
		return 60
	case "TARGET_COMMAND_NOT_FOUND", "TARGET_COMMAND_FAILED":
		return 60
	case "POLICY_BLOCKED_DOMAIN":
		return 20
	case "INCONCLUSIVE_NPM_METADATA", "INCONCLUSIVE_REMOTE_FETCH":
		return 10
	case "INCONCLUSIVE_PNPM_METADATA", "INCONCLUSIVE_BUN_METADATA":
		return 10
	case "SCRIPT_FETCHED", "RUNTIME_METADATA":
		return 0
	// Lifecycle content analysis (from registry script inspection)
	case "NPM_LIFECYCLE_STAGED_DOWNLOADER", "PNPM_LIFECYCLE_STAGED_DOWNLOADER", "BUN_LIFECYCLE_STAGED_DOWNLOADER":
		return 70
	case "NPM_LIFECYCLE_REVERSE_SHELL", "PNPM_LIFECYCLE_REVERSE_SHELL", "BUN_LIFECYCLE_REVERSE_SHELL":
		return 85
	case "NPM_LIFECYCLE_CREDENTIAL_READ", "PNPM_LIFECYCLE_CREDENTIAL_READ", "BUN_LIFECYCLE_CREDENTIAL_READ":
		return 80
	case "NPM_LIFECYCLE_SCRIPT_OBFUSCATION", "PNPM_LIFECYCLE_SCRIPT_OBFUSCATION", "BUN_LIFECYCLE_SCRIPT_OBFUSCATION":
		return 60
	case "NPM_LIFECYCLE_PERSISTENCE_WRITE", "PNPM_LIFECYCLE_PERSISTENCE_WRITE", "BUN_LIFECYCLE_PERSISTENCE_WRITE":
		return 80
	default:
		return 15
	}
}

func Evaluate(findings []Finding) (Verdict, int) {
	if len(findings) == 0 {
		return VerdictClean, 90
	}

	score := 0
	malicious := false
	inconclusive := false
	seenReasonWeight := map[string]int{}
	for _, f := range findings {
		if isHardMalicious(f) || f.Severity == SeverityCritical {
			malicious = true
		}
		if f.ReasonCode == "RUNTIME_MISSING_TOOL" ||
			f.ReasonCode == "RUNTIME_PREP_FAILURE" ||
			f.ReasonCode == "TARGET_COMMAND_NOT_FOUND" ||
			f.ReasonCode == "TARGET_COMMAND_FAILED" {
			inconclusive = true
		}
		w := reasonWeight(f.ReasonCode)
		if f.ReasonCode == "EXTERNAL_NETWORK" {
			// Cap total network contribution at 10 to avoid flooding the score.
			if seenReasonWeight[f.ReasonCode] >= 10 {
				continue
			}
			seenReasonWeight[f.ReasonCode] += w
			score += w
			continue
		}
		if _, exists := seenReasonWeight[f.ReasonCode]; exists {
			continue
		}
		seenReasonWeight[f.ReasonCode] = w
		score += w
	}
	if score > 100 {
		score = 100
	}

	if inconclusive {
		return VerdictInconclusive, 35
	}
	if malicious || score >= 80 {
		if score < 80 {
			score = 80
		}
		return VerdictMalicious, score
	}
	if score >= 25 {
		return VerdictSuspicious, 40 + (score / 2)
	}
	return VerdictClean, 75
}

func (r *Reporter) Report(findings []Finding) {
	verdict, confidence := Evaluate(findings)

	if r.CIMode {
		rep := Report{
			Verdict:    verdict,
			Confidence: confidence,
			Findings:   findings,
		}
		if rep.Findings == nil {
			rep.Findings = []Finding{}
		}
		out, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Println(string(out))
	} else {
		// Print suppressed network connection summary.
		if r.networkDupCount > 0 {
			color.Yellow("[WARNING] ... and %d more network connection(s) to %d host(s) (use --ci for full details)\n",
				r.networkDupCount, len(r.seenNetworkHosts))
		}

		fmt.Println("\n--- Scan Complete ---")
		switch verdict {
		case VerdictMalicious:
			color.Red("Verdict: %s", verdict)
		case VerdictSuspicious, VerdictInconclusive:
			color.Yellow("Verdict: %s", verdict)
		default:
			color.Green("Verdict: %s", verdict)
		}
		fmt.Printf("Confidence: %d\n", confidence)
		fmt.Printf("Total Findings: %d\n", len(findings))
	}

	if verdict == VerdictMalicious || verdict == VerdictInconclusive {
		os.Exit(1)
	}
	os.Exit(0)
}
