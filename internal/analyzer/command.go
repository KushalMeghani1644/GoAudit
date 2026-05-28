package analyzer

import (
	"regexp"
	"strings"

	"github.com/KushalMeghani1644/GoAudit-CLI/internal/report"
)

var (
	curlPipeShellRegex = regexp.MustCompile(`(?i)\bcurl\b[^|]*\|\s*(?:sh|bash)\b`)
	urlRegex           = regexp.MustCompile(`https?://[^\s'"]+`)
	obfuscationRegex   = regexp.MustCompile(`(?i)(base64\s+-d|eval\s+\$?\(|printf\s+['"].*\\x[0-9a-f]{2})`)
)

func AnalyzeCommand(command string) []report.Finding {
	cmd := strings.TrimSpace(command)
	if cmd == "" {
		return nil
	}

	var findings []report.Finding

	if curlPipeShellRegex.MatchString(cmd) {
		findings = append(findings, report.Finding{
			Severity:   report.SeverityWarning,
			Type:       "command",
			ReasonCode: "CURL_PIPE_SHELL",
			Path:       cmd,
			Confidence: 80,
			Evidence:   "Command pipes curl output directly into a shell interpreter",
		})
	}

	if strings.Contains(cmd, "npm install") && !strings.Contains(cmd, "--ignore-scripts") {
		findings = append(findings, report.Finding{
			Severity:   report.SeverityWarning,
			Type:       "command",
			ReasonCode: "NPM_LIFECYCLE_SCRIPTS",
			Path:       cmd,
			Confidence: 65,
			Evidence:   "npm install may execute lifecycle scripts (preinstall/install/postinstall)",
		})
	}
	if (strings.Contains(cmd, "pnpm add") || strings.Contains(cmd, "pnpm install")) && !strings.Contains(cmd, "--ignore-scripts") {
		findings = append(findings, report.Finding{
			Severity:   report.SeverityWarning,
			Type:       "command",
			ReasonCode: "PNPM_LIFECYCLE_SCRIPTS",
			Path:       cmd,
			Confidence: 65,
			Evidence:   "pnpm install/add may execute lifecycle scripts",
		})
	}
	if strings.Contains(cmd, "bun add") {
		findings = append(findings, report.Finding{
			Severity:   report.SeverityWarning,
			Type:       "command",
			ReasonCode: "BUN_INSTALL_SCRIPTS",
			Path:       cmd,
			Confidence: 65,
			Evidence:   "bun add may execute lifecycle scripts from packages",
		})
	}

	if obfuscationRegex.MatchString(cmd) {
		findings = append(findings, report.Finding{
			Severity:   report.SeverityWarning,
			Type:       "command",
			ReasonCode: "SCRIPT_OBFUSCATION",
			Path:       cmd,
			Confidence: 70,
			Evidence:   "Command includes obfuscation or eval-style execution",
		})
	}

	return findings
}

func ExtractURLs(input string) []string {
	matches := urlRegex.FindAllString(input, -1)
	seen := map[string]struct{}{}
	var out []string
	for _, u := range matches {
		if _, ok := seen[u]; ok {
			continue
		}
		seen[u] = struct{}{}
		out = append(out, u)
	}
	return out
}
