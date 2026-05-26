package report

import (
	"fmt"
	"sort"
	"strings"
)

var knownRegistryHosts = map[string]bool{
	"registry.npmjs.org":     true,
	"registry.yarnpkg.com":   true,
	"registry.npmmirror.com": true,
}

func FormatHumanReport(findings []Finding, meta ReportMeta, verdict Verdict, confidence int) string {
	var b strings.Builder
	title := meta.Command
	if strings.TrimSpace(title) == "" {
		title = "scan"
	}

	b.WriteString("╭─────────────────────────────────────────────╮\n")
	b.WriteString(fmt.Sprintf("│  GoAudit Report: %-27s│\n", trimWithEllipsis(title, 27)))
	b.WriteString("╰─────────────────────────────────────────────╯\n")

	switch verdict {
	case VerdictMalicious:
		b.WriteString(fmt.Sprintf("🚨 Verdict: %s (confidence: %d)\n", verdict, confidence))
	case VerdictSuspicious, VerdictInconclusive:
		b.WriteString(fmt.Sprintf("⚠️  Verdict: %s (confidence: %d)\n", verdict, confidence))
	default:
		b.WriteString(fmt.Sprintf("✅ Verdict: %s (confidence: %d)\n", verdict, confidence))
	}

	if meta.PackageName != "" {
		if meta.PackageVersion != "" {
			b.WriteString(fmt.Sprintf("📦 Package: %s@%s\n", meta.PackageName, meta.PackageVersion))
		} else {
			b.WriteString(fmt.Sprintf("📦 Package: %s\n", meta.PackageName))
		}
	}

	critical := filterBySeverity(findings, SeverityCritical)
	warnings := filterBySeverity(findings, SeverityWarning)
	info := filterBySeverity(findings, SeverityInfo)

	if len(critical) > 0 {
		b.WriteString("🔴 Critical Findings\n")
		writeFindingsList(&b, critical)
	}
	if len(warnings) > 0 {
		b.WriteString("⚠️  Warnings\n")
		writeFindingsList(&b, warnings)
	}

	writeNetworkSummary(&b, findings)
	writeProbeSummary(&b, findings)

	b.WriteString(fmt.Sprintf("📋 Summary: %d critical, %d warnings, %d informational\n", len(critical), len(warnings), len(info)))
	if verdict == VerdictMalicious {
		b.WriteString("   DO NOT INSTALL this package.\n")
	} else {
		b.WriteString("   Use --ci for full JSON output.\n")
	}
	return b.String()
}

func writeFindingsList(b *strings.Builder, findings []Finding) {
	for i, f := range findings {
		ex := ExplainReason(f.ReasonCode)
		title := ex.Title
		if title == "" {
			title = f.ReasonCode
		}
		context := findingContext(f)
		if context != "" {
			b.WriteString(fmt.Sprintf("   %d. %s: %s\n", i+1, strings.ToUpper(title), context))
		} else {
			b.WriteString(fmt.Sprintf("   %d. %s\n", i+1, strings.ToUpper(title)))
		}
		if ex.Detail != "" {
			b.WriteString(fmt.Sprintf("      └─ %s\n", ex.Detail))
		}
	}
}

func findingContext(f Finding) string {
	switch {
	case f.Path != "":
		return f.Path
	case f.Host != "":
		if f.Port > 0 {
			return fmt.Sprintf("%s:%d", f.Host, f.Port)
		}
		return f.Host
	case f.IP != "":
		if f.Port > 0 {
			return fmt.Sprintf("%s:%d", f.IP, f.Port)
		}
		return f.IP
	default:
		return ""
	}
}

func writeNetworkSummary(b *strings.Builder, findings []Finding) {
	type hostStats struct {
		host  string
		conns int
	}
	counts := map[string]int{}
	registryOnly := true
	for _, f := range findings {
		if f.Type != "network" {
			continue
		}
		host := f.Host
		if host == "" {
			host = f.IP
		}
		if host == "" {
			host = "unknown-host"
		}
		counts[host]++
		if f.ReasonCode != "EXTERNAL_NETWORK_REGISTRY" {
			registryOnly = false
		}
	}
	if len(counts) == 0 {
		return
	}

	hosts := make([]hostStats, 0, len(counts))
	total := 0
	for host, c := range counts {
		hosts = append(hosts, hostStats{host: host, conns: c})
		total += c
	}
	sort.Slice(hosts, func(i, j int) bool {
		if hosts[i].conns == hosts[j].conns {
			return hosts[i].host < hosts[j].host
		}
		return hosts[i].conns > hosts[j].conns
	})

	if registryOnly {
		b.WriteString("🌐 Network Activity (expected)\n")
	} else {
		b.WriteString("🌐 Network Activity\n")
	}
	for _, h := range hosts {
		annotation := ""
		if knownRegistryHosts[strings.ToLower(h.host)] {
			annotation = " (registry)"
		}
		b.WriteString(fmt.Sprintf("   • %d connection(s) to %s%s\n", h.conns, h.host, annotation))
	}
	b.WriteString(fmt.Sprintf("   • %d connection(s) to %d host(s)\n", total, len(hosts)))
}

func writeProbeSummary(b *strings.Builder, findings []Finding) {
	hasProbeMeta := false
	hasProbeRisk := false
	for _, f := range findings {
		if f.ReasonCode == "RUNTIME_METADATA" && strings.Contains(f.Evidence, "phase=probe") {
			hasProbeMeta = true
			continue
		}
		if strings.Contains(f.Evidence, "[runtime probe]") && (f.Severity == SeverityCritical || f.Severity == SeverityWarning) {
			hasProbeRisk = true
		}
	}
	if !hasProbeMeta {
		return
	}
	b.WriteString("🔍 Runtime Probe\n")
	if hasProbeRisk {
		b.WriteString("   • Probe observed suspicious runtime behavior\n")
	} else {
		b.WriteString("   • Runtime probe executed successfully\n")
		b.WriteString("   • No credential access, suspicious writes, or unknown exfiltration detected\n")
	}
}

func filterBySeverity(findings []Finding, severity Severity) []Finding {
	out := make([]Finding, 0)
	for _, f := range findings {
		if f.Severity == severity {
			out = append(out, f)
		}
	}
	return out
}

func trimWithEllipsis(s string, max int) string {
	if max <= 0 {
		return ""
	}
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}
