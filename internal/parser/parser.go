package parser

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/KushalMeghani1644/goaudit/internal/report"
)

var (
	fsRegex   = regexp.MustCompile(`(?i)(?:open|openat|openat2).*?\"(.*?)\",\s*([A-Z_\|]+)`)
	netRegex  = regexp.MustCompile(`connect\(.*sa_family=(?:AF_INET|AF_INET6).*?sin_port=htons\((\d+)\).*?(?:inet_addr\("(.*?)"\)|inet_pton\([^,]+,\s*"(.*?)")`)
	execRegex = regexp.MustCompile(`(?i)execve\(\"(.*?)\",\s*\[(.*?)\]`)
	mutRegex  = regexp.MustCompile(`(?i)(?:chmod|fchmod|fchmodat|rename|unlink|unlinkat)\(\"?(.*?)\"?[,)]`)
	privRegex = regexp.MustCompile(`(?i)(?:setuid|setgid|setreuid|setregid)\((\d+)`)

	readCriticalPaths  = regexp.MustCompile(`(?i)(.*?/\.env|.*?/\.ssh/.*?|.*?/\.aws/.*?|.*?/\.kube/.*?|.*?id_rsa)`)
	writeCriticalPaths = regexp.MustCompile(`(?i)(.*?/\.bashrc|.*?/\.zshrc|.*?/\.profile|^/etc/crontab|^/etc/cron\..*|^/usr/local/bin/.*|^/usr/bin/.*)`)
	writeAllowedPaths  = regexp.MustCompile(`(?i)(^/tmp/|^/dev/|^/proc/|^/sys/|^/workspace/|node_modules/|\.npm/|\.cache/|site-packages/|/var/tmp/|/pnpm/store/|pnpm-state\.json|^/usr/local/lib/|^/usr/lib/|(^|/)package(-lock)?\.json$|(^|/)pnpm-lock\.yaml$|(^|/)bun\.lockb?$|\.hm$|^/root/\.config/|^/home/.*?/\.config/|^/root/\.local/|^/home/.*?/\.local/|^/root/\.bun/|^/home/.*?/\.bun/)`)

	execSuspiciousBinaries = regexp.MustCompile(`(?i)(.*?/nc$|.*?/ncat$|.*?/netcat$|^/tmp/.*)`)

	symlinkRegex      = regexp.MustCompile(`(?i)(?:symlink|symlinkat)\("(.*?)",\s*(?:\d+,\s*)?"(.*?)"`)
	memfdRegex        = regexp.MustCompile(`(?i)memfd_create\("(.*?)"`)
	ptraceAttachRegex = regexp.MustCompile(`(?i)ptrace\(PTRACE_(?:ATTACH|SEIZE)`)
	bindListenRegex   = regexp.MustCompile(`(?:bind|listen)\(\d+,\s*\{sa_family=AF_INET6?,\s*sin6?_port=htons\((\d+)\)`)

	// Environment variable theft — reading /proc/self/environ
	procEnvironRegex = regexp.MustCompile(`(?i)open(?:at)?\(.*?"/proc/self/environ"`)
)

// ParseOptions configures the parser for the current scan context.
type ParseOptions struct {
	// KnownRegistryIPs maps IP addresses to their registry hostname.
	// Connections to these IPs are classified as EXTERNAL_NETWORK_REGISTRY.
	KnownRegistryIPs map[string]string
}

func ParseStream(r io.Reader, reporter *report.Reporter, opts ParseOptions) ([]report.Finding, error) {
	scanner := bufio.NewScanner(r)
	var findings []report.Finding
	probePhase := false
	targetPhase := false
	seen := map[string]bool{} // deduplication key

	if opts.KnownRegistryIPs == nil {
		opts.KnownRegistryIPs = map[string]string{}
	}

	for scanner.Scan() {
		line := scanner.Text()

		if strings.Contains(line, "GOAUDIT_RUNTIME_ERROR:missing_tool:") {
			tool := strings.TrimSpace(strings.TrimPrefix(line[strings.Index(line, "GOAUDIT_RUNTIME_ERROR:missing_tool:"):], "GOAUDIT_RUNTIME_ERROR:missing_tool:"))
			f := report.Finding{Severity: report.SeverityWarning, Type: "runtime", ReasonCode: "RUNTIME_MISSING_TOOL", Path: tool, Confidence: 90}
			findings = append(findings, f)
			reporter.PrintLiveFinding(f)
			continue
		}
		if strings.Contains(line, "GOAUDIT_RUNTIME_ERROR:prep_failed") {
			f := report.Finding{Severity: report.SeverityWarning, Type: "runtime", ReasonCode: "RUNTIME_PREP_FAILURE", Path: "sandbox prep failed", Confidence: 90}
			findings = append(findings, f)
			reporter.PrintLiveFinding(f)
			continue
		}
		if strings.Contains(line, "GOAUDIT_RUNTIME_META:") {
			meta := strings.TrimSpace(line[strings.Index(line, "GOAUDIT_RUNTIME_META:")+len("GOAUDIT_RUNTIME_META:"):])
			if strings.Contains(meta, "phase=probe") {
				probePhase = true
			}
			if strings.Contains(meta, "phase=target") {
				targetPhase = true
			}
			f := report.Finding{Severity: report.SeverityInfo, Type: "runtime", ReasonCode: "RUNTIME_METADATA", Path: "sandbox", Confidence: 90, Evidence: meta}
			findings = append(findings, f)
			reporter.PrintLiveFinding(f)
			continue
		}
		if strings.Contains(line, "GOAUDIT_TARGET_EXIT:") {
			raw := strings.TrimSpace(line[strings.Index(line, "GOAUDIT_TARGET_EXIT:")+len("GOAUDIT_TARGET_EXIT:"):])
			code, err := strconv.Atoi(raw)
			if err != nil {
				continue
			}
			if code != 0 {
				rc := "TARGET_COMMAND_FAILED"
				if code == 127 {
					rc = "TARGET_COMMAND_NOT_FOUND"
				}
				f := report.Finding{Severity: report.SeverityWarning, Type: "runtime", ReasonCode: rc, Path: strconv.Itoa(code), Confidence: 95, Evidence: "Target command returned non-zero exit status in sandbox"}
				findings = append(findings, f)
				reporter.PrintLiveFinding(f)
			}
			continue
		}

		// --- /proc/self/environ theft ---
		if procEnvironRegex.MatchString(line) {
			key := "ENV_THEFT"
			if !seen[key] {
				seen[key] = true
				f := report.Finding{Severity: report.SeverityCritical, Type: "fs_read", ReasonCode: "ENV_THEFT", Path: "/proc/self/environ", Confidence: 95, Evidence: "Read /proc/self/environ to steal CI secrets and environment variables"}
				findings = append(findings, f)
				reporter.PrintLiveFinding(f)
			}
			continue
		}

		// --- File Access ---
		if fsMatches := fsRegex.FindStringSubmatch(line); len(fsMatches) > 2 {
			path := fsMatches[1]
			flags := fsMatches[2]
			isWrite := strings.Contains(flags, "O_WRONLY") || strings.Contains(flags, "O_RDWR") || strings.Contains(flags, "O_CREAT")

			if !isWrite {
				if readCriticalPaths.MatchString(path) {
					key := "CREDENTIAL_READ:" + path
					if !seen[key] {
						seen[key] = true
						f := report.Finding{Severity: report.SeverityCritical, Type: "fs_read", ReasonCode: "CREDENTIAL_READ", Path: path, Confidence: 95}
						findings = append(findings, f)
						reporter.PrintLiveFinding(f)
					}
				}
			} else {
				if writeCriticalPaths.MatchString(path) {
					key := "PERSISTENCE_WRITE:" + path
					if !seen[key] {
						seen[key] = true
						f := report.Finding{Severity: report.SeverityCritical, Type: "fs_write", ReasonCode: "PERSISTENCE_WRITE", Path: path, Confidence: 95}
						findings = append(findings, f)
						reporter.PrintLiveFinding(f)
					}
				} else if !writeAllowedPaths.MatchString(path) {
					key := "UNEXPECTED_WRITE:" + path
					if !seen[key] {
						seen[key] = true
						f := report.Finding{Severity: report.SeverityWarning, Type: "fs_write", ReasonCode: "UNEXPECTED_WRITE", Path: path, Confidence: 70}
						findings = append(findings, f)
						reporter.PrintLiveFinding(f)
					}
				}
			}
			continue
		}

		// --- Exec ---
		if execMatches := execRegex.FindStringSubmatch(line); len(execMatches) > 2 {
			bin := execMatches[1]
			args := execMatches[2]
			isCritical := false
			if execSuspiciousBinaries.MatchString(bin) {
				isCritical = true
			} else if (strings.HasSuffix(bin, "/bash") || strings.HasSuffix(bin, "/sh")) && (strings.Contains(args, "-i") || strings.Contains(args, "/dev/tcp")) {
				isCritical = true
			}
			if isCritical {
				key := "SUSPICIOUS_EXEC:" + bin
				if !seen[key] {
					seen[key] = true
					f := report.Finding{Severity: report.SeverityCritical, Type: "exec", ReasonCode: "SUSPICIOUS_EXEC", Path: bin + " " + args, Confidence: 90}
					findings = append(findings, f)
					reporter.PrintLiveFinding(f)
				}
			}
			continue
		}

		// --- Mutation ---
		if mutMatches := mutRegex.FindStringSubmatch(line); len(mutMatches) > 1 {
			path := mutMatches[1]
			if path != "" && writeCriticalPaths.MatchString(path) {
				key := "PERSISTENCE_WRITE:" + path
				if !seen[key] {
					seen[key] = true
					f := report.Finding{Severity: report.SeverityCritical, Type: "fs_write", ReasonCode: "PERSISTENCE_WRITE", Path: path, Confidence: 90}
					findings = append(findings, f)
					reporter.PrintLiveFinding(f)
				}
			}
			continue
		}

		// --- Privilege escalation ---
		if privMatches := privRegex.FindStringSubmatch(line); len(privMatches) > 1 {
			if privMatches[1] == "0" && targetPhase {
				key := "PRIVILEGE_ESCALATION"
				if !seen[key] {
					seen[key] = true
					f := report.Finding{Severity: report.SeverityCritical, Type: "privilege", ReasonCode: "PRIVILEGE_ESCALATION", Path: line, Confidence: 92}
					findings = append(findings, f)
					reporter.PrintLiveFinding(f)
				}
			}
			continue
		}

		// --- Symlink ---
		if symlinkMatches := symlinkRegex.FindStringSubmatch(line); len(symlinkMatches) > 2 {
			target := symlinkMatches[1]
			linkPath := symlinkMatches[2]
			if readCriticalPaths.MatchString(target) || writeCriticalPaths.MatchString(target) ||
				readCriticalPaths.MatchString(linkPath) || writeCriticalPaths.MatchString(linkPath) {
				f := report.Finding{Severity: report.SeverityCritical, Type: "fs_write", ReasonCode: "SYMLINK_SENSITIVE_PATH", Path: linkPath + " -> " + target, Confidence: 90, Evidence: "Symlink created targeting a sensitive file path"}
				findings = append(findings, f)
				reporter.PrintLiveFinding(f)
			}
			continue
		}

		// --- memfd_create ---
		if memfdRegex.MatchString(line) {
			name := ""
			if m := memfdRegex.FindStringSubmatch(line); len(m) > 1 {
				name = m[1]
			}
			f := report.Finding{Severity: report.SeverityCritical, Type: "exec", ReasonCode: "FILELESS_EXEC", Path: name, Confidence: 92, Evidence: "memfd_create detected — possible fileless code execution"}
			findings = append(findings, f)
			reporter.PrintLiveFinding(f)
			continue
		}

		// --- ptrace ---
		if ptraceAttachRegex.MatchString(line) {
			f := report.Finding{Severity: report.SeverityCritical, Type: "exec", ReasonCode: "PROCESS_INJECTION", Path: line, Confidence: 95, Evidence: "ptrace ATTACH/SEIZE detected — possible process injection"}
			findings = append(findings, f)
			reporter.PrintLiveFinding(f)
			continue
		}

		// --- bind/listen ---
		if blMatches := bindListenRegex.FindStringSubmatch(line); len(blMatches) > 1 {
			port, _ := strconv.Atoi(blMatches[1])
			if port > 0 {
				f := report.Finding{Severity: report.SeverityWarning, Type: "network", ReasonCode: "BACKDOOR_LISTENER", Port: port, Confidence: 80, Evidence: "Process binding/listening on a network port inside sandbox"}
				findings = append(findings, f)
				reporter.PrintLiveFinding(f)
			}
			continue
		}

		// --- Network connections ---
		if netMatches := netRegex.FindStringSubmatch(line); len(netMatches) > 2 {
			port, _ := strconv.Atoi(netMatches[1])
			if port == 0 {
				continue
			}
			ipStr := netMatches[2]
			if ipStr == "" && len(netMatches) > 3 {
				ipStr = netMatches[3]
			}
			if ipStr == "" {
				continue
			}
			ip := net.ParseIP(ipStr)
			if ip != nil && (ip.IsLoopback() || ip.String() == "127.0.0.1" || ip.String() == "::1") {
				continue
			}

			// Deduplicate by IP:Port
			dedupKey := fmt.Sprintf("NET:%s:%d", ipStr, port)
			if seen[dedupKey] {
				continue
			}
			seen[dedupKey] = true

			// Classify: known registry or unknown host
			host := ipStr
			reasonCode := "EXTERNAL_NETWORK"
			severity := report.SeverityWarning

			if registryHost, ok := opts.KnownRegistryIPs[ipStr]; ok {
				host = registryHost
				reasonCode = "EXTERNAL_NETWORK_REGISTRY"
				severity = report.SeverityInfo
			} else if names, err := net.LookupAddr(ipStr); err == nil && len(names) > 0 {
				host = strings.TrimSuffix(names[0], ".")
			}

			f := report.Finding{Severity: severity, Type: "network", ReasonCode: reasonCode, Host: host, Port: port, IP: ipStr, Confidence: 60}
			findings = append(findings, f)
			reporter.PrintLiveFinding(f)
		}
	}

	// Annotate probe-phase findings
	if probePhase {
		probeStart := -1
		for i, f := range findings {
			if f.ReasonCode == "RUNTIME_METADATA" && strings.Contains(f.Evidence, "phase=probe") {
				probeStart = i
				break
			}
		}
		if probeStart >= 0 {
			for i := probeStart + 1; i < len(findings); i++ {
				if findings[i].Severity != report.SeverityInfo {
					findings[i].Evidence += " [runtime probe]"
					if findings[i].Confidence < 95 {
						findings[i].Confidence += 5
					}
				}
			}
		}
	}

	return findings, scanner.Err()
}
