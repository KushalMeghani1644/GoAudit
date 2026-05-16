package parser

import (
	"bufio"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/KushalMeghani1644/goaudit/internal/report"
)

var (
	fsRegex  = regexp.MustCompile(`(?i)(?:open|openat).*?\"(.*?/\.env|.*?/\.ssh/.*?|.*?/\.aws/.*?|.*?/\.kube/.*?|.*?id_rsa)\"`)
	netRegex = regexp.MustCompile(`connect\(.*sa_family=AF_INET.*?, sin_port=htons\((\d+)\), sin_addr=inet_addr\("(.*?)"\)`)
)

func ParseStream(r io.Reader, reporter *report.Reporter) ([]report.Finding, error) {
	scanner := bufio.NewScanner(r)
	var findings []report.Finding

	for scanner.Scan() {
		line := scanner.Text()

		// Match File Reads
		if fsMatches := fsRegex.FindStringSubmatch(line); len(fsMatches) > 1 {
			f := report.Finding{
				Severity: report.SeverityCritical,
				Type:     "fs_read",
				Path:     fsMatches[1],
			}
			findings = append(findings, f)
			reporter.PrintLiveFinding(f)
			continue
		}

		// Match Network Connections
		if netMatches := netRegex.FindStringSubmatch(line); len(netMatches) > 2 {
			port, _ := strconv.Atoi(netMatches[1])
			if port == 0 {
				continue
			}

			ipStr := netMatches[2]

			ip := net.ParseIP(ipStr)
			if ip != nil && (ip.IsLoopback() || ip.String() == "127.0.0.1" || ip.String() == "::1") {
				continue
			}

			host := ipStr
			if names, err := net.LookupAddr(ipStr); err == nil && len(names) > 0 {
				host = strings.TrimSuffix(names[0], ".")
			}

			f := report.Finding{
				Severity: report.SeverityWarning,
				Type:     "network",
				Host:     host,
				Port:     port,
				IP:       ipStr,
			}
			findings = append(findings, f)
			reporter.PrintLiveFinding(f)
		}
	}

	return findings, scanner.Err()
}
