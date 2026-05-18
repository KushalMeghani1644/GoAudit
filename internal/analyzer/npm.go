package analyzer

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/KushalMeghani1644/goaudit/internal/report"
)

var npmRegistryBaseURL = "https://registry.npmjs.org"

type npmMetadata struct {
	DistTags map[string]string `json:"dist-tags"`
	Time     struct {
		Created string `json:"created"`
	} `json:"time"`
	Versions map[string]struct {
		Scripts map[string]string `json:"scripts"`
	} `json:"versions"`
}

func AnalyzeJSPackageManagers(command string) []report.Finding {
	var findings []report.Finding
	findings = append(findings, AnalyzeNPMInstall(command)...)
	findings = append(findings, analyzePNPMInstall(command)...)
	findings = append(findings, analyzeBUNAdd(command)...)
	return findings
}

func AnalyzeNPMInstall(command string) []report.Finding {
	specs := extractInstallSpecs(command, "npm", []string{"install", "i"})
	if len(specs) == 0 {
		return nil
	}
	return analyzeRegistryBackedSpecs(specs, "npm")
}

func analyzePNPMInstall(command string) []report.Finding {
	specs := extractInstallSpecs(command, "pnpm", []string{"add", "install", "i"})
	if len(specs) == 0 {
		return nil
	}
	return analyzeRegistryBackedSpecs(specs, "pnpm")
}

func analyzeBUNAdd(command string) []report.Finding {
	specs := extractInstallSpecs(command, "bun", []string{"add"})
	if len(specs) == 0 {
		return nil
	}
	return analyzeRegistryBackedSpecs(specs, "bun")
}

func analyzeRegistryBackedSpecs(specs []string, manager string) []report.Finding {
	client := &http.Client{Timeout: 8 * time.Second}
	var findings []report.Finding
	for i, spec := range specs {
		if i >= 3 {
			break
		}
		if isNonRegistryNpmSpec(spec) {
			findings = append(findings, report.Finding{
				Severity:   report.SeverityWarning,
				Type:       manager,
				ReasonCode: managerReason(manager, "NON_REGISTRY_SOURCE"),
				Path:       spec,
				Confidence: 85,
				Evidence:   "Package source is not a standard npm registry reference",
			})
			continue
		}

		pkg := normalizeNPMPackageName(spec)
		if pkg == "" {
			continue
		}
		meta, err := fetchNPMMetadata(client, pkg)
		if err != nil {
			findings = append(findings, report.Finding{
				Severity:   report.SeverityWarning,
				Type:       manager,
				ReasonCode: managerReason(manager, "INCONCLUSIVE_METADATA"),
				Path:       pkg,
				Confidence: 45,
				Evidence:   err.Error(),
			})
			continue
		}

		latest := meta.DistTags["latest"]
		if latest != "" {
			if version, ok := meta.Versions[latest]; ok {
				for scriptName := range version.Scripts {
					if scriptName == "preinstall" || scriptName == "install" || scriptName == "postinstall" || scriptName == "prepare" {
						findings = append(findings, report.Finding{
							Severity:   report.SeverityWarning,
							Type:       manager,
							ReasonCode: managerReason(manager, "LIFECYCLE_SCRIPT_METADATA"),
							Path:       pkg + "@" + latest,
							Confidence: 80,
							Evidence:   fmt.Sprintf("Latest package version defines %s script", scriptName),
						})
						break
					}
				}
			}
		}

		if meta.Time.Created != "" {
			createdAt, err := time.Parse(time.RFC3339, meta.Time.Created)
			if err == nil && time.Since(createdAt) < 14*24*time.Hour {
				findings = append(findings, report.Finding{
					Severity:   report.SeverityWarning,
					Type:       manager,
					ReasonCode: managerReason(manager, "RECENT_PACKAGE"),
					Path:       pkg,
					Confidence: 70,
					Evidence:   "Package was created recently on npm registry",
				})
			}
		}
	}
	return findings
}

func managerReason(manager, suffix string) string {
	switch strings.ToLower(manager) {
	case "pnpm":
		return "PNPM_" + suffix
	case "bun":
		return "BUN_" + suffix
	default:
		return "NPM_" + suffix
	}
}

func extractInstallSpecs(command, manager string, operations []string) []string {
	parts := strings.Fields(command)
	if len(parts) < 2 || strings.ToLower(parts[0]) != manager {
		return nil
	}

	installIdx := -1
	for i := 1; i < len(parts); i++ {
		for _, op := range operations {
			if parts[i] == op {
				installIdx = i
				break
			}
		}
		if installIdx != -1 {
			break
		}
	}
	if installIdx == -1 {
		return nil
	}

	var specs []string
	for i := installIdx + 1; i < len(parts); i++ {
		p := parts[i]
		if p == "&&" || p == ";" || p == "|" {
			break
		}
		if strings.HasPrefix(p, "-") {
			continue
		}
		specs = append(specs, p)
	}
	return specs
}

func isNonRegistryNpmSpec(spec string) bool {
	return strings.Contains(spec, "://") ||
		strings.HasPrefix(spec, "git+") ||
		strings.Contains(spec, "github.com/") ||
		strings.HasPrefix(spec, "file:")
}

func normalizeNPMPackageName(spec string) string {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return ""
	}
	if strings.HasPrefix(spec, "npm:") {
		spec = strings.TrimPrefix(spec, "npm:")
	}
	if strings.HasPrefix(spec, "@") {
		if strings.Count(spec, "@") > 1 {
			last := strings.LastIndex(spec, "@")
			if last > 0 {
				return spec[:last]
			}
		}
		return spec
	}
	if idx := strings.Index(spec, "@"); idx > 0 {
		return spec[:idx]
	}
	return spec
}

func fetchNPMMetadata(client *http.Client, pkg string) (*npmMetadata, error) {
	escaped := url.PathEscape(pkg)
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(npmRegistryBaseURL, "/")+"/"+escaped, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "goaudit/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("npm registry status: %d", resp.StatusCode)
	}
	var meta npmMetadata
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return nil, err
	}
	return &meta, nil
}
