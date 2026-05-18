package analyzer

import "testing"

func TestAnalyzeCommandDetectsCurlPipeShell(t *testing.T) {
	findings := AnalyzeCommand("curl -fsSL https://example.com/install.sh | sh")
	if len(findings) == 0 {
		t.Fatalf("expected findings for curl|sh")
	}
	found := false
	for _, f := range findings {
		if f.ReasonCode == "CURL_PIPE_SHELL" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected CURL_PIPE_SHELL finding")
	}
}

func TestAnalyzeCommandDetectsNPMLifecycleRisk(t *testing.T) {
	findings := AnalyzeCommand("npm install")
	found := false
	for _, f := range findings {
		if f.ReasonCode == "NPM_LIFECYCLE_SCRIPTS" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected NPM_LIFECYCLE_SCRIPTS finding")
	}
}

func TestAnalyzeCommandDetectsPNPMLifecycleRisk(t *testing.T) {
	findings := AnalyzeCommand("pnpm add lodash")
	found := false
	for _, f := range findings {
		if f.ReasonCode == "PNPM_LIFECYCLE_SCRIPTS" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected PNPM_LIFECYCLE_SCRIPTS finding")
	}
}

func TestAnalyzeCommandDetectsBUNLifecycleRisk(t *testing.T) {
	findings := AnalyzeCommand("bun add lodash")
	found := false
	for _, f := range findings {
		if f.ReasonCode == "BUN_INSTALL_SCRIPTS" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected BUN_INSTALL_SCRIPTS finding")
	}
}
