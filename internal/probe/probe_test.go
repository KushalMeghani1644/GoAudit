package probe

import (
	"strings"
	"testing"
)

func TestGenerateNodeProbeScriptEmpty(t *testing.T) {
	if got := GenerateNodeProbeScript(nil, 15); got != "" {
		t.Fatalf("expected empty for nil packages, got %q", got)
	}
}

func TestGenerateNodeProbeScriptSinglePackage(t *testing.T) {
	script := GenerateNodeProbeScript([]string{"lodash"}, 15)
	if !strings.Contains(script, `"lodash"`) {
		t.Fatal("expected lodash in probe script")
	}
	if !strings.Contains(script, "phase=probe") {
		t.Fatal("expected phase=probe marker")
	}
	if !strings.Contains(script, "require(") {
		t.Fatal("expected require() call")
	}
	if !strings.Contains(script, "timeout 17") {
		t.Fatalf("expected timeout 17 (15+2), got: %s", script)
	}
}

func TestGenerateNodeProbeScriptScopedPackage(t *testing.T) {
	script := GenerateNodeProbeScript([]string{"@scope/pkg", "lodash"}, 10)
	if !strings.Contains(script, `"@scope/pkg"`) {
		t.Fatal("expected scoped package in probe script")
	}
	if !strings.Contains(script, `"lodash"`) {
		t.Fatal("expected lodash in probe script")
	}
	if !strings.Contains(script, "timeout 12") {
		t.Fatal("expected timeout 12 (10+2)")
	}
}

func TestGenerateNodeProbeScriptDefaultTimeout(t *testing.T) {
	script := GenerateNodeProbeScript([]string{"x"}, 0)
	if !strings.Contains(script, "15000") {
		t.Fatal("expected default 15s timeout in JS")
	}
}
