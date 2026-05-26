package parser

import (
	"strings"
	"testing"

	"github.com/KushalMeghani1644/goaudit/internal/report"
)

func TestParseStreamDetectsRuntimeMissingTool(t *testing.T) {
	rep := report.NewReporter(true, false)
	logs := "GOAUDIT_RUNTIME_ERROR:missing_tool:curl\n"
	findings, err := ParseStream(strings.NewReader(logs), rep, ParseOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	if findings[0].ReasonCode != "RUNTIME_MISSING_TOOL" {
		t.Fatalf("expected runtime missing tool reason, got %s", findings[0].ReasonCode)
	}
}

func TestParseStreamDetectsTargetExitFailure(t *testing.T) {
	rep := report.NewReporter(true, false)
	logs := "GOAUDIT_TARGET_EXIT:127\n"
	findings, err := ParseStream(strings.NewReader(logs), rep, ParseOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	if findings[0].ReasonCode != "TARGET_COMMAND_NOT_FOUND" {
		t.Fatalf("expected target command not found reason, got %s", findings[0].ReasonCode)
	}
}
