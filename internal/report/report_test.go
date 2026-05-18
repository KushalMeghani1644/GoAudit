package report

import "testing"

func TestEvaluateMaliciousForCredentialRead(t *testing.T) {
	verdict, confidence := Evaluate([]Finding{
		{Severity: SeverityCritical, ReasonCode: "CREDENTIAL_READ"},
	})
	if verdict != VerdictMalicious {
		t.Fatalf("expected malicious verdict, got %s", verdict)
	}
	if confidence < 80 {
		t.Fatalf("expected high confidence, got %d", confidence)
	}
}

func TestEvaluateSuspiciousForCurlPipeShellOnly(t *testing.T) {
	verdict, _ := Evaluate([]Finding{
		{Severity: SeverityWarning, ReasonCode: "CURL_PIPE_SHELL"},
	})
	if verdict != VerdictSuspicious {
		t.Fatalf("expected suspicious verdict, got %s", verdict)
	}
}

func TestEvaluateInconclusiveForRuntimeIssue(t *testing.T) {
	verdict, _ := Evaluate([]Finding{
		{Severity: SeverityWarning, ReasonCode: "RUNTIME_MISSING_TOOL"},
	})
	if verdict != VerdictInconclusive {
		t.Fatalf("expected inconclusive verdict, got %s", verdict)
	}
}

func TestEvaluateInconclusiveForTargetFailure(t *testing.T) {
	verdict, _ := Evaluate([]Finding{
		{Severity: SeverityWarning, ReasonCode: "TARGET_COMMAND_NOT_FOUND"},
	})
	if verdict != VerdictInconclusive {
		t.Fatalf("expected inconclusive verdict, got %s", verdict)
	}
}
