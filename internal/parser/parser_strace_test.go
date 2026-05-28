package parser

import (
	"strings"
	"testing"

	"github.com/KushalMeghani1644/GoAudit-CLI/internal/report"
)

func parse(t *testing.T, input string) []report.Finding {
	t.Helper()
	rep := report.NewReporter(true, false)
	findings, err := ParseStream(strings.NewReader(input), rep, ParseOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return findings
}

func findByReason(findings []report.Finding, reason string) *report.Finding {
	for i := range findings {
		if findings[i].ReasonCode == reason {
			return &findings[i]
		}
	}
	return nil
}

func TestDetectsCredentialReadAWS(t *testing.T) {
	f := findByReason(parse(t,
		`openat(AT_FDCWD, "/root/.aws/credentials", O_RDONLY) = 3`),
		"CREDENTIAL_READ")
	if f == nil {
		t.Fatal("expected CREDENTIAL_READ for .aws/credentials")
	}
}

func TestDetectsCredentialReadSSH(t *testing.T) {
	f := findByReason(parse(t,
		`openat(AT_FDCWD, "/home/user/.ssh/id_rsa", O_RDONLY) = 3`),
		"CREDENTIAL_READ")
	if f == nil {
		t.Fatal("expected CREDENTIAL_READ for .ssh/id_rsa")
	}
}

func TestDetectsCredentialReadEnv(t *testing.T) {
	f := findByReason(parse(t,
		`openat(AT_FDCWD, "/home/sandbox/.env", O_RDONLY) = 3`),
		"CREDENTIAL_READ")
	if f == nil {
		t.Fatal("expected CREDENTIAL_READ for .env")
	}
}

func TestDetectsPersistenceWriteBashrc(t *testing.T) {
	f := findByReason(parse(t,
		`openat(AT_FDCWD, "/root/.bashrc", O_WRONLY|O_CREAT) = 3`),
		"PERSISTENCE_WRITE")
	if f == nil {
		t.Fatal("expected PERSISTENCE_WRITE for .bashrc")
	}
}

func TestDetectsPersistenceWriteCron(t *testing.T) {
	f := findByReason(parse(t,
		`openat(AT_FDCWD, "/etc/cron.d/backdoor", O_WRONLY|O_CREAT) = 3`),
		"PERSISTENCE_WRITE")
	if f == nil {
		t.Fatal("expected PERSISTENCE_WRITE for /etc/cron.d/")
	}
}

func TestAllowedWriteNotFlagged(t *testing.T) {
	findings := parse(t, `openat(AT_FDCWD, "/tmp/npm-cache/file", O_WRONLY|O_CREAT) = 3`)
	for _, f := range findings {
		if f.ReasonCode == "UNEXPECTED_WRITE" || f.ReasonCode == "PERSISTENCE_WRITE" {
			t.Fatalf("should not flag /tmp/ writes, got %s", f.ReasonCode)
		}
	}
}

func TestAllowedWriteNodeModules(t *testing.T) {
	findings := parse(t, `openat(AT_FDCWD, "/workspace/node_modules/lodash/index.js", O_WRONLY|O_CREAT) = 3`)
	for _, f := range findings {
		if f.ReasonCode == "UNEXPECTED_WRITE" {
			t.Fatal("should not flag node_modules writes")
		}
	}
}

func TestUnexpectedWriteFlagged(t *testing.T) {
	f := findByReason(parse(t,
		`openat(AT_FDCWD, "/opt/evil/backdoor.sh", O_WRONLY|O_CREAT) = 3`),
		"UNEXPECTED_WRITE")
	if f == nil {
		t.Fatal("expected UNEXPECTED_WRITE for unusual path")
	}
}

func TestDetectsSuspiciousExecNetcat(t *testing.T) {
	f := findByReason(parse(t,
		`execve("/usr/bin/nc", ["nc", "-e", "/bin/bash"]`),
		"SUSPICIOUS_EXEC")
	if f == nil {
		t.Fatal("expected SUSPICIOUS_EXEC for netcat")
	}
}

func TestDetectsSuspiciousExecFromTmp(t *testing.T) {
	f := findByReason(parse(t,
		`execve("/tmp/payload", ["/tmp/payload"]`),
		"SUSPICIOUS_EXEC")
	if f == nil {
		t.Fatal("expected SUSPICIOUS_EXEC for /tmp/ binary")
	}
}

func TestDetectsPrivilegeEscalation(t *testing.T) {
	input := "GOAUDIT_RUNTIME_META:phase=target\nsetuid(0) = 0"
	f := findByReason(parse(t, input), "PRIVILEGE_ESCALATION")
	if f == nil {
		t.Fatal("expected PRIVILEGE_ESCALATION for setuid(0) after target phase")
	}
}

func TestSetuidBeforeTargetPhaseNotFlagged(t *testing.T) {
	// setuid(0) from su/PAM happens before phase=target and should be ignored.
	for _, f := range parse(t, `setuid(0) = 0`) {
		if f.ReasonCode == "PRIVILEGE_ESCALATION" {
			t.Fatal("should not flag setuid(0) before target phase (su/PAM noise)")
		}
	}
}

func TestNonRootSetuidNotFlagged(t *testing.T) {
	input := "GOAUDIT_RUNTIME_META:phase=target\nsetuid(1000) = 0"
	for _, f := range parse(t, input) {
		if f.ReasonCode == "PRIVILEGE_ESCALATION" {
			t.Fatal("should not flag setuid to non-root")
		}
	}
}

func TestDetectsExternalNetwork(t *testing.T) {
	f := findByReason(parse(t,
		`connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("104.16.23.35")}, 16) = 0`),
		"EXTERNAL_NETWORK")
	if f == nil {
		t.Fatal("expected EXTERNAL_NETWORK")
	}
}

func TestLoopbackNotFlagged(t *testing.T) {
	for _, f := range parse(t,
		`connect(3, {sa_family=AF_INET, sin_port=htons(3000), sin_addr=inet_addr("127.0.0.1")}, 16) = 0`) {
		if f.ReasonCode == "EXTERNAL_NETWORK" {
			t.Fatal("should not flag loopback")
		}
	}
}

func TestDetectsSymlinkToCredentials(t *testing.T) {
	f := findByReason(parse(t,
		`symlink("/root/.aws/credentials", "/tmp/link") = 0`),
		"SYMLINK_SENSITIVE_PATH")
	if f == nil {
		t.Fatal("expected SYMLINK_SENSITIVE_PATH")
	}
}

func TestDetectsMemfdCreate(t *testing.T) {
	f := findByReason(parse(t,
		`memfd_create("jit-code", MFD_CLOEXEC) = 3`),
		"FILELESS_EXEC")
	if f == nil {
		t.Fatal("expected FILELESS_EXEC")
	}
}

func TestDetectsPtraceAttach(t *testing.T) {
	f := findByReason(parse(t,
		`ptrace(PTRACE_ATTACH, 1234) = 0`),
		"PROCESS_INJECTION")
	if f == nil {
		t.Fatal("expected PROCESS_INJECTION")
	}
}

func TestDetectsBackdoorListener(t *testing.T) {
	f := findByReason(parse(t,
		`bind(3, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("0.0.0.0")}, 16) = 0`),
		"BACKDOOR_LISTENER")
	if f == nil {
		t.Fatal("expected BACKDOOR_LISTENER")
	}
}

func TestDetectsChmodOnCriticalPath(t *testing.T) {
	f := findByReason(parse(t,
		`chmod("/usr/local/bin/evil", 0755) = 0`),
		"PERSISTENCE_WRITE")
	if f == nil {
		t.Fatal("expected PERSISTENCE_WRITE for chmod")
	}
}

func TestProbePhaseBoostsConfidence(t *testing.T) {
	input := "GOAUDIT_RUNTIME_META:phase=probe\n" +
		`openat(AT_FDCWD, "/root/.aws/credentials", O_RDONLY) = 3`
	findings := parse(t, input)
	f := findByReason(findings, "CREDENTIAL_READ")
	if f == nil {
		t.Fatal("expected CREDENTIAL_READ")
	}
	if !strings.Contains(f.Evidence, "[runtime probe]") {
		t.Fatalf("expected probe annotation, got %q", f.Evidence)
	}
}
