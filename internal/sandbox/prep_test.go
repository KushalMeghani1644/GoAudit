package sandbox

import (
	"strings"
	"testing"
)

func TestAptPrepScriptSkipsWhenToolsPresent(t *testing.T) {
	if !strings.Contains(aptPrepScript, "command -v strace") {
		t.Fatal("expected conditional strace check")
	}
	if !strings.Contains(aptPrepScript, "command -v rsync") {
		t.Fatal("expected conditional rsync check")
	}
	if !strings.Contains(aptPrepScript, "apt-get update") {
		t.Fatal("expected apt-get when tools missing")
	}
}
