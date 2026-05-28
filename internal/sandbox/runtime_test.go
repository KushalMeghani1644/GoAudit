package sandbox

import (
	"strings"
	"testing"

	"github.com/docker/docker/api/types/system"
)

func TestRuntimeFromDockerInfo(t *testing.T) {
	if got := RuntimeFromDockerInfo(nil); got != "" {
		t.Fatalf("nil runtimes: got %q", got)
	}
	if got := RuntimeFromDockerInfo(map[string]system.RuntimeWithStatus{"runc": {}}); got != "" {
		t.Fatalf("runc only: got %q", got)
	}
	if got := RuntimeFromDockerInfo(map[string]system.RuntimeWithStatus{"runsc": {}, "runc": {}}); got != "runsc" {
		t.Fatalf("runsc registered: got %q", got)
	}
}

func TestNodeSandboxImageUsesGHCR(t *testing.T) {
	if !strings.HasPrefix(NodeSandboxImage, "ghcr.io/kushalmeghani1644/goaudit-node-sandbox:") {
		t.Fatalf("unexpected node sandbox image: %s", NodeSandboxImage)
	}
}
