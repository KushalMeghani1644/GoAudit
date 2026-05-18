package cmd

import "testing"

func TestInferProfileForPackageManagers(t *testing.T) {
	nodeImage = "node:current-slim"
	bunImage = "oven/bun:1"

	npm := inferProfile("npm install lodash")
	if npm.Name != "npm" || npm.Image != nodeImage {
		t.Fatalf("unexpected npm profile: %#v", npm)
	}

	pnpm := inferProfile("pnpm add lodash")
	if pnpm.Name != "pnpm" || pnpm.Image != nodeImage {
		t.Fatalf("unexpected pnpm profile: %#v", pnpm)
	}
	if len(pnpm.SetupCommands) == 0 {
		t.Fatalf("expected pnpm setup commands")
	}

	bun := inferProfile("bun add lodash")
	if bun.Name != "bun" || bun.Image != bunImage {
		t.Fatalf("unexpected bun profile: %#v", bun)
	}
}
