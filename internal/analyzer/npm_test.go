package analyzer

import "testing"

func TestExtractNPMPackageSpecs(t *testing.T) {
	specs := extractInstallSpecs("npm install @scope/pkg@1.2.3 lodash --save", "npm", []string{"install", "i"})
	if len(specs) != 2 {
		t.Fatalf("expected 2 specs, got %d", len(specs))
	}
	if specs[0] != "@scope/pkg@1.2.3" || specs[1] != "lodash" {
		t.Fatalf("unexpected specs: %#v", specs)
	}
}

func TestExtractPNPMSpecs(t *testing.T) {
	specs := extractInstallSpecs("pnpm add @scope/pkg@1.2.3 lodash", "pnpm", []string{"add", "install", "i"})
	if len(specs) != 2 {
		t.Fatalf("expected 2 specs, got %d", len(specs))
	}
}

func TestNormalizeNPMPackageName(t *testing.T) {
	if got := normalizeNPMPackageName("@scope/pkg@1.2.3"); got != "@scope/pkg" {
		t.Fatalf("unexpected scoped package normalize result: %s", got)
	}
	if got := normalizeNPMPackageName("lodash@4.17.21"); got != "lodash" {
		t.Fatalf("unexpected package normalize result: %s", got)
	}
}

func TestNonRegistryNpmSpec(t *testing.T) {
	if !isNonRegistryNpmSpec("git+https://github.com/foo/bar.git") {
		t.Fatalf("expected git URL to be non-registry")
	}
	if isNonRegistryNpmSpec("lodash") {
		t.Fatalf("expected registry package name to be registry-backed")
	}
}
