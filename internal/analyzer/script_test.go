package analyzer

import "testing"

func TestLooksLikeShellScript(t *testing.T) {
	if !looksLikeShellScript("#!/bin/sh\nset -e\ncurl -fsSL https://example.com") {
		t.Fatalf("expected shell script detection to be true")
	}
	if looksLikeShellScript("<html><body>hello</body></html>") {
		t.Fatalf("expected html content to not be treated as shell script")
	}
}

func TestDomainAllowed(t *testing.T) {
	if domainAllowed("https://evil.test/install.sh", []string{"example.com"}) {
		t.Fatalf("expected domain to be blocked")
	}
	if !domainAllowed("https://sub.example.com/install.sh", []string{"example.com"}) {
		t.Fatalf("expected subdomain to be allowed")
	}
}
