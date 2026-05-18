package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/KushalMeghani1644/goaudit/internal/analyzer"
	"github.com/KushalMeghani1644/goaudit/internal/parser"
	"github.com/KushalMeghani1644/goaudit/internal/report"
	"github.com/KushalMeghani1644/goaudit/internal/sandbox"
	"github.com/spf13/cobra"
)

var ciMode bool
var maxRemoteDepth int
var offlineMode bool
var allowedDomains []string
var nodeImage string
var bunImage string

type scanProfile struct {
	Name          string
	Image         string
	RequiredTools []string
	SetupCommands []string
}

var scanCmd = &cobra.Command{
	Use:   "scan <command>",
	Short: "Scan a command inside a gVisor sandbox",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		targetCmd := strings.Join(args, " ")
		profile := inferProfile(targetCmd)

		ctx := context.Background()

		reporter := report.NewReporter(ciMode)
		findings := analyzer.AnalyzeCommand(targetCmd)
		for _, f := range findings {
			reporter.PrintLiveFinding(f)
		}

		jsFindings := analyzer.AnalyzeJSPackageManagers(targetCmd)
		findings = append(findings, jsFindings...)
		for _, f := range jsFindings {
			reporter.PrintLiveFinding(f)
		}

		if urls := analyzer.ExtractURLs(targetCmd); len(urls) > 0 {
			if offlineMode {
				f := report.Finding{
					Severity:   report.SeverityWarning,
					Type:       "policy",
					ReasonCode: "INCONCLUSIVE_REMOTE_FETCH",
					Path:       strings.Join(urls, ","),
					Confidence: 35,
					Evidence:   "Offline mode disabled remote script retrieval",
				}
				findings = append(findings, f)
				reporter.PrintLiveFinding(f)
			} else {
				scriptFindings := analyzer.AnalyzeRemoteScriptsWithPolicy(urls, maxRemoteDepth, allowedDomains)
				findings = append(findings, scriptFindings...)
				for _, f := range scriptFindings {
					reporter.PrintLiveFinding(f)
				}
			}
		}

		if !ciMode {
			fmt.Printf("Pulling sandbox image %s (one-time setup)...\n", profile.Image)
		}

		s, err := sandbox.NewSandbox(ctx, profile.Image)
		if err != nil {
			reporter.Fatalf("Failed to initialize sandbox: %v\n", err)
		}

		if err := s.EnsureImage(ctx); err != nil {
			reporter.Fatalf("Failed to pull image: %v\n", err)
		}

		if s.Runtime() != "runsc" && !ciMode {
			fmt.Println("\n\033[33m[WARNING] 'runsc' (gVisor) runtime not found in Docker. Falling back to default runtime (runc).\033[0m")
			fmt.Println("\033[33mFor proper sandboxing, it is highly recommended to install gVisor and configure it in Docker.\033[0m")
			fmt.Println()
		}

		if !ciMode {
			fmt.Println("Running command in sandbox:", targetCmd)
		}

		logStream, err := s.RunCommand(ctx, targetCmd, profile.Name, profile.Image, profile.RequiredTools, profile.SetupCommands)
		if err != nil {
			s.Cleanup(ctx)
			reporter.Fatalf("Failed to run command: %v\n", err)
		}

		dynamicFindings, err := parser.ParseStream(logStream, reporter)
		if err != nil {
			s.Cleanup(ctx)
			reporter.Fatalf("Failed to parse output: %v\n", err)
		}
		findings = append(findings, dynamicFindings...)

		s.Cleanup(ctx)
		reporter.Report(findings)
	},
}

func inferProfile(cmd string) scanProfile {
	lc := strings.ToLower(cmd)
	switch {
	case strings.Contains(lc, "pnpm"):
		return scanProfile{
			Name:          "pnpm",
			Image:         nodeImage,
			RequiredTools: []string{"bash", "strace", "node", "npm", "pnpm", "curl"},
			SetupCommands: []string{
				"command -v corepack >/dev/null 2>&1 && corepack enable >/dev/null 2>&1 || true",
				"command -v corepack >/dev/null 2>&1 && corepack prepare pnpm@latest --activate >/dev/null 2>&1 || true",
				"command -v pnpm >/dev/null 2>&1 || npm install -g pnpm@latest >/dev/null 2>&1 || true",
			},
		}
	case strings.Contains(lc, "bun"):
		return scanProfile{
			Name:          "bun",
			Image:         bunImage,
			RequiredTools: []string{"bash", "strace", "bun", "curl"},
		}
	case strings.Contains(lc, "npm") || strings.Contains(lc, "npx"):
		return scanProfile{
			Name:          "npm",
			Image:         nodeImage,
			RequiredTools: []string{"bash", "strace", "node", "npm", "curl"},
		}
	case strings.Contains(lc, "pip") || strings.Contains(lc, "python"):
		return scanProfile{
			Name:          "python",
			Image:         "python:3.12-slim",
			RequiredTools: []string{"bash", "strace", "python3", "curl"},
		}
	case strings.Contains(lc, "curl") || strings.Contains(lc, "bash"):
		return scanProfile{
			Name:          "shell",
			Image:         "ubuntu:24.04",
			RequiredTools: []string{"bash", "strace", "curl"},
		}
	default:
		return scanProfile{
			Name:          "default",
			Image:         "ubuntu:24.04",
			RequiredTools: []string{"bash", "strace", "curl"},
		}
	}
}

func init() {
	scanCmd.Flags().BoolVar(&ciMode, "ci", false, "Output JSON for CI integration")
	scanCmd.Flags().IntVar(&maxRemoteDepth, "max-remote-depth", 2, "Max recursion depth when fetching staged remote scripts")
	scanCmd.Flags().BoolVar(&offlineMode, "offline", false, "Disable remote URL/script fetching during static analysis")
	scanCmd.Flags().StringSliceVar(&allowedDomains, "allow-domain", nil, "Allowlist domains for remote script fetches (repeatable)")
	scanCmd.Flags().StringVar(&nodeImage, "node-image", "node:current-slim", "Node.js image used for npm/pnpm scans")
	scanCmd.Flags().StringVar(&bunImage, "bun-image", "oven/bun:1", "Bun image used for bun scans")
	rootCmd.AddCommand(scanCmd)
}
