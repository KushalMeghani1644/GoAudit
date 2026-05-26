package cmd

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/KushalMeghani1644/goaudit/internal/analyzer"
	"github.com/KushalMeghani1644/goaudit/internal/parser"
	"github.com/KushalMeghani1644/goaudit/internal/probe"
	"github.com/KushalMeghani1644/goaudit/internal/report"
	"github.com/KushalMeghani1644/goaudit/internal/sandbox"
)

type pipelineOptions struct {
	projectPath     string
	skipStatic      bool
	priorFindings   []report.Finding
	allowNetwork    bool
	runAsRoot       bool
	scanProjectMode bool
	probePackages   []string
	skipProbe       bool
}

// resolveRegistryIPs resolves known registry hostnames to IPs for classification.
func resolveRegistryIPs(profileName string) map[string]string {
	registries := []string{"registry.npmjs.org"}
	switch profileName {
	case "pnpm":
		registries = append(registries, "registry.npmmirror.com")
	}
	result := map[string]string{}
	for _, host := range registries {
		ips, err := net.LookupHost(host)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			result[ip] = host
		}
	}
	return result
}

func runScanPipeline(ctx context.Context, targetCmd string, profile scanProfile, reporter *report.Reporter, opts pipelineOptions) {
	findings := append([]report.Finding{}, opts.priorFindings...)

	reporter.StartProgress("Running static analysis...")

	if !opts.skipStatic {
		cmdFindings := analyzer.AnalyzeCommand(targetCmd)
		findings = append(findings, cmdFindings...)
		for _, f := range cmdFindings {
			reporter.PrintLiveFinding(f)
		}

		jsFindings := analyzer.AnalyzeJSPackageManagers(targetCmd)
		findings = append(findings, jsFindings...)
		for _, f := range jsFindings {
			reporter.PrintLiveFinding(f)
		}
	}

	if urls := analyzer.ExtractURLs(targetCmd); len(urls) > 0 && !opts.skipStatic {
		if offlineMode {
			f := report.Finding{
				Severity: report.SeverityWarning, Type: "policy", ReasonCode: "INCONCLUSIVE_REMOTE_FETCH",
				Path: strings.Join(urls, ","), Confidence: 35, Evidence: "Offline mode disabled remote script retrieval",
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

	// Determine network policy
	networkEnabled := opts.allowNetwork
	if networkMode == "auto" {
		switch profile.Name {
		case "npm", "pnpm", "bun":
			networkEnabled = true
		default:
			networkEnabled = false
		}
	} else if networkMode == "on" {
		networkEnabled = true
	} else if networkMode == "off" {
		networkEnabled = false
	}

	// Append runtime probe
	finalCmd := targetCmd
	if len(opts.probePackages) > 0 && !opts.skipProbe && isNodeProfile(profile.Name) {
		probeScript := probe.GenerateNodeProbeScript(opts.probePackages, probe.DefaultTimeoutSec)
		finalCmd = targetCmd + "\n" + probeScript
	}

	reporter.UpdateProgress(fmt.Sprintf("Pulling sandbox image %s...", profile.Image))

	s, err := sandbox.NewSandbox(ctx, profile.Image, sandbox.SandboxOptions{
		NetworkEnabled: networkEnabled,
		RunAsRoot:      opts.runAsRoot,
	})
	if err != nil {
		reporter.StopProgress()
		reporter.Fatalf("Failed to initialize sandbox: %v\n", err)
	}

	if err := s.EnsureImage(ctx); err != nil {
		reporter.StopProgress()
		reporter.Fatalf("Failed to pull image: %v\n", err)
	}

	if s.Runtime() != "runsc" && !ciMode && verbose {
		reporter.StopProgress()
		fmt.Println("\033[33m[WARNING] gVisor (runsc) not found. Using default runtime (runc).\033[0m")
		reporter.StartProgress("Running in sandbox...")
	}

	reporter.UpdateProgress(fmt.Sprintf("Running %s in sandbox...", profile.Name))

	// Resolve registry IPs for network classification
	registryIPs := resolveRegistryIPs(profile.Name)

	var logStream io.Reader
	if opts.projectPath != "" {
		logStream, err = s.RunProjectCommand(ctx, finalCmd, opts.projectPath, profile.Name, profile.Image, profile.RequiredTools, profile.SetupCommands)
	} else {
		logStream, err = s.RunCommand(ctx, finalCmd, profile.Name, profile.Image, profile.RequiredTools, profile.SetupCommands)
	}
	if err != nil {
		s.Cleanup(ctx)
		reporter.StopProgress()
		reporter.Fatalf("Failed to run command: %v\n", err)
	}

	if len(opts.probePackages) > 0 && !opts.skipProbe {
		reporter.UpdateProgress(fmt.Sprintf("Running in sandbox + probing %d package(s)...", len(opts.probePackages)))
	}

	dynamicFindings, err := parser.ParseStream(logStream, reporter, parser.ParseOptions{
		KnownRegistryIPs: registryIPs,
	})
	if err != nil {
		s.Cleanup(ctx)
		reporter.StopProgress()
		reporter.Fatalf("Failed to parse output: %v\n", err)
	}
	findings = append(findings, dynamicFindings...)

	s.Cleanup(ctx)

	meta := report.ReportMeta{
		Command:                  targetCmd,
		ProfileName:              profile.Name,
		SuppressExpectedBehavior: isNodeProfile(profile.Name),
	}
	reporter.Report(findings, meta)
}

func isNodeProfile(name string) bool {
	switch name {
	case "npm", "pnpm", "bun":
		return true
	}
	return false
}

func profileForManager(manager string) scanProfile {
	switch strings.ToLower(manager) {
	case "pnpm":
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
	case "bun":
		return scanProfile{
			Name:          "bun",
			Image:         bunImage,
			RequiredTools: []string{"bash", "strace", "bun", "curl"},
		}
	default:
		return scanProfile{
			Name:          "npm",
			Image:         nodeImage,
			RequiredTools: []string{"bash", "strace", "node", "npm", "curl"},
		}
	}
}
