package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/KushalMeghani1644/goaudit/internal/parser"
	"github.com/KushalMeghani1644/goaudit/internal/report"
	"github.com/KushalMeghani1644/goaudit/internal/sandbox"
	"github.com/spf13/cobra"
)

var ciMode bool

var scanCmd = &cobra.Command{
	Use:   "scan <command>",
	Short: "Scan a command inside a gVisor sandbox",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		targetCmd := strings.Join(args, " ")
		
		image := inferImage(targetCmd)

		ctx := context.Background()

		reporter := report.NewReporter(ciMode)

		if !ciMode {
			fmt.Printf("Pulling sandbox image %s (one-time setup)...\n", image)
		}

		s, err := sandbox.NewSandbox(ctx, image)
		if err != nil {
			reporter.Fatalf("Failed to initialize sandbox: %v\n", err)
		}

		if err := s.EnsureImage(ctx); err != nil {
			reporter.Fatalf("Failed to pull image: %v\n", err)
		}

		if s.Runtime() != "runsc" && !ciMode {
			fmt.Println("\n\033[33m[WARNING] 'runsc' (gVisor) runtime not found in Docker. Falling back to default runtime (runc).\033[0m")
			fmt.Println("\033[33mFor proper sandboxing, it is highly recommended to install gVisor and configure it in Docker.\033[0m\n")
		}

		if !ciMode {
			fmt.Println("Running command in sandbox:", targetCmd)
		}

		logStream, err := s.RunCommand(ctx, targetCmd)
		if err != nil {
			s.Cleanup(ctx)
			reporter.Fatalf("Failed to run command: %v\n", err)
		}

		findings, err := parser.ParseStream(logStream, reporter)
		if err != nil {
			s.Cleanup(ctx)
			reporter.Fatalf("Failed to parse output: %v\n", err)
		}

		s.Cleanup(ctx)
		reporter.Report(findings)
	},
}

func inferImage(cmd string) string {
	switch {
	case strings.Contains(cmd, "npm") || strings.Contains(cmd, "npx"):
		return "node:20-slim"
	case strings.Contains(cmd, "pip") || strings.Contains(cmd, "python"):
		return "python:3.12-slim"
	case strings.Contains(cmd, "curl") || strings.Contains(cmd, "bash"):
		return "ubuntu:24.04"
	default:
		return "ubuntu:24.04"
	}
}

func init() {
	scanCmd.Flags().BoolVar(&ciMode, "ci", false, "Output JSON for CI integration")
	rootCmd.AddCommand(scanCmd)
}
