package sandbox

import (
	"context"

	"github.com/docker/docker/api/types/system"
	"github.com/docker/docker/client"
)

// NodeSandboxImage is the published Node sandbox image used for gVisor scans.
const NodeSandboxImage = "ghcr.io/kushalmeghani1644/goaudit-node-sandbox:latest"

// DefaultNodeImage is the stock Node image used when runc is selected or user overrides.
const DefaultNodeImage = "node:current-slim"

// DefaultBunImage is the stock Bun image used when runc is selected or user overrides.
const DefaultBunImage = "oven/bun:1"

// RuntimeFromDockerInfo returns "runsc" only when Docker has registered that runtime.
func RuntimeFromDockerInfo(runtimes map[string]system.RuntimeWithStatus) string {
	if _, ok := runtimes["runsc"]; ok {
		return "runsc"
	}
	return ""
}

// RunscAvailable reports whether Docker lists runsc in docker info Runtimes.
func RunscAvailable(ctx context.Context) bool {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return false
	}
	defer cli.Close()
	info, err := cli.Info(ctx)
	if err != nil {
		return false
	}
	return RuntimeFromDockerInfo(info.Runtimes) == "runsc"
}

func detectRuntime(ctx context.Context, cli *client.Client) string {
	info, err := cli.Info(ctx)
	if err != nil {
		return ""
	}
	return RuntimeFromDockerInfo(info.Runtimes)
}
