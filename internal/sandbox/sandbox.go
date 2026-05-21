package sandbox

import (
	"context"
	"fmt"
	"io"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
)

// SandboxOptions controls sandbox security policies.
type SandboxOptions struct {
	NetworkEnabled bool
	RunAsRoot      bool
}

type Sandbox struct {
	cli            *client.Client
	image          string
	containerID    string
	runtime        string
	networkEnabled bool
	runAsRoot      bool
}

func NewSandbox(ctx context.Context, image string, opts SandboxOptions) (*Sandbox, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, err
	}

	info, err := cli.Info(ctx)
	if err != nil {
		return nil, err
	}

	runtime := ""
	if _, ok := info.Runtimes["runsc"]; ok {
		runtime = "runsc"
	}

	return &Sandbox{
		cli:            cli,
		image:          image,
		runtime:        runtime,
		networkEnabled: opts.NetworkEnabled,
		runAsRoot:      opts.RunAsRoot,
	}, nil
}

func (s *Sandbox) Runtime() string        { return s.runtime }
func (s *Sandbox) NetworkEnabled() bool    { return s.networkEnabled }

func (s *Sandbox) EnsureImage(ctx context.Context) error {
	reader, err := s.cli.ImagePull(ctx, s.image, image.PullOptions{})
	if err != nil {
		return err
	}
	defer reader.Close()
	_, _ = io.Copy(io.Discard, reader)
	return nil
}

func (s *Sandbox) RunCommand(ctx context.Context, targetCmd, profileName, image string, requiredTools, setupCommands []string) (io.Reader, error) {
	return s.run(ctx, targetCmd, profileName, image, requiredTools, setupCommands, "")
}

func (s *Sandbox) RunProjectCommand(ctx context.Context, targetCmd, projectPath, profileName, image string, requiredTools, setupCommands []string) (io.Reader, error) {
	return s.run(ctx, targetCmd, profileName, image, requiredTools, setupCommands, projectPath)
}

// StraceTraceSet is the full set of syscalls traced by GoAudit.
const StraceTraceSet = "open,openat,openat2,connect,execve,chmod,fchmod,fchmodat,rename,unlink,unlinkat,setuid,setgid,setreuid,setregid,socket,bind,listen,symlink,symlinkat,memfd_create,ptrace"

func (s *Sandbox) run(ctx context.Context, targetCmd, profileName, image string, requiredTools, setupCommands []string, projectPath string) (io.Reader, error) {
	toolsCheck := ""
	for _, t := range requiredTools {
		toolsCheck += fmt.Sprintf("command -v %s >/dev/null 2>&1 || { echo \"GOAUDIT_RUNTIME_ERROR:missing_tool:%s\" >&2; exit 97; }\n", t, t)
	}
	setupScript := ""
	for _, c := range setupCommands {
		setupScript += c + "\n"
	}

	projectStage := "mkdir -p /workspace\ncd /workspace\n"
	if projectPath != "" {
		projectStage = `
if [ ! -d /project-ro ]; then
  echo "GOAUDIT_RUNTIME_ERROR:project_mount_missing" >&2; exit 98
fi
command -v rsync >/dev/null 2>&1 || apt-get install -y -qq --no-install-recommends rsync > /dev/null 2>&1 || { echo "GOAUDIT_RUNTIME_ERROR:prep_failed" >&2; exit 98; }
mkdir -p /workspace
rsync -a --exclude node_modules --exclude .git /project-ro/ /workspace/
cd /workspace
`
	}

	// User setup: detect existing uid 1000 (e.g. "node" in node images) or create sandbox user.
	userSetup := ""
	execLine := ""
	if s.runAsRoot {
		userSetup = `SANDBOX_HOME="/root"
`
		execLine = fmt.Sprintf(
			`strace -s 256 -f -e trace=%s -o /dev/stderr bash /tmp/target.sh`, StraceTraceSet)
	} else {
		userSetup = `SANDBOX_USER=$(getent passwd 1000 2>/dev/null | cut -d: -f1)
if [ -z "$SANDBOX_USER" ]; then
  useradd -m -u 1000 -s /bin/bash sandbox 2>/dev/null || true
  SANDBOX_USER=sandbox
fi
SANDBOX_HOME=$(eval echo "~${SANDBOX_USER}")
`
		execLine = fmt.Sprintf(
			`chown -R 1000:1000 /workspace 2>/dev/null || true
strace -s 256 -f -e trace=%s -o /dev/stderr su "$SANDBOX_USER" -s /bin/bash -c 'cd /workspace && bash /tmp/target.sh'`, StraceTraceSet)
	}

	script := fmt.Sprintf(`set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
if command -v apt-get >/dev/null 2>&1; then
  apt-get update -qq > /dev/null 2>&1 || { echo "GOAUDIT_RUNTIME_ERROR:prep_failed" >&2; exit 98; }
  apt-get install -y -qq --no-install-recommends strace curl ca-certificates dnsutils > /dev/null 2>&1 || { echo "GOAUDIT_RUNTIME_ERROR:prep_failed" >&2; exit 98; }
fi

%s
%s

echo "GOAUDIT_RUNTIME_META:profile=%s;image=%s" >&2
for tool in node npm pnpm bun bash curl strace; do
  if command -v "${tool}" >/dev/null 2>&1; then
    ver="$(${tool} --version 2>/dev/null | head -n1 | tr -d '\r' || true)"
    if [ -n "${ver}" ]; then
      echo "GOAUDIT_RUNTIME_META:tool=${tool};version=${ver}" >&2
    fi
  fi
done

%s
%s
%s
cat << 'EOF_TARGET_CMD' > /tmp/target.sh
echo 'GOAUDIT_RUNTIME_META:phase=target' >&2
%s
EOF_TARGET_CMD
chmod +x /tmp/target.sh

set +e
%s
target_rc=$?
set -e
echo "GOAUDIT_TARGET_EXIT:${target_rc}" >&2
if [ "${target_rc}" -ne 0 ]; then
  exit 99
fi
`, setupScript, toolsCheck, profileName, image,
		userSetup, honeypotScript(), projectStage, targetCmd, execLine)

	pidsLimit := int64(256)
	hostConfig := &container.HostConfig{
		Runtime:    s.runtime,
		AutoRemove: false,
		Resources: container.Resources{
			Memory:    512 * 1024 * 1024,
			CPUPeriod: 100000,
			CPUQuota:  50000,
			PidsLimit: &pidsLimit,
		},
	}
	if !s.networkEnabled {
		hostConfig.NetworkMode = "none"
	}
	if projectPath != "" {
		hostConfig.Mounts = []mount.Mount{{
			Type: mount.TypeBind, Source: projectPath,
			Target: "/project-ro", ReadOnly: true,
		}}
	}

	resp, err := s.cli.ContainerCreate(ctx, &container.Config{
		Image: s.image, Cmd: []string{"bash", "-c", script},
		Tty: false, AttachStderr: true, AttachStdout: true,
	}, hostConfig, nil, nil, "")
	if err != nil {
		return nil, err
	}
	s.containerID = resp.ID

	if err := s.cli.ContainerStart(ctx, s.containerID, container.StartOptions{}); err != nil {
		return nil, err
	}

	logs, err := s.cli.ContainerLogs(ctx, s.containerID, container.LogsOptions{
		ShowStdout: true, ShowStderr: true, Follow: true,
	})
	if err != nil {
		return nil, err
	}
	return logs, nil
}

func (s *Sandbox) Cleanup(ctx context.Context) {
	if s.containerID != "" {
		_ = s.cli.ContainerRemove(ctx, s.containerID, container.RemoveOptions{Force: true})
	}
}

// honeypotScript creates realistic decoy credential files using $SANDBOX_HOME shell variable.
func honeypotScript() string {
	return `mkdir -p "${SANDBOX_HOME}/.ssh" "${SANDBOX_HOME}/.aws" "${SANDBOX_HOME}/.kube"
cat > "${SANDBOX_HOME}/.ssh/id_rsa" << 'HONEYPOT_SSH'
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBhbGljZUBleGFtcGxlLmNvbSBnb2F1ZGl0LWhvbmV5cG90AAAAJGF1ZGl0
HONEYPOT_SSH
chmod 600 "${SANDBOX_HOME}/.ssh/id_rsa"
cat > "${SANDBOX_HOME}/.aws/credentials" << 'HONEYPOT_AWS'
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
region = us-east-1
HONEYPOT_AWS
cat > "${SANDBOX_HOME}/.kube/config" << 'HONEYPOT_KUBE'
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://k8s.example.com:6443
  name: production
users:
- name: admin
  user:
    token: eyJhbGciOiJSUzI1NiJ9.goaudit-honeypot
HONEYPOT_KUBE
echo 'DATABASE_URL=postgres://admin:s3cret@db.example.com:5432/prod' > "${SANDBOX_HOME}/.env"
echo 'API_SECRET=sk_live_goaudit_honeypot_4f8a2b1c9d3e' >> "${SANDBOX_HOME}/.env"
if [ -n "$SANDBOX_USER" ] && [ "$SANDBOX_USER" != "root" ]; then
  chown -R 1000:1000 "${SANDBOX_HOME}" 2>/dev/null || true
fi
`
}
