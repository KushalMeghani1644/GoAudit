package sandbox

import (
	"context"
	"fmt"
	"io"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
)

type Sandbox struct {
	cli         *client.Client
	image       string
	containerID string
	runtime     string
}

func NewSandbox(ctx context.Context, image string) (*Sandbox, error) {
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
		cli:     cli,
		image:   image,
		runtime: runtime,
	}, nil
}

func (s *Sandbox) Runtime() string {
	return s.runtime
}

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
	requiredToolsCheck := ""
	for _, t := range requiredTools {
		requiredToolsCheck += fmt.Sprintf("command -v %s >/dev/null 2>&1 || { echo \"GOAUDIT_RUNTIME_ERROR:missing_tool:%s\" >&2; exit 97; }\n", t, t)
	}
	setupScript := ""
	for _, c := range setupCommands {
		setupScript += c + "\n"
	}

	script := fmt.Sprintf(`
set -euo pipefail
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

mkdir -p ~/.ssh ~/.aws ~/.kube
echo 'fake-key' > ~/.ssh/id_rsa
echo 'fake-aws' > ~/.aws/credentials
echo 'fake-kube' > ~/.kube/config
echo 'SECRET=fake' > ~/.env
mkdir -p /workspace
cd /workspace

cat << 'EOF_TARGET_CMD' > /tmp/target.sh
%s
EOF_TARGET_CMD

chmod +x /tmp/target.sh

set +e
strace -s 256 -f -e trace=open,openat,openat2,connect,execve,chmod,fchmod,fchmodat,rename,unlink,unlinkat,setuid,setgid,setreuid,setregid -o /dev/stderr bash /tmp/target.sh
target_rc=$?
set -e
echo "GOAUDIT_TARGET_EXIT:${target_rc}" >&2
if [ "${target_rc}" -ne 0 ]; then
  exit 99
fi
 `, setupScript, requiredToolsCheck, profileName, image, targetCmd)

	resp, err := s.cli.ContainerCreate(ctx, &container.Config{
		Image:        s.image,
		Cmd:          []string{"bash", "-c", script},
		Tty:          false,
		AttachStderr: true,
		AttachStdout: true,
	}, &container.HostConfig{
		Runtime:    s.runtime,
		AutoRemove: false,
	}, nil, nil, "")
	if err != nil {
		return nil, err
	}
	s.containerID = resp.ID

	if err := s.cli.ContainerStart(ctx, s.containerID, container.StartOptions{}); err != nil {
		return nil, err
	}

	logs, err := s.cli.ContainerLogs(ctx, s.containerID, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     true,
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
