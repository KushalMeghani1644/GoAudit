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

func (s *Sandbox) RunCommand(ctx context.Context, targetCmd string) (io.Reader, error) {
	script := fmt.Sprintf(`
apt-get update -qq > /dev/null 2>&1
apt-get install -y -qq strace > /dev/null 2>&1 || true

mkdir -p ~/.ssh ~/.aws ~/.kube
echo 'fake-key' > ~/.ssh/id_rsa
echo 'fake-aws' > ~/.aws/credentials
echo 'fake-kube' > ~/.kube/config
echo 'SECRET=fake' > ~/.env

strace -s 256 -f -e trace=open,openat,connect -o /dev/stderr %s
`, targetCmd)

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
