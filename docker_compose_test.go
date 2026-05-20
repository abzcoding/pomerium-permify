//go:build dockercompose

// docker_compose_test.go runs the demo docker-compose stack
// (permify + permify-bootstrap + pomerium-permify + upstream),
// routes HTTP requests through Pomerium, and asserts that the
// Permify PDP's allow/deny decisions actually drive the response.
//
// Run with:
//
//	go test -tags=dockercompose -run TestDockerCompose -v -timeout=300s ./...
//
// Requirements: docker, docker compose plugin, free TCP ports 9080,
// 3478 and 3476 on the host. The test pulls the permify, alpine,
// curlimages/curl and hashicorp/http-echo images on first run.

package permify

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	composeProjectName = "pomerium-permify-demo"
	pomeriumURL        = "http://127.0.0.1:9080"
	composeDir         = "docker"
)

func TestDockerCompose(t *testing.T) {
	requireComposeDocker(t)

	binaryPath := buildBinary(t)
	composePath := composeFile(t)

	env := append(os.Environ(),
		"POMERIUM_PERMIFY_BINARY="+binaryPath,
	)

	// Bring the stack up. `--wait` blocks until healthchecks pass, so
	// permify is guaranteed ready when this returns. The bootstrap
	// container is one-shot; the test waits for it explicitly below.
	runCompose(t, env, composePath, "up", "-d", "--wait", "--remove-orphans")
	t.Cleanup(func() {
		runCompose(t, env, composePath, "down", "-v", "--remove-orphans")
	})

	waitForBootstrap(t, env, composePath)
	waitForPomerium(t)

	cases := []struct {
		name       string
		host       string
		path       string
		wantStatus int
		wantBody   string
	}{
		{
			name:       "allow host returns upstream body",
			host:       "allow.localhost",
			path:       "/",
			wantStatus: http.StatusOK,
			wantBody:   "hello-from-upstream",
		},
		{
			name:       "deny host produces 403",
			host:       "deny.localhost",
			path:       "/",
			wantStatus: http.StatusForbidden,
		},
	}

	for i := range cases {
		c := &cases[i]
		t.Run(c.name, func(t *testing.T) {
			status, body := getThroughPomerium(t, c.host, c.path)
			assert.Equal(t, c.wantStatus, status, "status mismatch (body=%q)", body)
			if c.wantBody != "" {
				assert.Contains(t, body, c.wantBody)
			}
		})
	}
}

// requireComposeDocker skips the test when docker / docker compose are
// not usable from the host environment, keeping CI failures readable.
func requireComposeDocker(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker not on PATH: %v", err)
	}
	if err := exec.Command("docker", "compose", "version").Run(); err != nil {
		t.Skipf("docker compose plugin not available: %v", err)
	}
}

// buildBinary compiles the custom Pomerium binary with the permify
// engine baked in, into the docker/ build context where the compose
// bind mount expects it. Returns the absolute path.
func buildBinary(t *testing.T) string {
	t.Helper()
	outDir, err := filepath.Abs(composeDir)
	require.NoError(t, err)
	out := filepath.Join(outDir, "pomerium-permify")

	t.Logf("building %s (this can take ~30s the first time)", out)
	// The -ldflags trick downgrades the proto-registry duplicate
	// registration to a warning so the binary (which links both the
	// buf.build and the envoy-vendored copies of validate.proto) can
	// start up. See the Makefile for the same workaround.
	cmd := exec.Command("go", "build",
		"-ldflags=-X google.golang.org/protobuf/reflect/protoregistry.conflictPolicy=warn",
		"-o", out, "./cmd/pomerium-permify",
	)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr
	require.NoError(t, cmd.Run(), "go build failed: %s", stderr.String())

	t.Cleanup(func() { _ = os.Remove(out) })
	return out
}

func composeFile(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join(composeDir, "compose.yaml"))
	require.NoError(t, err)
	return p
}

// runCompose shells out to `docker compose -f <file> -p <project> …`
// with the supplied args and fails the test on a non-zero exit.
func runCompose(t *testing.T, env []string, composePath string, args ...string) {
	t.Helper()
	full := append([]string{"compose", "-f", composePath, "-p", composeProjectName}, args...)
	cmd := exec.Command("docker", full...)
	cmd.Env = env
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("docker %s failed: %v\nstdout: %s\nstderr: %s",
			strings.Join(full, " "), err, stdout.String(), stderr.String())
	}
}

// waitForBootstrap blocks until the permify-bootstrap one-shot
// container has exited successfully, signalling that the schema and
// tuples are loaded.
func waitForBootstrap(t *testing.T, env []string, composePath string) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		cmd := exec.Command("docker", "compose",
			"-f", composePath, "-p", composeProjectName,
			"ps", "-a", "--format", "{{.Name}}\t{{.State}}\t{{.ExitCode}}",
			"permify-bootstrap",
		)
		cmd.Env = env
		out, err := cmd.Output()
		if err == nil {
			text := strings.TrimSpace(string(out))
			if strings.Contains(text, "exited") && strings.Contains(text, "\t0") {
				return
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatal("permify-bootstrap did not finish successfully within 90s")
}

// waitForPomerium polls until Pomerium replies on the proxy port.
// Any HTTP response counts as ready; we just want to know the
// listener is up before issuing the assertion requests.
func waitForPomerium(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, pomeriumURL+"/healthz", nil)
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatal("timed out waiting for pomerium-permify to start listening on :9080")
}

// getThroughPomerium issues a GET to host+path via the Pomerium proxy
// port and returns (status, body). The Host header is what Pomerium
// uses to dispatch onto the configured route.
func getThroughPomerium(t *testing.T, host, path string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, pomeriumURL+path, nil)
	require.NoError(t, err)
	req.Host = host

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<14))
	require.NoError(t, err)
	return resp.StatusCode, string(body)
}
