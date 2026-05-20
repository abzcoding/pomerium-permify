//go:build integration

// To run:
//   go test -tags=integration -run TestIntegration ./...
//
// Requires a working Docker daemon. The test pulls
// ghcr.io/permify/permify:latest on first run.

package permify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/policy/criteria"
)

const (
	permifyImage      = "ghcr.io/permify/permify:latest"
	permifyTenant     = "t1"
	permifyEntityKind = "pomerium_route"

	// schemaDSL is the test schema. It models a `pomerium_route`
	// entity with three direct user relations (viewer/editor/owner)
	// and the four CRUD permissions the engine maps HTTP methods
	// onto. `access` exists for unknown verbs (DefaultPermission).
	schemaDSL = `entity user {}

entity pomerium_route {
    relation viewer @user
    relation editor @user
    relation owner  @user

    permission view   = viewer or editor or owner
    permission create = editor or owner
    permission update = editor or owner
    permission delete = owner
    permission access = viewer or editor or owner
}`
)

// permifyServer is a single Permify PDP container managed by the test.
type permifyServer struct {
	containerID string
	grpcAddr    string
	httpAddr    string
}

// launchPermify starts a Permify container in memory mode, waits for
// it to become reachable, and returns the gRPC + HTTP addresses for
// the test to talk to.
func launchPermify(t *testing.T) *permifyServer {
	t.Helper()
	requireDocker(t)

	grpcPort := freePort(t)
	httpPort := freePort(t)

	args := []string{
		"run", "-d", "--rm",
		"-p", fmt.Sprintf("%d:3478", grpcPort),
		"-p", fmt.Sprintf("%d:3476", httpPort),
		permifyImage,
		"serve",
		"--database-engine=memory",
	}
	out, err := exec.Command("docker", args...).Output()
	require.NoError(t, err, "docker run permify")
	containerID := strings.TrimSpace(string(out))
	require.NotEmpty(t, containerID)
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", containerID).Run()
	})

	srv := &permifyServer{
		containerID: containerID,
		grpcAddr:    fmt.Sprintf("127.0.0.1:%d", grpcPort),
		httpAddr:    fmt.Sprintf("http://127.0.0.1:%d", httpPort),
	}
	srv.waitReady(t)
	return srv
}

// waitReady polls the Permify HTTP healthcheck until it responds 200
// or the deadline expires. Permify exposes `/healthz` on the HTTP
// port; any 200 means the gRPC server is also listening.
func (s *permifyServer) waitReady(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(s.httpAddr + "/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("permify did not become ready at %s within 60s", s.httpAddr)
}

// bootstrap writes the tenant, schema and tuples needed by the test
// scenarios via Permify's REST API.
func (s *permifyServer) bootstrap(t *testing.T, tuples []tuple) string {
	t.Helper()

	s.postJSON(t, "/v1/tenants/create", map[string]any{
		"id":   permifyTenant,
		"name": "Test Tenant",
	})

	schemaResp := s.postJSON(t,
		fmt.Sprintf("/v1/tenants/%s/schemas/write", permifyTenant),
		map[string]any{"schema": schemaDSL},
	)
	schemaVersion, _ := schemaResp["schema_version"].(string)
	require.NotEmpty(t, schemaVersion, "schema_version returned by Permify")

	encoded := make([]map[string]any, 0, len(tuples))
	for _, tp := range tuples {
		encoded = append(encoded, tp.toJSON())
	}
	s.postJSON(t,
		fmt.Sprintf("/v1/tenants/%s/data/write", permifyTenant),
		map[string]any{
			"metadata": map[string]any{"schema_version": schemaVersion},
			"tuples":   encoded,
		},
	)
	return schemaVersion
}

// postJSON posts an arbitrary JSON body and decodes the response as a
// generic JSON map. Non-2xx responses fail the test immediately.
func (s *permifyServer) postJSON(t *testing.T, path string, body any) map[string]any {
	t.Helper()
	buf, err := json.Marshal(body)
	require.NoError(t, err)

	resp, err := http.Post(s.httpAddr+path, "application/json", bytes.NewReader(buf))
	require.NoError(t, err, "POST %s", path)
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	require.GreaterOrEqualf(t, resp.StatusCode, 200, "POST %s: %s", path, respBody)
	require.Lessf(t, resp.StatusCode, 300, "POST %s: %s", path, respBody)

	var out map[string]any
	if len(respBody) > 0 {
		_ = json.Unmarshal(respBody, &out)
	}
	return out
}

// tuple is the in-memory shape used by tests to describe Permify
// relationships before they are encoded into the REST payload.
type tuple struct {
	entityType string
	entityID   string
	relation   string
	subjectID  string
}

func (t tuple) toJSON() map[string]any {
	return map[string]any{
		"entity":   map[string]any{"type": t.entityType, "id": t.entityID},
		"relation": t.relation,
		"subject":  map[string]any{"type": "user", "id": t.subjectID},
	}
}

func requireDocker(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker not on PATH: %v", err)
	}
}

// freePort returns a TCP port the kernel believes is currently free.
// There is an inherent race between the port being returned and the
// docker daemon binding it, but in practice this is good enough for
// hermetic CI runs.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func TestIntegration_PermifyPDP(t *testing.T) {
	srv := launchPermify(t)

	// Use Host-keyed entity IDs so the tuples we seed line up with
	// the hostnames in the test requests; RouteID is fine for
	// production but harder to reason about in tests.
	tuples := []tuple{
		{permifyEntityKind, "from.example.com", "viewer", "u1"},
		{permifyEntityKind, "from.example.com", "owner", "owner1"},
		{permifyEntityKind, "from.example.com", "viewer", anonymousSubjectID},
	}
	schemaVersion := srv.bootstrap(t, tuples)

	newEngine := func(t *testing.T) *Engine {
		t.Helper()
		eng, err := New(Config{
			Endpoint:       srv.grpcAddr,
			Plaintext:      true,
			TenantID:       permifyTenant,
			SchemaVersion:  schemaVersion,
			EntityIDSource: EntityIDSourceHost,
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = eng.Close() })
		return eng
	}

	policy := newPolicy(t)

	t.Run("viewer can read", func(t *testing.T) {
		eng := newEngine(t)
		dec, err := eng.Evaluate(t.Context(), &evaluator.Request{
			Policy:  policy,
			HTTP:    evaluator.RequestHTTP{Method: http.MethodGet, Host: "from.example.com"},
			Session: evaluator.RequestSession{ID: "s1", UserID: "u1"},
		})
		require.NoError(t, err)
		assert.True(t, dec.Allow.Value)
		assert.True(t, dec.Allow.Reasons.Has(criteria.ReasonUserOK))
	})

	t.Run("unknown user is denied", func(t *testing.T) {
		eng := newEngine(t)
		dec, err := eng.Evaluate(t.Context(), &evaluator.Request{
			Policy:  policy,
			HTTP:    evaluator.RequestHTTP{Method: http.MethodGet, Host: "from.example.com"},
			Session: evaluator.RequestSession{ID: "sX", UserID: "uX"},
		})
		require.NoError(t, err)
		assert.True(t, dec.Deny.Value)
		assert.True(t, dec.Deny.Reasons.Has(criteria.ReasonUserUnauthorized))
	})

	t.Run("viewer cannot delete", func(t *testing.T) {
		eng := newEngine(t)
		dec, err := eng.Evaluate(t.Context(), &evaluator.Request{
			Policy:  policy,
			HTTP:    evaluator.RequestHTTP{Method: http.MethodDelete, Host: "from.example.com"},
			Session: evaluator.RequestSession{ID: "s1", UserID: "u1"},
		})
		require.NoError(t, err)
		assert.True(t, dec.Deny.Value, "viewer DELETE must be denied")
	})

	t.Run("owner can delete", func(t *testing.T) {
		eng := newEngine(t)
		dec, err := eng.Evaluate(t.Context(), &evaluator.Request{
			Policy:  policy,
			HTTP:    evaluator.RequestHTTP{Method: http.MethodDelete, Host: "from.example.com"},
			Session: evaluator.RequestSession{ID: "s2", UserID: "owner1"},
		})
		require.NoError(t, err)
		assert.True(t, dec.Allow.Value, "owner DELETE must be allowed")
	})

	t.Run("public route uses anonymous subject and is allowed", func(t *testing.T) {
		eng := newEngine(t)
		publicPolicy := newPolicy(t)
		publicPolicy.AllowPublicUnauthenticatedAccess = true
		dec, err := eng.Evaluate(t.Context(), &evaluator.Request{
			Policy: publicPolicy,
			HTTP:   evaluator.RequestHTTP{Method: http.MethodGet, Host: "from.example.com"},
		})
		require.NoError(t, err)
		assert.True(t, dec.Allow.Value, "anonymous read on public route must be allowed")
	})

	t.Run("pre-check: nil request short-circuits without calling PDP", func(t *testing.T) {
		eng := newEngine(t)
		dec, err := eng.Evaluate(t.Context(), nil)
		require.NoError(t, err)
		assert.True(t, dec.Deny.Value)
		assert.True(t, dec.Deny.Reasons.Has(criteria.ReasonRouteNotFound))
	})

	t.Run("pre-check: missing session on private route", func(t *testing.T) {
		eng := newEngine(t)
		dec, err := eng.Evaluate(t.Context(), &evaluator.Request{
			Policy: newPolicyForHost(t, "private.example.com"),
			HTTP:   evaluator.RequestHTTP{Method: http.MethodGet, Host: "private.example.com"},
		})
		require.NoError(t, err)
		assert.True(t, dec.Deny.Value)
		assert.True(t, dec.Deny.Reasons.Has(criteria.ReasonUserUnauthenticated))
	})

	_ = context.Background // silence linter when no ctx vars survive
}

// newPolicyForHost builds a config.Policy whose From URL uses the
// given host. Used to exercise the missing-session pre-check on a
// route distinct from the one the bootstrap tuples cover.
func newPolicyForHost(t *testing.T, host string) *config.Policy {
	t.Helper()
	to, err := config.ParseWeightedUrls("https://to.example.com")
	require.NoError(t, err)
	p := &config.Policy{From: "https://" + host, To: to}
	_, err = p.RouteID()
	require.NoError(t, err)
	return p
}
