package permify

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	permifypb "buf.build/gen/go/permifyco/permify/protocolbuffers/go/base/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/authorize/evaluator/engine"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/policy/criteria"
)

// fakeClient is a hand-rolled stub for the small permifyClient
// interface. Using a stub instead of a real PDP keeps the engine
// tests hermetic.
type fakeClient struct {
	result permifypb.CheckResult
	err    error

	calls   atomic.Int64
	lastCtx context.Context
	lastReq *permifypb.PermissionCheckRequest
}

func (f *fakeClient) Check(
	ctx context.Context,
	in *permifypb.PermissionCheckRequest,
) (*permifypb.PermissionCheckResponse, error) {
	f.calls.Add(1)
	f.lastCtx = ctx
	f.lastReq = in
	if f.err != nil {
		return nil, f.err
	}
	return &permifypb.PermissionCheckResponse{Can: f.result}, nil
}

// newTestEngine wires the fake client into an Engine with the
// package-default Config. Tests that need to customise Config can call
// newWithClient directly.
func newTestEngine(t *testing.T, client permifyClient) *Engine {
	t.Helper()
	return newWithClient(Config{}.withDefaults(), client)
}

func TestNew_RequiresEndpoint(t *testing.T) {
	t.Parallel()
	_, err := New(Config{})
	assert.ErrorIs(t, err, ErrMissingEndpoint)
}

func TestNew_BuildsClient(t *testing.T) {
	t.Parallel()
	e, err := New(Config{Endpoint: "localhost:3478", Plaintext: true})
	require.NoError(t, err)
	require.NotNil(t, e)
	assert.NoError(t, e.Close())
}

func TestEngine_Evaluate_PreChecks(t *testing.T) {
	t.Parallel()

	client := &fakeClient{}
	e := newTestEngine(t, client)

	privatePolicy := &config.Policy{}

	cases := []struct {
		name        string
		req         *evaluator.Request
		wantAllow   bool
		wantDeny    bool
		wantReasons []criteria.Reason
	}{
		{
			name:        "nil request",
			req:         nil,
			wantDeny:    true,
			wantReasons: []criteria.Reason{criteria.ReasonRouteNotFound},
		},
		{
			name:        "nil policy",
			req:         &evaluator.Request{},
			wantDeny:    true,
			wantReasons: []criteria.Reason{criteria.ReasonRouteNotFound},
		},
		{
			name:        "internal route",
			req:         &evaluator.Request{IsInternal: true, Policy: privatePolicy},
			wantAllow:   true,
			wantReasons: []criteria.Reason{criteria.ReasonPomeriumRoute},
		},
		{
			name:        "missing session on private route",
			req:         &evaluator.Request{Policy: privatePolicy},
			wantDeny:    true,
			wantReasons: []criteria.Reason{criteria.ReasonUserUnauthenticated},
		},
	}

	for i := range cases {
		c := &cases[i]
		t.Run(c.name, func(t *testing.T) {
			dec, err := e.Evaluate(t.Context(), c.req)
			require.NoError(t, err)
			require.NotNil(t, dec)
			assert.Equal(t, c.wantAllow, dec.Allow.Value)
			assert.Equal(t, c.wantDeny, dec.Deny.Value)
			for _, r := range c.wantReasons {
				assert.True(t, dec.Allow.Reasons.Has(r) || dec.Deny.Reasons.Has(r),
					"expected reason %q in %v / %v", r, dec.Allow.Reasons, dec.Deny.Reasons)
			}
		})
	}

	assert.Equal(t, int64(0), client.calls.Load(), "PDP must not be called for pre-check scenarios")
}

func TestEngine_Evaluate_PublicAnonymousReachesPDP(t *testing.T) {
	t.Parallel()

	client := &fakeClient{result: permifypb.CheckResult_CHECK_RESULT_ALLOWED}
	e := newTestEngine(t, client)

	policy := newPolicy(t)
	policy.AllowPublicUnauthenticatedAccess = true

	dec, err := e.Evaluate(t.Context(), &evaluator.Request{
		Policy: policy,
		HTTP:   evaluator.RequestHTTP{Method: http.MethodGet, Host: "from.example.com"},
	})
	require.NoError(t, err)
	assert.True(t, dec.Allow.Value)
	assert.Equal(t, int64(1), client.calls.Load())
	require.NotNil(t, client.lastReq)
	assert.Equal(t, anonymousSubjectID, client.lastReq.Subject.Id)
}

func TestEngine_Evaluate_AllowsAndDenies(t *testing.T) {
	t.Parallel()

	policy := newPolicy(t)
	req := &evaluator.Request{
		Policy:  policy,
		HTTP:    evaluator.RequestHTTP{Method: http.MethodGet, Host: "from.example.com", Path: "/x"},
		Session: evaluator.RequestSession{ID: "s1", UserID: "u1"},
	}

	t.Run("allow", func(t *testing.T) {
		client := &fakeClient{result: permifypb.CheckResult_CHECK_RESULT_ALLOWED}
		e := newTestEngine(t, client)

		dec, err := e.Evaluate(t.Context(), req)
		require.NoError(t, err)
		assert.True(t, dec.Allow.Value)
		assert.False(t, dec.Deny.Value)
		assert.True(t, dec.Allow.Reasons.Has(criteria.ReasonUserOK))

		assert.Equal(t, "u1", client.lastReq.Subject.Id)
		assert.Equal(t, DefaultEntityType, client.lastReq.Entity.Type)
		assert.NotEmpty(t, client.lastReq.Entity.Id)
		assert.Equal(t, "view", client.lastReq.Permission)
		assert.Equal(t, DefaultTenantID, client.lastReq.TenantId)
		assert.Equal(t, DefaultDepth, client.lastReq.Metadata.Depth)
	})

	t.Run("deny on result denied", func(t *testing.T) {
		client := &fakeClient{result: permifypb.CheckResult_CHECK_RESULT_DENIED}
		e := newTestEngine(t, client)

		dec, err := e.Evaluate(t.Context(), req)
		require.NoError(t, err)
		assert.False(t, dec.Allow.Value)
		assert.True(t, dec.Deny.Value)
		assert.True(t, dec.Deny.Reasons.Has(criteria.ReasonUserUnauthorized))
	})

	t.Run("deny on unspecified result", func(t *testing.T) {
		client := &fakeClient{result: permifypb.CheckResult_CHECK_RESULT_UNSPECIFIED}
		e := newTestEngine(t, client)

		dec, err := e.Evaluate(t.Context(), req)
		require.NoError(t, err)
		assert.True(t, dec.Deny.Value, "unspecified must be treated as deny — never silently allow")
	})
}

func TestEngine_Evaluate_PropagatesPDPError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("pdp unavailable")
	e := newTestEngine(t, &fakeClient{err: wantErr})

	_, err := e.Evaluate(t.Context(), &evaluator.Request{
		Policy:  newPolicy(t),
		HTTP:    evaluator.RequestHTTP{Method: http.MethodGet, Host: "from.example.com"},
		Session: evaluator.RequestSession{ID: "s1", UserID: "u1"},
	})
	assert.ErrorIs(t, err, ErrPDPRequest)
	assert.ErrorIs(t, err, wantErr)
}

func TestEngine_Evaluate_AppliesTimeout(t *testing.T) {
	t.Parallel()

	client := &fakeClient{result: permifypb.CheckResult_CHECK_RESULT_ALLOWED}
	cfg := Config{Timeout: 25 * time.Millisecond}.withDefaults()
	e := newWithClient(cfg, client)

	_, err := e.Evaluate(t.Context(), &evaluator.Request{
		Policy:  newPolicy(t),
		HTTP:    evaluator.RequestHTTP{Method: http.MethodGet, Host: "from.example.com"},
		Session: evaluator.RequestSession{ID: "s1", UserID: "u1"},
	})
	require.NoError(t, err)
	require.NotNil(t, client.lastCtx)

	deadline, ok := client.lastCtx.Deadline()
	require.True(t, ok, "expected a deadline on the per-call context")
	assert.WithinDuration(t, time.Now().Add(cfg.Timeout), deadline, cfg.Timeout)
}

func TestFactoryRegistration(t *testing.T) {
	t.Parallel()
	assert.Contains(t, engine.RegisteredKinds(), Kind)

	t.Run("external flag required", func(t *testing.T) {
		_, err := engine.Build(Kind, engine.FactoryConfig{})
		assert.ErrorIs(t, err, engine.ErrExternalNotAllowed)
	})

	t.Run("missing endpoint", func(t *testing.T) {
		_, err := engine.Build(Kind, engine.FactoryConfig{
			ExternalEnginesEnabled: true,
		})
		assert.ErrorIs(t, err, ErrMissingEndpoint)
	})

	t.Run("builds from map config", func(t *testing.T) {
		eng, err := engine.Build(Kind, engine.FactoryConfig{
			ExternalEnginesEnabled: true,
			EngineConfig: map[string]any{
				"endpoint":  "localhost:3478",
				"plaintext": true,
				"tenant_id": "t1",
			},
		})
		require.NoError(t, err)
		require.NotNil(t, eng)
		assert.NoError(t, eng.Close())
	})

	t.Run("builds from typed Config value", func(t *testing.T) {
		eng, err := engine.Build(Kind, engine.FactoryConfig{
			ExternalEnginesEnabled: true,
			EngineConfig:           Config{Endpoint: "localhost:3478", Plaintext: true},
		})
		require.NoError(t, err)
		assert.NoError(t, eng.Close())
	})
}

// newPolicy returns a config.Policy whose RouteID() succeeds. Shared by
// every test in the package.
func newPolicy(t *testing.T) *config.Policy {
	t.Helper()
	to, err := config.ParseWeightedUrls("https://to.example.com")
	require.NoError(t, err)
	p := &config.Policy{From: "https://from.example.com", To: to}
	_, err = p.RouteID()
	require.NoError(t, err)
	return p
}
