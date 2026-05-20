// Package permify implements a Pomerium PolicyEngine that delegates
// per-request access decisions to a Permify Policy Decision Point over
// the Permify gRPC API.
//
// It is an out-of-tree adapter: it registers itself with the Pomerium
// engine registry at import time, so a custom Pomerium binary picks it
// up via a blank import alongside the standard build. Operators select
// it by setting:
//
//	policy_engine: permify
//	external_policy_engine:
//	  endpoint: localhost:3478
//	  plaintext: true
//	  tenant_id: t1
//	runtime_flags:
//	  external_policy_engine: true
//
// See README.md for the full integration guide.
package permify

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	permifypb "buf.build/gen/go/permifyco/permify/protocolbuffers/go/base/v1"
	permifygrpc "github.com/Permify/permify-go/grpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/authorize/evaluator/engine"
	"github.com/pomerium/pomerium/pkg/policy/criteria"
)

// Kind is the engine kind registered with Pomerium.
const Kind engine.Kind = "permify"

// Sentinel errors returned by the package.
var (
	// ErrMissingEndpoint indicates that Config.Endpoint was not set.
	ErrMissingEndpoint = errors.New("permify: endpoint is required")
	// ErrInvalidConfig indicates an unsupported or malformed engine
	// config blob.
	ErrInvalidConfig = errors.New("permify: invalid configuration")
	// ErrPDPRequest indicates a transport-level failure talking to the
	// Permify PDP. The orchestrator translates this into a 5xx response;
	// the engine never silently denies on transport failures.
	ErrPDPRequest = errors.New("permify: PDP request failed")
)

// permifyClient is the small subset of the Permify Go SDK the engine
// depends on. Defining it locally keeps the engine testable without a
// running PDP: tests inject a fake implementation, production code
// uses *permifygrpc.Client wrapped by realClient.
type permifyClient interface {
	Check(
		ctx context.Context,
		in *permifypb.PermissionCheckRequest,
	) (*permifypb.PermissionCheckResponse, error)
}

// realClient adapts the generated Permify gRPC stub onto permifyClient.
// The wrapper exists purely so the production code path uses the SDK
// directly while unit tests can swap in a fake.
type realClient struct {
	c *permifygrpc.Client
	// authToken, when non-empty, is sent as an "authorization: Bearer …"
	// metadata header on every call. Permify Cloud uses this for tenant
	// authentication; self-hosted PDPs typically leave it empty.
	authToken string
}

func (r *realClient) Check(
	ctx context.Context,
	in *permifypb.PermissionCheckRequest,
) (*permifypb.PermissionCheckResponse, error) {
	if r.authToken != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+r.authToken)
	}
	return r.c.Permission.Check(ctx, in)
}

// Engine is a Pomerium PolicyEngine backed by a Permify PDP.
type Engine struct {
	cfg    Config
	client permifyClient
}

// Compile-time assertion that *Engine satisfies engine.PolicyEngine.
var _ engine.PolicyEngine = (*Engine)(nil)

// New creates a new Engine using a real Permify gRPC client built from
// cfg. Defaults are applied to cfg before the client is constructed.
//
// New does not block on PDP availability; the underlying connection is
// lazily established by gRPC on first use.
func New(cfg Config) (*Engine, error) {
	cfg = cfg.withDefaults()
	if cfg.Endpoint == "" {
		return nil, ErrMissingEndpoint
	}
	dialOpts, err := cfg.dialOptions()
	if err != nil {
		return nil, fmt.Errorf("permify: build dial options: %w", err)
	}
	client, err := permifygrpc.NewClient(
		permifygrpc.Config{Endpoint: cfg.Endpoint},
		dialOpts...,
	)
	if err != nil {
		return nil, fmt.Errorf("permify: new client: %w", err)
	}
	return newWithClient(cfg, &realClient{c: client, authToken: cfg.Token}), nil
}

// newWithClient is the test seam used to inject a fake permifyClient.
// Defaults are NOT re-applied: callers (New and the tests) pass an
// already-defaulted Config.
func newWithClient(cfg Config, client permifyClient) *Engine {
	return &Engine{cfg: cfg, client: client}
}

// Evaluate runs the orchestrator-mandated local pre-checks and, when
// none apply, delegates the access decision to the Permify PDP.
func (e *Engine) Evaluate(ctx context.Context, req *evaluator.Request) (*engine.Decision, error) {
	if dec, ok := preCheck(req); ok {
		return dec, nil
	}
	return e.callPDP(ctx, req)
}

// Close is a no-op. The underlying gRPC client manages its own
// connection lifecycle and exposes no Close method via the SDK.
func (e *Engine) Close() error { return nil }

// callPDP performs a single PermissionCheck call against the configured
// PDP and translates the boolean verdict into the Pomerium
// engine.Decision shape.
func (e *Engine) callPDP(ctx context.Context, req *evaluator.Request) (*engine.Decision, error) {
	checkReq := buildCheckRequest(req, e.cfg)

	if e.cfg.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, e.cfg.Timeout)
		defer cancel()
	}

	resp, err := e.client.Check(ctx, checkReq)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPDPRequest, err)
	}
	if resp != nil && resp.GetCan() == permifypb.CheckResult_CHECK_RESULT_ALLOWED {
		return allow(criteria.ReasonUserOK), nil
	}
	return deny(criteria.ReasonUserUnauthorized), nil
}

// preCheck returns a Decision and true when the request can be answered
// without consulting the PDP. The reasons it emits drive Pomerium's
// special-case flows (route-not-found, internal route, login redirect),
// which the engine cannot delegate away.
func preCheck(req *evaluator.Request) (*engine.Decision, bool) {
	switch {
	case req == nil, req.Policy == nil:
		return deny(criteria.ReasonRouteNotFound), true
	case req.IsInternal:
		return allow(criteria.ReasonPomeriumRoute), true
	case req.Session.ID == "" && !req.Policy.AllowPublicUnauthenticatedAccess:
		return deny(criteria.ReasonUserUnauthenticated), true
	}
	return nil, false
}

func allow(reasons ...criteria.Reason) *engine.Decision {
	return &engine.Decision{
		Allow: evaluator.NewRuleResult(true, reasons...),
		Deny:  evaluator.NewRuleResult(false),
	}
}

func deny(reasons ...criteria.Reason) *engine.Decision {
	return &engine.Decision{
		Allow: evaluator.NewRuleResult(false),
		Deny:  evaluator.NewRuleResult(true, reasons...),
	}
}

// buildTransportCredentials translates the Config's TLS settings into a
// grpc.DialOption. It is package-internal so it can be reused by tests
// that exercise the dial-option construction without standing up a TLS
// listener.
func buildTransportCredentials(cfg Config) (grpc.DialOption, error) {
	if cfg.Plaintext {
		return grpc.WithTransportCredentials(insecure.NewCredentials()), nil
	}
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: cfg.TLSInsecure, //nolint:gosec // operator-opt-in
	}
	if cfg.CACertPath != "" {
		pem, err := os.ReadFile(cfg.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("read CA cert %q: %w", cfg.CACertPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("parse CA cert %q: no certificates found", cfg.CACertPath)
		}
		tlsCfg.RootCAs = pool
	}
	return grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)), nil
}

func init() {
	engine.Register(Kind, true, factory)
}

// factory is the registry callback that builds a Permify engine from a
// raw FactoryConfig blob.
func factory(cfg engine.FactoryConfig) (engine.PolicyEngine, error) {
	c, err := decodeConfig(cfg.EngineConfig)
	if err != nil {
		return nil, err
	}
	return New(*c)
}
