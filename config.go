package permify

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc"
)

// Default values used by New when the operator leaves fields unset.
const (
	DefaultTimeout          = 2 * time.Second
	DefaultTenantID         = "t1"
	DefaultEntityType       = "pomerium_route"
	DefaultSubjectType      = "user"
	DefaultPermission       = "access"
	DefaultDepth     int32  = 20
	DefaultEntityIDSource   = EntityIDSourceRouteID

	anonymousSubjectID = "anonymous"
)

// EntityIDSource selects which field on the Pomerium request becomes
// the Permify entity ID. Permify tuples are typed by (entity.type,
// entity.id), so the operator needs to align this with whatever the
// tuples in their PDP were seeded against.
type EntityIDSource string

const (
	// EntityIDSourceRouteID uses Policy.RouteID() — the stable hash
	// Pomerium computes from a route's From+To pair. Recommended in
	// production because it survives policy edits that do not change
	// the route's identity.
	EntityIDSourceRouteID EntityIDSource = "route_id"

	// EntityIDSourceHost uses the HTTP Host header. Useful for demos
	// and for hand-authored tuples that key by hostname.
	EntityIDSourceHost EntityIDSource = "host"

	// EntityIDSourceFrom uses Policy.From verbatim (e.g.
	// "https://allow.example.com"). Convenient when the operator
	// already manages route identity in their PDP by URL.
	EntityIDSourceFrom EntityIDSource = "from"
)

// Config configures the Permify engine.
//
// It is the shape Pomerium's config layer unmarshals the
// external_policy_engine YAML block into. JSON and mapstructure tags
// match Pomerium's existing options conventions so the same struct can
// be consumed either way.
type Config struct {
	// Endpoint is the address of the Permify PDP, in any form gRPC
	// accepts ("host:port", "dns:///host:port", "unix:/path/to/sock").
	Endpoint string `json:"endpoint" mapstructure:"endpoint"`

	// Plaintext disables TLS on the gRPC connection. Use only when the
	// PDP lives in the same network segment as Pomerium.
	Plaintext bool `json:"plaintext" mapstructure:"plaintext"`

	// TLSInsecure skips PDP certificate verification. Equivalent to
	// passing tls.Config{InsecureSkipVerify: true} to gRPC.
	TLSInsecure bool `json:"tls_insecure" mapstructure:"tls_insecure"`

	// CACertPath, when set, is loaded as the PDP's trusted CA bundle.
	CACertPath string `json:"ca_cert" mapstructure:"ca_cert"`

	// Token, when set, is sent as a "Bearer …" authorization metadata
	// header on every call. Permify Cloud requires this; self-hosted
	// PDPs generally leave it empty.
	Token string `json:"token" mapstructure:"token"`

	// Timeout bounds each evaluation call's gRPC context. Defaults to
	// DefaultTimeout. It is applied to outbound calls by the engine via
	// context.WithTimeout.
	Timeout time.Duration `json:"timeout" mapstructure:"timeout"`

	// TenantID is the Permify tenant. Defaults to DefaultTenantID
	// ("t1"), which matches Permify's single-tenant default.
	TenantID string `json:"tenant_id" mapstructure:"tenant_id"`

	// SchemaVersion pins the PDP to a particular schema revision. Empty
	// uses the PDP's latest schema (the usual case).
	SchemaVersion string `json:"schema_version" mapstructure:"schema_version"`

	// SnapToken pins the PDP to a particular relationship-store
	// snapshot. Empty disables snapshot pinning (the usual case).
	SnapToken string `json:"snap_token" mapstructure:"snap_token"`

	// Depth is the recursion limit Permify applies when walking the
	// relationship graph. Defaults to DefaultDepth (20). The PDP
	// rejects requests that omit it, so the engine always sends a
	// value.
	Depth int32 `json:"depth" mapstructure:"depth"`

	// EntityType is the Permify entity.type sent with every check.
	// Defaults to DefaultEntityType ("pomerium_route"). Operators
	// override it to match the entity used in their schema.
	EntityType string `json:"entity_type" mapstructure:"entity_type"`

	// EntityIDSource selects which Pomerium field becomes the
	// Permify entity.id. See EntityIDSource constants for choices.
	EntityIDSource EntityIDSource `json:"entity_id_source" mapstructure:"entity_id_source"`

	// SubjectType is the Permify subject.type used for every
	// principal. Defaults to DefaultSubjectType ("user").
	SubjectType string `json:"subject_type" mapstructure:"subject_type"`

	// SubjectRelation, when set, becomes Subject.Relation in the
	// PermissionCheckRequest. Permify uses it to model "members of a
	// group can access X" style rules. Leave empty for direct user
	// checks.
	SubjectRelation string `json:"subject_relation" mapstructure:"subject_relation"`

	// AnonymousSubjectID is the subject ID used when the request has
	// no authenticated session (only reached on public routes).
	// Defaults to "anonymous" so PDP schemas can grant access to a
	// well-known principal instead of having to special-case empty
	// IDs.
	AnonymousSubjectID string `json:"anonymous_subject_id" mapstructure:"anonymous_subject_id"`

	// DefaultPermission is the permission name sent for HTTP methods
	// not covered by PermissionMap. Defaults to DefaultPermission
	// ("access").
	DefaultPermission string `json:"default_permission" mapstructure:"default_permission"`

	// PermissionMap overrides the built-in HTTP-method → permission
	// mapping. Keys are normalised to upper case before lookup so
	// "get" and "GET" both work. Unmapped methods fall back to
	// DefaultPermission.
	PermissionMap map[string]string `json:"permission_map" mapstructure:"permission_map"`

	// IncludeRequestContext, when true, sends the route + HTTP
	// context as Permify Context.Data so that ABAC rules in the schema
	// can pattern-match on request.host, request.path, request.method,
	// request.ip, and request.client_cert_valid. Off by default to
	// keep checks minimal; ABAC schemas should turn it on.
	IncludeRequestContext bool `json:"include_request_context" mapstructure:"include_request_context"`
}

// withDefaults returns a copy of c with zero-valued fields populated
// from the package defaults.
func (c Config) withDefaults() Config {
	if c.Timeout <= 0 {
		c.Timeout = DefaultTimeout
	}
	if c.TenantID == "" {
		c.TenantID = DefaultTenantID
	}
	if c.EntityType == "" {
		c.EntityType = DefaultEntityType
	}
	if c.SubjectType == "" {
		c.SubjectType = DefaultSubjectType
	}
	if c.AnonymousSubjectID == "" {
		c.AnonymousSubjectID = anonymousSubjectID
	}
	if c.DefaultPermission == "" {
		c.DefaultPermission = DefaultPermission
	}
	if c.Depth <= 0 {
		c.Depth = DefaultDepth
	}
	if c.EntityIDSource == "" {
		c.EntityIDSource = DefaultEntityIDSource
	}
	return c
}

// dialOptions converts the connection-related fields on Config into the
// grpc.DialOption slice handed to permifygrpc.NewClient.
func (c Config) dialOptions() ([]grpc.DialOption, error) {
	creds, err := buildTransportCredentials(c)
	if err != nil {
		return nil, err
	}
	return []grpc.DialOption{creds}, nil
}

// lookupPermission returns the Permify permission name for an HTTP
// method, honouring the operator's overrides before falling back to
// the built-in mapping and then to DefaultPermission.
func (c Config) lookupPermission(method string) string {
	key := strings.ToUpper(strings.TrimSpace(method))
	if key == "" {
		return c.DefaultPermission
	}
	if v, ok := c.PermissionMap[key]; ok {
		return v
	}
	// Case-insensitive fallback for operators that wrote the override
	// keys in their preferred case (mapstructure preserves them).
	for k, v := range c.PermissionMap {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	if v, ok := defaultPermissionByMethod[key]; ok {
		return v
	}
	return c.DefaultPermission
}

// defaultPermissionByMethod is the built-in HTTP-verb → permission
// table. The names are intentionally the conventional Permify schema
// verbs (view/create/update/delete) so the simplest schemas work out
// of the box.
var defaultPermissionByMethod = map[string]string{
	"GET":     "view",
	"HEAD":    "view",
	"OPTIONS": "view",
	"POST":    "create",
	"PUT":     "update",
	"PATCH":   "update",
	"DELETE":  "delete",
}

// decodeConfig converts an opaque engine config blob into a *Config.
//
// Supported shapes:
//   - nil               → defaults only (caller still gets ErrMissingEndpoint)
//   - *Config / Config  → used directly
//   - map[string]any    → JSON-round-tripped into Config (matches mapstructure)
func decodeConfig(raw any) (*Config, error) {
	switch v := raw.(type) {
	case nil:
		c := Config{}
		return &c, nil
	case *Config:
		if v == nil {
			c := Config{}
			return &c, nil
		}
		c := *v
		return &c, nil
	case Config:
		c := v
		return &c, nil
	case map[string]any:
		b, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("%w: marshal: %w", ErrInvalidConfig, err)
		}
		c := Config{}
		if err := json.Unmarshal(b, &c); err != nil {
			return nil, fmt.Errorf("%w: unmarshal: %w", ErrInvalidConfig, err)
		}
		return &c, nil
	default:
		return nil, fmt.Errorf("%w: unsupported config type %T", ErrInvalidConfig, raw)
	}
}
