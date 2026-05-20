package permify

import (
	permifypb "buf.build/gen/go/permifyco/permify/protocolbuffers/go/base/v1"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/pomerium/pomerium/authorize/evaluator"
)

// buildCheckRequest assembles a single PermissionCheckRequest from a
// Pomerium request. The request never mutates *evaluator.Request — the
// orchestrator passes the same value into the headers evaluator in
// parallel — so all the work is read-only against req.
func buildCheckRequest(req *evaluator.Request, cfg Config) *permifypb.PermissionCheckRequest {
	out := &permifypb.PermissionCheckRequest{
		TenantId: cfg.TenantID,
		Metadata: &permifypb.PermissionCheckRequestMetadata{
			SchemaVersion: cfg.SchemaVersion,
			SnapToken:     cfg.SnapToken,
			Depth:         cfg.Depth,
		},
		Entity: &permifypb.Entity{
			Type: cfg.EntityType,
			Id:   resourceID(req, cfg.EntityIDSource),
		},
		Permission: cfg.lookupPermission(req.HTTP.Method),
		Subject: &permifypb.Subject{
			Type:     cfg.SubjectType,
			Id:       subjectID(req, cfg),
			Relation: cfg.SubjectRelation,
		},
	}
	if cfg.IncludeRequestContext {
		if ctx := buildContext(req); ctx != nil {
			out.Context = ctx
		}
	}
	return out
}

// subjectID returns the principal ID for the Permify check. The
// session UserID is used when present; anonymous (public-route)
// requests fall back to cfg.AnonymousSubjectID so PDP schemas can
// grant access to a well-known principal.
func subjectID(req *evaluator.Request, cfg Config) string {
	if req.Session.UserID != "" {
		return req.Session.UserID
	}
	return cfg.AnonymousSubjectID
}

// resourceID returns the Permify entity ID for the route being
// checked. The fallback "unknown" exists for callers (mostly tests)
// that bypass preCheck; production traffic is rejected by the
// route-not-found pre-check before it reaches here.
func resourceID(req *evaluator.Request, source EntityIDSource) string {
	if req == nil || req.Policy == nil {
		return "unknown"
	}
	switch source {
	case EntityIDSourceHost:
		if req.HTTP.Host != "" {
			return req.HTTP.Host
		}
	case EntityIDSourceFrom:
		if req.Policy.From != "" {
			return req.Policy.From
		}
	}
	// Default + fallback path: try RouteID, then "unknown".
	id, err := req.Policy.RouteID()
	if err == nil && id != "" {
		return id
	}
	return "unknown"
}

// buildContext packs the HTTP + route metadata into a Permify Context.
// PDP schemas reach these fields through the `request.X` namespace in
// their rule expressions. Returning nil keeps the wire format identical
// to a check without context when IncludeRequestContext is off or no
// usable data is available.
func buildContext(req *evaluator.Request) *permifypb.Context {
	if req == nil {
		return nil
	}
	fields := map[string]any{}
	if req.HTTP.Host != "" {
		fields["host"] = req.HTTP.Host
	}
	if req.HTTP.Path != "" {
		fields["path"] = req.HTTP.Path
	}
	if req.HTTP.Method != "" {
		fields["method"] = req.HTTP.Method
	}
	if req.HTTP.IP != "" {
		fields["ip"] = req.HTTP.IP
	}
	fields["client_cert_valid"] = clientCertValid(req)
	if req.Policy != nil && req.Policy.From != "" {
		fields["route_from"] = req.Policy.From
	}
	if req.Session.ID != "" {
		fields["session_id"] = req.Session.ID
	}

	data, err := structpb.NewStruct(fields)
	if err != nil {
		// structpb.NewStruct only fails on unsupported value types;
		// every value we put in is JSON-native, so a failure here
		// means an unexpected schema change. Drop the context rather
		// than fail the request — the PDP can still answer from
		// tuples alone.
		return nil
	}
	return &permifypb.Context{Data: data}
}

// clientCertValid returns the precomputed client-certificate validity,
// defaulting to true when the orchestrator has not stored a value
// (routes without a client-cert requirement leave it nil, matching
// OPA's "no requirement → no failure" behaviour).
func clientCertValid(req *evaluator.Request) bool {
	if req.PrecomputedClientCertValid == nil {
		return true
	}
	return *req.PrecomputedClientCertValid
}
