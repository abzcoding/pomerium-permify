package permify

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/authorize/evaluator"
)

func TestBuildCheckRequest_Basics(t *testing.T) {
	t.Parallel()

	cfg := Config{}.withDefaults()
	policy := newPolicy(t)
	wantRouteID, err := policy.RouteID()
	require.NoError(t, err)

	r := buildCheckRequest(&evaluator.Request{
		Policy:  policy,
		HTTP:    evaluator.RequestHTTP{Method: http.MethodGet, Host: "from.example.com", Path: "/x", IP: "1.2.3.4"},
		Session: evaluator.RequestSession{ID: "s1", UserID: "u1"},
	}, cfg)

	require.NotNil(t, r)
	assert.Equal(t, DefaultTenantID, r.TenantId)
	require.NotNil(t, r.Metadata)
	assert.Equal(t, DefaultDepth, r.Metadata.Depth)

	require.NotNil(t, r.Entity)
	assert.Equal(t, DefaultEntityType, r.Entity.Type)
	assert.Equal(t, wantRouteID, r.Entity.Id)

	require.NotNil(t, r.Subject)
	assert.Equal(t, DefaultSubjectType, r.Subject.Type)
	assert.Equal(t, "u1", r.Subject.Id)
	assert.Empty(t, r.Subject.Relation)

	assert.Equal(t, "view", r.Permission)
	assert.Nil(t, r.Context, "context omitted unless IncludeRequestContext is true")
}

func TestBuildCheckRequest_AnonymousSubject(t *testing.T) {
	t.Parallel()
	cfg := Config{}.withDefaults()
	r := buildCheckRequest(&evaluator.Request{
		Policy: newPolicy(t),
		HTTP:   evaluator.RequestHTTP{Method: http.MethodGet},
	}, cfg)
	assert.Equal(t, anonymousSubjectID, r.Subject.Id)
}

func TestBuildCheckRequest_CustomEntityIDSource(t *testing.T) {
	t.Parallel()
	policy := newPolicy(t)

	t.Run("host", func(t *testing.T) {
		cfg := Config{EntityIDSource: EntityIDSourceHost}.withDefaults()
		r := buildCheckRequest(&evaluator.Request{
			Policy: policy,
			HTTP:   evaluator.RequestHTTP{Host: "allow.example.com"},
		}, cfg)
		assert.Equal(t, "allow.example.com", r.Entity.Id)
	})

	t.Run("from", func(t *testing.T) {
		cfg := Config{EntityIDSource: EntityIDSourceFrom}.withDefaults()
		r := buildCheckRequest(&evaluator.Request{
			Policy: policy,
		}, cfg)
		assert.Equal(t, "https://from.example.com", r.Entity.Id)
	})

	t.Run("route_id default", func(t *testing.T) {
		cfg := Config{}.withDefaults()
		wantID, err := policy.RouteID()
		require.NoError(t, err)
		r := buildCheckRequest(&evaluator.Request{Policy: policy}, cfg)
		assert.Equal(t, wantID, r.Entity.Id)
	})
}

func TestBuildCheckRequest_IncludeRequestContext(t *testing.T) {
	t.Parallel()
	cfg := Config{IncludeRequestContext: true}.withDefaults()

	r := buildCheckRequest(&evaluator.Request{
		Policy:  newPolicy(t),
		HTTP:    evaluator.RequestHTTP{Method: http.MethodGet, Host: "h", Path: "/p", IP: "1.2.3.4"},
		Session: evaluator.RequestSession{ID: "s1", UserID: "u1"},
	}, cfg)
	require.NotNil(t, r.Context)
	require.NotNil(t, r.Context.Data)
	fields := r.Context.Data.Fields
	assert.Equal(t, "h", fields["host"].GetStringValue())
	assert.Equal(t, "/p", fields["path"].GetStringValue())
	assert.Equal(t, "GET", fields["method"].GetStringValue())
	assert.Equal(t, "1.2.3.4", fields["ip"].GetStringValue())
	assert.True(t, fields["client_cert_valid"].GetBoolValue())
	assert.Equal(t, "s1", fields["session_id"].GetStringValue())
	assert.Equal(t, "https://from.example.com", fields["route_from"].GetStringValue())
}

func TestBuildCheckRequest_ClientCertInvalid(t *testing.T) {
	t.Parallel()
	cfg := Config{IncludeRequestContext: true}.withDefaults()
	invalid := false
	r := buildCheckRequest(&evaluator.Request{
		Policy:                     newPolicy(t),
		HTTP:                       evaluator.RequestHTTP{Method: http.MethodGet, Host: "h"},
		Session:                    evaluator.RequestSession{ID: "s1", UserID: "u1"},
		PrecomputedClientCertValid: &invalid,
	}, cfg)
	require.NotNil(t, r.Context)
	require.NotNil(t, r.Context.Data)
	assert.False(t, r.Context.Data.Fields["client_cert_valid"].GetBoolValue())
}

func TestBuildCheckRequest_PermissionMap(t *testing.T) {
	t.Parallel()
	cfg := Config{
		PermissionMap: map[string]string{
			http.MethodGet:    "read",
			http.MethodDelete: "remove",
		},
	}.withDefaults()

	cases := []struct {
		method string
		want   string
	}{
		{http.MethodGet, "read"},
		{http.MethodDelete, "remove"},
		{http.MethodPost, "create"},     // falls back to defaults
		{"WEIRDVERB", DefaultPermission}, // falls back to DefaultPermission
	}
	for _, c := range cases {
		t.Run(c.method, func(t *testing.T) {
			r := buildCheckRequest(&evaluator.Request{
				Policy: newPolicy(t),
				HTTP:   evaluator.RequestHTTP{Method: c.method},
			}, cfg)
			assert.Equal(t, c.want, r.Permission)
		})
	}
}

func TestBuildCheckRequest_SubjectRelationForwarded(t *testing.T) {
	t.Parallel()
	cfg := Config{SubjectRelation: "member"}.withDefaults()
	r := buildCheckRequest(&evaluator.Request{
		Policy:  newPolicy(t),
		Session: evaluator.RequestSession{UserID: "u1"},
	}, cfg)
	assert.Equal(t, "member", r.Subject.Relation)
}

func TestResourceID_UnknownFallback(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "unknown", resourceID(nil, EntityIDSourceRouteID))
	assert.Equal(t, "unknown", resourceID(&evaluator.Request{}, EntityIDSourceRouteID))
}
