package permify

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig_WithDefaults(t *testing.T) {
	t.Parallel()

	t.Run("zero value gets defaults", func(t *testing.T) {
		c := Config{}.withDefaults()
		assert.Equal(t, DefaultTimeout, c.Timeout)
		assert.Equal(t, DefaultTenantID, c.TenantID)
		assert.Equal(t, DefaultEntityType, c.EntityType)
		assert.Equal(t, DefaultSubjectType, c.SubjectType)
		assert.Equal(t, anonymousSubjectID, c.AnonymousSubjectID)
		assert.Equal(t, DefaultPermission, c.DefaultPermission)
		assert.Equal(t, DefaultDepth, c.Depth)
		assert.Equal(t, EntityIDSourceRouteID, c.EntityIDSource)
	})

	t.Run("explicit values preserved", func(t *testing.T) {
		c := Config{
			Timeout:           7 * time.Second,
			TenantID:          "acme",
			EntityType:        "route",
			SubjectType:       "service_account",
			DefaultPermission: "use",
			Depth:             50,
			EntityIDSource:    EntityIDSourceHost,
		}.withDefaults()
		assert.Equal(t, 7*time.Second, c.Timeout)
		assert.Equal(t, "acme", c.TenantID)
		assert.Equal(t, "route", c.EntityType)
		assert.Equal(t, "service_account", c.SubjectType)
		assert.Equal(t, "use", c.DefaultPermission)
		assert.Equal(t, int32(50), c.Depth)
		assert.Equal(t, EntityIDSourceHost, c.EntityIDSource)
	})

	t.Run("negative timeout and depth reset to defaults", func(t *testing.T) {
		c := Config{Timeout: -1 * time.Second, Depth: -7}.withDefaults()
		assert.Equal(t, DefaultTimeout, c.Timeout)
		assert.Equal(t, DefaultDepth, c.Depth)
	})
}

func TestConfig_DialOptions(t *testing.T) {
	t.Parallel()

	t.Run("plaintext", func(t *testing.T) {
		opts, err := Config{Plaintext: true}.dialOptions()
		require.NoError(t, err)
		assert.Len(t, opts, 1)
	})

	t.Run("tls insecure", func(t *testing.T) {
		opts, err := Config{TLSInsecure: true}.dialOptions()
		require.NoError(t, err)
		assert.Len(t, opts, 1)
	})

	t.Run("missing CA cert path errors", func(t *testing.T) {
		_, err := Config{CACertPath: "/does/not/exist"}.dialOptions()
		assert.Error(t, err)
	})
}

func TestConfig_LookupPermission(t *testing.T) {
	t.Parallel()

	defaults := Config{}.withDefaults()

	cases := map[string]string{
		http.MethodGet:     "view",
		http.MethodHead:    "view",
		http.MethodOptions: "view",
		http.MethodPost:    "create",
		http.MethodPut:     "update",
		http.MethodPatch:   "update",
		http.MethodDelete:  "delete",
		"WEIRDVERB":        DefaultPermission,
		"":                 DefaultPermission,
		"get":              "view", // case-insensitive
	}
	for method, want := range cases {
		t.Run(method+"->"+want, func(t *testing.T) {
			assert.Equal(t, want, defaults.lookupPermission(method))
		})
	}

	t.Run("operator override wins", func(t *testing.T) {
		c := Config{
			PermissionMap: map[string]string{"GET": "read"},
		}.withDefaults()
		assert.Equal(t, "read", c.lookupPermission("get"))
	})

	t.Run("override case-insensitive against map keys", func(t *testing.T) {
		c := Config{
			PermissionMap: map[string]string{"get": "read"},
		}.withDefaults()
		assert.Equal(t, "read", c.lookupPermission("GET"))
	})
}

func TestDecodeConfig(t *testing.T) {
	t.Parallel()

	t.Run("nil yields empty Config", func(t *testing.T) {
		c, err := decodeConfig(nil)
		require.NoError(t, err)
		assert.Equal(t, &Config{}, c)
	})

	t.Run("typed Config value", func(t *testing.T) {
		in := Config{Endpoint: "host:1", Plaintext: true}
		c, err := decodeConfig(in)
		require.NoError(t, err)
		assert.Equal(t, &in, c)
	})

	t.Run("typed Config pointer", func(t *testing.T) {
		in := &Config{Endpoint: "host:2"}
		c, err := decodeConfig(in)
		require.NoError(t, err)
		assert.Equal(t, in, c)
		c.Endpoint = "mutated"
		assert.Equal(t, "host:2", in.Endpoint)
	})

	t.Run("nil typed pointer", func(t *testing.T) {
		var in *Config
		c, err := decodeConfig(in)
		require.NoError(t, err)
		assert.Equal(t, &Config{}, c)
	})

	t.Run("map shape", func(t *testing.T) {
		c, err := decodeConfig(map[string]any{
			"endpoint":         "host:3",
			"plaintext":        true,
			"tenant_id":        "acme",
			"entity_type":      "route",
			"entity_id_source": "host",
			"depth":            50,
			"permission_map": map[string]any{
				"GET": "read",
			},
			"include_request_context": true,
		})
		require.NoError(t, err)
		assert.Equal(t, "host:3", c.Endpoint)
		assert.True(t, c.Plaintext)
		assert.Equal(t, "acme", c.TenantID)
		assert.Equal(t, "route", c.EntityType)
		assert.Equal(t, EntityIDSourceHost, c.EntityIDSource)
		assert.Equal(t, int32(50), c.Depth)
		assert.Equal(t, "read", c.PermissionMap["GET"])
		assert.True(t, c.IncludeRequestContext)
	})

	t.Run("unsupported type", func(t *testing.T) {
		_, err := decodeConfig(123)
		assert.ErrorIs(t, err, ErrInvalidConfig)
	})

	t.Run("invalid map element type", func(t *testing.T) {
		_, err := decodeConfig(map[string]any{
			"timeout": map[string]any{"nope": true},
		})
		assert.ErrorIs(t, err, ErrInvalidConfig)
	})
}
