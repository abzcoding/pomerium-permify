# pomerium-permify

An out-of-tree [Pomerium](https://github.com/pomerium/pomerium)
`PolicyEngine` that delegates per-request access decisions to a
[Permify](https://github.com/Permify/permify) Policy Decision Point
over the native Permify gRPC API.

It plugs into Pomerium's [external policy engine
SPI](https://github.com/pomerium/pomerium/pull/6361) via init-time
registration. Permify is a Zanzibar-style relationship-based
authorization service; this adapter exists so operators who already
model their authorisation graph in Permify can reuse it for Pomerium
without re-expressing the rules in Rego or AuthZEN.

## Usage

This module is meant to be consumed by a small custom Pomerium binary
that adds a blank import:

```go
// cmd/pomerium-with-permify/main.go
package main

import (
    _ "github.com/abzcoding/pomerium-permify" // registers the "permify" engine
    // …same imports as cmd/pomerium/main.go
)

func main() {
    // …same body as cmd/pomerium/main.go
}
```

Then point Pomerium at the Permify PDP:

```yaml
policy_engine: permify
external_policy_engine:
  endpoint: localhost:3478            # Permify gRPC port (default 3478)
  plaintext: true                     # disable TLS for local/in-cluster PDPs
  # tls_insecure: false               # skip cert verification
  # ca_cert: /etc/permify/ca.crt      # trusted CA bundle
  # token: ${PERMIFY_API_TOKEN}       # bearer token (Permify Cloud)
  timeout: 2s                         # per-call deadline
  tenant_id: t1                       # Permify tenant
  schema_version: ""                  # pin schema version (optional)
  snap_token: ""                      # pin snapshot token  (optional)
  depth: 20                           # PermissionCheck recursion depth
  entity_type: pomerium_route         # Permify entity.type
  entity_id_source: route_id          # route_id | host | from
  subject_type: user                  # Permify subject.type
  subject_relation: ""                # subject.relation (optional)
  anonymous_subject_id: anonymous     # subject.id for public-route requests
  default_permission: access          # permission name for unknown HTTP verbs
  permission_map:                     # override the built-in HTTP->permission map
    GET: view
    POST: create
  include_request_context: false      # send HTTP attrs as Permify Context.Data
runtime_flags:
  external_policy_engine: true
```

The runtime flag is required by Pomerium's SPI for any non-OPA engine.

## Request shape

Each authorize check becomes one Permify
[`PermissionCheck`](https://docs.permify.co/api-reference/permission/check-api)
call:

| Permify field                | Source                                                  |
|------------------------------|---------------------------------------------------------|
| `tenant_id`                  | `tenant_id`                                             |
| `metadata.schema_version`    | `schema_version`                                        |
| `metadata.snap_token`        | `snap_token`                                            |
| `metadata.depth`             | `depth`                                                 |
| `entity.type`                | `entity_type`                                           |
| `entity.id`                  | `Policy.RouteID()` / `HTTP.Host` / `Policy.From`        |
| `permission`                 | HTTP method → `view`/`create`/`update`/`delete`/`access`|
| `subject.type`               | `subject_type`                                          |
| `subject.id`                 | `Session.UserID` (or `anonymous_subject_id`)            |
| `subject.relation`           | `subject_relation`                                      |
| `context.data` (optional)    | `{host, path, method, ip, client_cert_valid, route_from, session_id}` when `include_request_context: true` |

The `entity_id_source` setting controls how the route identity is
encoded:

- `route_id` *(default)* — Pomerium's stable per-route hash. Robust
  across cosmetic config edits.
- `host` — the HTTP `Host` header. Lets the operator hand-author
  tuples keyed by hostname (`pomerium_route:foo.example.com`).
- `from` — the route's `from:` URL verbatim
  (`pomerium_route:https://foo.example.com`).

## Pre-checks (run locally)

| Condition                                       | Decision                                              |
|-------------------------------------------------|-------------------------------------------------------|
| `req == nil` or `req.Policy == nil`             | Deny + `ReasonRouteNotFound`                          |
| `req.IsInternal`                                | Allow + `ReasonPomeriumRoute`                         |
| `req.Session.ID == ""` (and route not public)   | Deny + `ReasonUserUnauthenticated` (→ login redirect) |

The PDP is consulted only after these are evaluated. Login/WebAuthn
flows continue to work even when the PDP is unreachable.

## Verdict translation

| PDP response                                              | engine.Decision                            |
|-----------------------------------------------------------|--------------------------------------------|
| `can == CHECK_RESULT_ALLOWED`                             | Allow + `criteria.ReasonUserOK`            |
| `can == CHECK_RESULT_DENIED`                              | Deny + `criteria.ReasonUserUnauthorized`   |
| `can == CHECK_RESULT_UNSPECIFIED` *(failure-safe deny)*   | Deny + `criteria.ReasonUserUnauthorized`   |
| transport error / context deadline                        | `ErrPDPRequest` (orchestrator returns 5xx) |

The engine never silently allows on failure.

## Example Permify schema

A minimal schema that matches the default HTTP-verb mapping and the
seed tuples in [`docker/permify-bootstrap`](docker/permify-bootstrap):

```perm
entity user {}

entity pomerium_route {
    relation viewer @user
    relation editor @user
    relation owner  @user

    permission view   = viewer or editor or owner
    permission create = editor or owner
    permission update = editor or owner
    permission delete = owner
    permission access = viewer or editor or owner
}
```

For attribute-based rules (path, method, IP, …), turn on
`include_request_context: true` and reach the values via Permify's
`request.X` namespace in your schema rules.

## Development

The repository ships a `Makefile` that wraps the test and build
invocations with a `-ldflags` workaround required because Permify's
generated protobuf code (`buf.build/gen/.../validate/validate.proto`)
and Pomerium's vendored envoy validate proto register the same file
in `protoregistry.GlobalFiles`. The default conflict policy panics;
the linker flag downgrades it to a warning so the binary can start.

```bash
make test                # unit tests, no daemon required
make test-integration    # spins up a real Permify PDP in Docker
make test-dockercompose  # full Pomerium + Permify + upstream stack
make build               # builds ./pomerium-permify
make vet
```

The raw command equivalents are:

```bash
go test  -ldflags="-X google.golang.org/protobuf/reflect/protoregistry.conflictPolicy=warn" ./...
go build -ldflags="-X google.golang.org/protobuf/reflect/protoregistry.conflictPolicy=warn" -o pomerium-permify ./cmd/pomerium-permify
```

You can substitute the runtime environment variable
`GOLANG_PROTOBUF_REGISTRATION_CONFLICT=warn` instead of the linker
flag if you prefer not to touch build settings — set it before
invoking either the binary or `go test`.

Three layers of tests:

1. **Unit tests** use a hand-rolled stub for the small `permifyClient`
   interface so they are hermetic and fast.
2. **`integration` tag** spins up a real Permify PDP in Docker
   (`ghcr.io/permify/permify:latest`) in memory mode and exercises
   the engine against it, bootstrapping the schema and tuples via
   the REST API.
3. **`dockercompose` tag** builds the custom Pomerium binary
   (`cmd/pomerium-permify`), brings up the full stack from
   [`docker/compose.yaml`](docker/compose.yaml) (Permify +
   permify-bootstrap + `hashicorp/http-echo` upstream + Pomerium),
   and verifies that HTTP requests routed through Pomerium honour
   the Permify PDP's decisions end to end.

See [`docker/README.md`](docker/README.md) for how to run the demo
stack by hand.

The `go.mod` carries a `replace` directive that points at a sibling
checkout of Pomerium during local development. Remove it before
tagging a release against a published Pomerium version.

## AI usage disclosure

The initial draft of this adapter was written with the help of
[Amp](https://ampcode.com) (Anthropic Claude). All code has been
reviewed and is maintained by a human author. The implementation
follows the public Pomerium external-policy-engine SPI and the
public Permify Go SDK.
