# Demo docker-compose stack

This directory wires up the four things needed to prove the Permify
engine end-to-end:

| Service             | Image                          | Role                                                              |
|---------------------|--------------------------------|-------------------------------------------------------------------|
| `permify`           | `ghcr.io/permify/permify:latest` | Permify PDP, in-memory storage                                  |
| `permify-bootstrap` | `curlimages/curl`              | One-shot: writes the tenant, schema and seed tuples              |
| `upstream`          | `hashicorp/http-echo`          | Trivial backend that proves routing                               |
| `pomerium`          | `debian:bookworm-slim` + bind-mounted binary | Custom Pomerium with the plugin baked in (glibc required) |

The Pomerium binary is bind-mounted from the host rather than baked
into a custom image so this folder remains buildable without a
Dockerfile.

## Run it

From the repository root (the `-ldflags` setting downgrades a
protobuf duplicate-registration panic to a warning — see the top-
level `README.md` for the why):

```bash
CGO_ENABLED=0 go build \
  -ldflags="-X google.golang.org/protobuf/reflect/protoregistry.conflictPolicy=warn" \
  -o docker/pomerium-permify ./cmd/pomerium-permify
docker compose -f docker/compose.yaml up --wait
```

Or via the bundled Makefile and a small move:

```bash
make build && mv pomerium-permify docker/
docker compose -f docker/compose.yaml up --wait
```

`--wait` blocks until permify is healthy; `permify-bootstrap` runs to
completion before pomerium is started thanks to the
`service_completed_successfully` dependency.

Send a request through the proxy:

```bash
# allow.localhost is permitted by the seeded Permify tuple
#   pomerium_route:allow.localhost#viewer@user:anonymous
curl -i -H 'Host: allow.localhost' http://127.0.0.1:9080/
# expect: 200 OK, body "hello-from-upstream"

# deny.localhost has no tuple, so Permify returns CHECK_RESULT_DENIED
curl -i -H 'Host: deny.localhost' http://127.0.0.1:9080/
# expect: 403 Forbidden
```

Tear down:

```bash
docker compose -f docker/compose.yaml down -v
```

## Automated test

The same flow is exercised by [docker_compose_test.go](../docker_compose_test.go),
gated by the `dockercompose` build tag:

```bash
go test -tags=dockercompose -run TestDockerCompose -v -timeout=300s ./...
```

It builds the binary, brings up the stack, waits for the bootstrap
container to exit cleanly, asserts the allow / deny cases, and tears
the stack back down.

## Files

- `compose.yaml` — service definitions and bind mounts.
- `pomerium-config.yaml` — minimal Pomerium config with
  `policy_engine: permify`, two public routes, and the runtime flag
  required by the SPI.
- `permify-bootstrap/schema.json` — the Permify DSL the test depends
  on, expressed as a JSON payload for the `/schemas/write` endpoint.
- `permify-bootstrap/tuples.json` — relationship seeds, with a
  `__SCHEMA_VERSION__` placeholder substituted at runtime by
  `bootstrap.sh`.
- `permify-bootstrap/bootstrap.sh` — waits for permify, posts the
  tenant / schema / tuples via the REST API on port 3476.

Do not use the secrets in `pomerium-config.yaml` for anything outside
this demo: they are checked-in fixed values to keep the test
deterministic.
