# Convenience wrapper around go build / go test.
#
# Permify's generated protobuf code comes from buf.build, while Pomerium
# pulls the same `validate/validate.proto` in via the envoy-vendored
# `github.com/envoyproxy/protoc-gen-validate` module. Both packages call
# protoregistry.GlobalFiles.RegisterFile during init, and the default
# conflict policy panics. The ldflags below downgrade that to a warning
# so a binary linking against both modules can start up.
LDFLAGS ?= -X google.golang.org/protobuf/reflect/protoregistry.conflictPolicy=warn

.PHONY: test test-integration test-dockercompose build vet tidy

test:
	go test -ldflags='$(LDFLAGS)' ./...

test-integration:
	go test -ldflags='$(LDFLAGS)' -tags=integration -timeout=120s ./...

test-dockercompose:
	go test -ldflags='$(LDFLAGS)' -tags=dockercompose -timeout=300s ./...

build:
	CGO_ENABLED=0 go build -ldflags='$(LDFLAGS)' -o pomerium-permify ./cmd/pomerium-permify

vet:
	go vet ./...

tidy:
	go mod tidy
