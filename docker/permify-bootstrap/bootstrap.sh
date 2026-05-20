#!/bin/sh
# Bootstrap the Permify PDP for the demo stack: create the tenant,
# write the schema, and seed the relationship tuples that Pomerium's
# routes depend on. Re-running is safe — tenant/schema/tuple writes
# are idempotent for the values we use here.
set -eu

PERMIFY="http://permify:3476"
TENANT="t1"

echo "permify-bootstrap: waiting for $PERMIFY/healthz ..."
i=0
while ! curl -fsS "$PERMIFY/healthz" > /dev/null 2>&1; do
    i=$((i + 1))
    if [ "$i" -ge 60 ]; then
        echo "permify-bootstrap: permify never became ready" >&2
        exit 1
    fi
    sleep 1
done

echo "permify-bootstrap: creating tenant"
curl -fsS -X POST "$PERMIFY/v1/tenants/create" \
    -H "Content-Type: application/json" \
    -d "{\"id\":\"$TENANT\",\"name\":\"demo\"}" \
    > /tmp/tenant.json || true   # 409 if tenant exists already

echo "permify-bootstrap: writing schema"
SCHEMA_RESP="$(curl -fsS -X POST "$PERMIFY/v1/tenants/$TENANT/schemas/write" \
    -H "Content-Type: application/json" \
    --data @/bootstrap/schema.json)"

# Tiny inline JSON extractor: pull "schema_version":"…" without a
# dependency on jq.
SCHEMA_VERSION="$(echo "$SCHEMA_RESP" | sed -n 's/.*"schema_version":"\([^"]*\)".*/\1/p')"
if [ -z "$SCHEMA_VERSION" ]; then
    echo "permify-bootstrap: could not extract schema_version from response: $SCHEMA_RESP" >&2
    exit 1
fi
echo "permify-bootstrap: schema_version=$SCHEMA_VERSION"

echo "permify-bootstrap: writing tuples"
sed "s/__SCHEMA_VERSION__/$SCHEMA_VERSION/" /bootstrap/tuples.json \
    | curl -fsS -X POST "$PERMIFY/v1/tenants/$TENANT/data/write" \
        -H "Content-Type: application/json" \
        --data @-

echo "permify-bootstrap: OK"
