#!/usr/bin/env bash
# Cross-language contract test: build a demo product+license via xtask, start
# talos-server, then run the C# SDK against it (activate/validate/deactivate,
# verifying the signed tokens with the product's real public key).
#
# Requires: a running Postgres (deploy/saas/docker-compose.yml), the Rust
# toolchain, and the .NET SDK. Run from the repo root: ./sdks/csharp/contract.sh
set -euo pipefail
cd "$(dirname "$0")/../.."   # repo root

gen32() { python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"; }
export TALOS_KEK="$(gen32)"
export TALOS_RELEASE_KEK="$(gen32)"   # separate custody for release-signing keys
export TALOS_LICENSE_PEPPER="$(gen32)"
export TALOS_SESSION_KEY="$(gen32)"
export TALOS_MIGRATE_URL="${TALOS_MIGRATE_URL:-postgres://talos:talos_dev@localhost:5432/talos}"
export DATABASE_URL="${DATABASE_URL:-postgres://talos_app:talos_app_dev@localhost:5432/talos}"
export TALOS_BIND="127.0.0.1:8080"
export TALOS_PUBLIC_URL="http://127.0.0.1:8080"
export TALOS_LOG="warn"
# Absolute so the publisher (xtask, cwd=server) and the server (cwd=repo root)
# read/write the same artifact store.
export TALOS_ARTIFACT_DIR="$PWD/server/target/talos-artifacts"
rm -rf "$TALOS_ARTIFACT_DIR"

( cd server && cargo xtask db-reset >/dev/null )
DEMO="$( cd server && cargo xtask demo-license 2>/dev/null )"
echo "demo license: $DEMO"

cargo build --manifest-path server/Cargo.toml -p talos-server
./server/target/debug/talos-server &
SRV=$!
trap 'kill $SRV 2>/dev/null || true' EXIT

# Wait for readiness.
for _ in $(seq 1 30); do
  if curl -sf -o /dev/null http://127.0.0.1:8080/health; then break; fi
  sleep 1
done

export TALOS_CONTRACT=1
export TALOS_SERVER_URL="http://127.0.0.1:8080"
export TALOS_PRODUCT_TOKEN="$(echo "$DEMO" | python -c "import json,sys;print(json.load(sys.stdin)['product_token'])")"
export TALOS_PUBLIC_KEY="$(echo "$DEMO" | python -c "import json,sys;print(json.load(sys.stdin)['public_key'])")"
export TALOS_RELEASE_PUBLIC_KEY="$(echo "$DEMO" | python -c "import json,sys;print(json.load(sys.stdin)['release_public_key'])")"
export TALOS_LICENSE_KEY="$(echo "$DEMO" | python -c "import json,sys;print(json.load(sys.stdin)['license_key'])")"
export TALOS_CURRENT_VERSION="$(echo "$DEMO" | python -c "import json,sys;print(json.load(sys.stdin)['current_version'])")"
export TALOS_UPDATE_VERSION="$(echo "$DEMO" | python -c "import json,sys;print(json.load(sys.stdin)['update_version'])")"

echo "== C# contract =="
dotnet test sdks/csharp/Talos.Sdk.Tests/Talos.Sdk.Tests.csproj

echo "== Node contract =="
( cd sdks/node && npm ci --no-audit --no-fund && npm test )
