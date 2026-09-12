#!/usr/bin/env bash
# What a release would do, asked before one runs.
#
# Two workflows in two repositories need the same three answers per package —
# which version the manifest carries, and whether the registry already has it.
# The mirror's `release.yml` asks in order to decide whether to publish at all;
# the monorepo's `sync-sdk-mirror.yml` asks in order to decide whether a release
# tag still names the right commit. One implementation, carried between them by
# the same subtree split that carries the SDKs.
#
# It prints `key=value` lines, which is also the format GitHub Actions reads
# from `$GITHUB_OUTPUT`, so a job can consume it without parsing anything:
#
#   npm_name=@antondziuin/talos-sdk
#   npm_version=0.2.0
#   npm_published=false
#   nuget_id=Talos.Sdk
#   nuget_version=0.2.0
#   nuget_published=true
#
# Paths resolve against this file's own directory — `sdks/` in the monorepo, the
# repository root in the mirror — so neither caller has to know which one it is
# standing in.
set -euo pipefail
cd "$(dirname "$0")"

# A version that is not a version becomes a tag named `node-v` and a publish of
# nothing. Both manifests are read with an expression that returns empty rather
# than failing when the field moves, so the check is here rather than implied.
usable() {
  case "$1" in
    [0-9]*.[0-9]*.[0-9]*) ;;
    *) echo "$2 has no usable version ('$1')" >&2; exit 1 ;;
  esac
}

npm_name=$(node -p "require('./node/package.json').name")
npm_version=$(node -p "require('./node/package.json').version")
usable "$npm_version" "node/package.json"

# `npm view` prints nothing and exits non-zero for a version that does not
# exist — and does the same when the registry cannot be reached. So this reads
# an unreachable registry as "not published", and what discovers the difference
# is the publish itself, which fails loudly rather than skipping quietly.
npm_published=false
if [ -n "$(npm view "$npm_name@$npm_version" version 2>/dev/null || true)" ]; then
  npm_published=true
fi

csproj="csharp/Talos.Sdk/Talos.Sdk.csproj"
nuget_id=$(sed -n 's|.*<PackageId>\([^<]*\)</PackageId>.*|\1|p' "$csproj")
nuget_version=$(sed -n 's|^[[:space:]]*<Version>\([^<]*\)</Version>.*|\1|p' "$csproj")
usable "$nuget_version" "$csproj"

# The flat container is nuget.org's own index of what exists, and it 404s for a
# package that has never been published at all — `-f` turns that into a non-zero
# exit rather than an HTML error page parsed as a version list. The id is
# lower-cased because that is how the URL is spelled, whatever the casing in the
# csproj. The fetch is kept out of the pipe on purpose: with `pipefail` a `||`
# after the pipeline would append its own answer to the one node already
# printed.
nuget_lower=$(printf '%s' "$nuget_id" | tr '[:upper:]' '[:lower:]')
index=$(curl -sf "https://api.nuget.org/v3-flatcontainer/$nuget_lower/index.json" || true)
nuget_published=$(printf '%s' "$index" | node -e '
  let body = "";
  process.stdin.on("data", (d) => (body += d));
  process.stdin.on("end", () => {
    let versions = [];
    try { versions = JSON.parse(body).versions || []; } catch { /* absent or unreachable */ }
    process.stdout.write(versions.includes(process.argv[1]) ? "true" : "false");
  });
' "$nuget_version")

cat <<EOF
npm_name=$npm_name
npm_version=$npm_version
npm_published=$npm_published
nuget_id=$nuget_id
nuget_version=$nuget_version
nuget_published=$nuget_published
EOF
