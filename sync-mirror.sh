#!/usr/bin/env bash
# Publish `sdks/` to the public SDK repository, which is where releases happen.
#
# The monorepo is the source of truth: the SDKs are developed here, tested here
# against a real server, and versioned with the protocol they speak. But it is
# private, and npm attests provenance only against a public repository — so the
# packages are published from a mirror of this directory, and this is what puts
# the code there.
#
# What it does: `git subtree split` rewrites the history of `sdks/` as if it had
# always been its own repository (same commits, same authors, paths at the
# root), pushes that to the mirror's `main`, and puts the release tag on it. The
# mirror's own release workflow — authored here, at `sdks/.github/workflows/` —
# does the publishing from there.
#
#   ./sdks/sync-mirror.sh v0.1.0             # split, push, tag
#   ./sdks/sync-mirror.sh v0.1.0 --dry-run   # split and report, push nothing
#
# The mirror URL comes from TALOS_MIRROR_URL if you set it.
set -euo pipefail

MIRROR_URL="${TALOS_MIRROR_URL:-https://github.com/antondziuin/talos-sdk.git}"
PREFIX="sdks"

cd "$(dirname "$0")/.."   # repo root

tag="${1:-}"
dry_run=""
[ "${2:-}" = "--dry-run" ] && dry_run=1

if [ -z "$tag" ]; then
  echo "usage: $0 <tag> [--dry-run]    (e.g. $0 v0.1.0)" >&2
  exit 1
fi
case "$tag" in
  v*) ;;
  *) echo "the tag must start with 'v' — the mirror's release workflow triggers on 'v*'" >&2; exit 1 ;;
esac

# A split of a dirty tree silently publishes the last commit, not what you are
# looking at, and the difference is discovered on the registry.
if [ -n "$(git status --porcelain)" ]; then
  echo "the working tree has uncommitted changes; commit them before syncing" >&2
  exit 1
fi

# The same check the mirror's release workflow runs, made here so a mismatch
# costs a re-tag rather than a burnt version number.
version="${tag#v}"
csproj=$(sed -n 's|^[[:space:]]*<Version>\([^<]*\)</Version>.*|\1|p' \
         sdks/csharp/Talos.Sdk/Talos.Sdk.csproj)
npm=$(node -p "require('./sdks/node/package.json').version")
if [ "$version" != "$csproj" ] || [ "$version" != "$npm" ]; then
  echo "the tag says $version, the csproj says $csproj and package.json says $npm" >&2
  echo "bump the manifests in a commit first: a published version cannot be recalled" >&2
  exit 1
fi

echo "== splitting $PREFIX/ out of $(git rev-parse --short HEAD) =="
split_sha=$(git subtree split --prefix="$PREFIX" HEAD)
echo "split commit: $split_sha"

# What lands at the mirror's root has to be what its workflows expect. A split
# that produced the wrong shape would otherwise be discovered by a red CI run in
# a public repository.
for want in package.json README.md LICENSE .github/workflows/release.yml; do
  case "$want" in
    package.json|LICENSE) path="node/$want" ;;
    *) path="$want" ;;
  esac
  if ! git cat-file -e "$split_sha:$path" 2>/dev/null; then
    echo "the split is missing $path — refusing to push a mirror that cannot build" >&2
    exit 1
  fi
done
echo "the split carries the SDKs, their licences and the mirror's workflows"

if [ -n "$dry_run" ]; then
  echo
  echo "dry run: nothing pushed. It would have run:"
  echo "  git push $MIRROR_URL $split_sha:refs/heads/main"
  echo "  git push $MIRROR_URL $split_sha:refs/tags/$tag"
  exit 0
fi

echo "== pushing to $MIRROR_URL =="
# The SHA is pushed straight at the remote refs, so no local branch or tag is
# created here. That matters for the tag: in this repository `$tag` names the
# monorepo commit, and in the mirror it has to name the split one. Same name,
# two repositories, two different objects — and no way for one to overwrite the
# other by accident.
git push "$MIRROR_URL" "$split_sha:refs/heads/main"
git push "$MIRROR_URL" "$split_sha:refs/tags/$tag"

echo
echo "pushed. The mirror's release workflow publishes both packages from $tag;"
echo "watch it at https://github.com/antondziuin/talos-sdk/actions"
