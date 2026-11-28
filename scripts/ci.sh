#!/bin/sh
# The checks of .github/workflows/ci.yml (jobs "test" and "ui") on any Linux host with Rust
# (clippy) and Node. Use it while the repository has no GitHub remote, or before a push.
#   scripts/ci.sh            # in the source tree
#   scripts/ci.sh --docker   # in a container (IMAGE=..., default deskd-dev-check:latest)
# A copy of the tree is checked, so generated files never change your working copy; the
# check fails when committed TypeScript bindings or the compiled UI are not current.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)

if [ "${1:-}" = "--docker" ]; then
  image=${IMAGE:-deskd-dev-check:latest}
  exec docker run --rm -v "$root:/repo:ro" -v lw-target:/target -v lw-cargo:/root/.cargo/registry \
    -e CARGO_TARGET_DIR=/target "$image" sh /repo/scripts/ci.sh --in-copy
fi

if [ "${1:-}" != "--in-copy" ]; then
  work=$(mktemp -d)
  trap 'rm -rf "$work"' EXIT
  tar -C "$root" --exclude=./target --exclude=./node_modules --exclude=./.idea -cf - . | tar -C "$work" -xf -
  cd "$work"
else
  work=$(mktemp -d)
  tar -C /repo --exclude=./target --exclude=./node_modules --exclude=./.idea -cf - . | tar -C "$work" -xf -
  cd "$work"
fi

export RUSTFLAGS="-D warnings" CARGO_TERM_COLOR=always
# The copy belongs to another user inside a container.
git config --global --add safe.directory "$work" 2>/dev/null || true
step() { printf '\n== %s\n' "$*"; }
changed() {
  # Compare generated files with the committed copy (the tree is a copy, so plain diff).
  if [ -d .git ]; then git diff --exit-code -- "$@" && test -z "$(git status --porcelain -- "$@")"; fi
}

step "clippy"
cargo clippy --locked --all-targets -- -D warnings
step "tests"
cargo test --locked --release
step "API bindings are current"
changed src/web/ui/src/api
step "UI: install, type check, build"
npm ci --ignore-scripts --no-audit --no-fund
npm run check
npm run build
step "UI: CSP audit"
! grep -rnE "innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function|style=|\.style\." src/web/ui/src src/web/ui/index.html
step "compiled UI is current"
changed src/web/ui/dist src/web/ui/src/api
printf '\nci: all checks passed\n'
