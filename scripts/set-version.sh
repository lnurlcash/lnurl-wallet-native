#!/usr/bin/env bash
# Stamp a version into Cargo.toml and Cargo.lock, e.g. from a release tag:
#   scripts/set-version.sh "${GITHUB_REF_NAME#v}"
# Cargo.toml itself carries a 0.0.0-dev placeholder; releases get their
# version from the tag instead of a hand-bumped field.
set -euo pipefail

version="${1:?usage: set-version.sh <version, e.g. 1.2.3 or 1.2.3-rc.1>}"
if ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]; then
  echo "not a semver version: $version" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
# only the package's own version: the first `version =` line, in [package]
# (awk, not `sed 0,/re/`: that is GNU-only, and the macOS runners have BSD sed)
awk -v v="$version" '!done && /^version = "/ { sub(/"[^"]*"/, "\"" v "\""); done = 1 } { print }' \
  Cargo.toml > Cargo.toml.tmp
mv Cargo.toml.tmp Cargo.toml
# refresh just this package's entry in the lockfile, so --locked builds pass
cargo update --workspace --offline --quiet
grep -m1 '^version' Cargo.toml
