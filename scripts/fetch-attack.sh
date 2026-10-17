#!/usr/bin/env bash
# Fetch the pinned MITRE ATT&CK Enterprise STIX bundle and verify it (#26).
#
# Usage: scripts/fetch-attack.sh [--check]
#
# Downloads enterprise-attack.json from the mitre/cti GitHub repository at the
# tag for the version in data/attack/VERSION, checks its SHA-256 against
# data/attack/SHA256 and writes it to target/attack/ (git-ignored). The full
# bundle is never committed. With --check it also compares every technique in
# data/attack/techniques.json against the bundle (needs jq).
#
# Run by a maintainer when reviewing a version bump (docs/attack-mapping.md).
# Never run in CI: CI uses the committed sidecar only and stays offline.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
data="$root/data/attack"
out_dir="$root/target/attack"

if [[ -n "${CI:-}" ]]; then
  echo "fetch-attack.sh is a maintainer tool and does not run in CI" >&2
  exit 2
fi

check=0
case "${1:-}" in
  "") ;;
  --check) check=1 ;;
  *) echo "usage: $0 [--check]" >&2; exit 2 ;;
esac

version="$(tr -d '[:space:]' < "$data/VERSION")"
expected="$(tr -d '[:space:]' < "$data/SHA256")"

if [[ ! "$version" =~ ^[0-9]+\.[0-9]+$ ]]; then
  echo "data/attack/VERSION must hold a version like 20.0, got '$version'" >&2
  exit 1
fi
if [[ ! "$expected" =~ ^[0-9a-f]{64}$ ]]; then
  echo "data/attack/SHA256 must hold the bundle's lowercase SHA-256 before this script will run" >&2
  exit 1
fi

# The tag contains '&', which must be percent-encoded in the URL.
url="https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v${version}/enterprise-attack/enterprise-attack.json"
dest="$out_dir/enterprise-attack-${version}.json"

mkdir -p "$out_dir"
tmp="$(mktemp "$out_dir/.download.XXXXXX")"
trap 'rm -f "$tmp"' EXIT

echo "fetching ATT&CK v${version} from $url"
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  --max-time 600 --output "$tmp" "$url"

if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$tmp" | cut -d' ' -f1)"
else
  actual="$(shasum -a 256 "$tmp" | cut -d' ' -f1)"
fi

if [[ "$actual" != "$expected" ]]; then
  echo "SHA-256 mismatch for ATT&CK v${version}" >&2
  echo "  expected $expected" >&2
  echo "  actual   $actual" >&2
  echo "Upstream changed the file or the download was tampered with. Do not update SHA256 without review." >&2
  exit 1
fi

mv "$tmp" "$dest"
trap - EXIT
echo "verified $dest"

if [[ "$check" -eq 0 ]]; then
  exit 0
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "--check needs jq" >&2
  exit 1
fi

# For each sidecar technique, find the bundle object with the same ATT&CK id
# and report any difference in name, tactics or STIX id, or a technique that
# is revoked, deprecated or missing in the pinned version.
problems="$(jq -r --slurpfile side "$data/techniques.json" '
  [ .objects[]
    | select(.type == "attack-pattern")
    | { stix_id: .id,
        name,
        revoked: (.revoked // false),
        deprecated: (.x_mitre_deprecated // false),
        tactics: [ .kill_chain_phases[]? | select(.kill_chain_name == "mitre-attack") | .phase_name ],
        attack_id: (.external_references[]? | select(.source_name == "mitre-attack") | .external_id) }
  ] as $bundle
  | $side[0].techniques[]
  | . as $t
  | ([ $bundle[] | select(.attack_id == $t.id and (.revoked | not) and (.deprecated | not)) ] | first) as $b
  | if $b == null then "\($t.id): missing, revoked or deprecated in the pinned bundle"
    elif $b.name != $t.name then "\($t.id): name is \($b.name | @json) in the bundle"
    elif $b.tactics != $t.tactics then "\($t.id): tactics are \($b.tactics | @json) in the bundle"
    elif $b.stix_id != $t.stix_id then "\($t.id): stix_id is \($b.stix_id) in the bundle"
    else empty end
' "$dest")"

if [[ -n "$problems" ]]; then
  echo "data/attack/techniques.json differs from the pinned bundle:" >&2
  echo "$problems" >&2
  exit 1
fi
echo "data/attack/techniques.json matches ATT&CK v${version}"
