#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Build the foiled-demo-app decoy image reproducibly (#6).
#
# What this does:
#   1. Refuses to run while the base image digest is still a placeholder.
#   2. Verifies every app source against sources.lock.
#   3. Builds with Docker Buildx, with the build steps offline (--network=none).
#   4. Applies provenance labels (revision, catalogue id, CVEs).
#   5. Writes the image digest to build/output/<id>.digest.
#   6. Optionally generates a CycloneDX SBOM with Syft (--sbom).
#   7. Prints the artefact line to paste into the catalogue entry.
#
# Builders are never honeypot hosts. See docs/adr/0004-image-builder.md.
set -euo pipefail

ID="foiled-demo-app"
CATALOGUE_ID="foiled/demo-app/1.0.0"
CVES="FOILED-DEMO-0001"

RECIPE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$RECIPE_DIR"

# Repo root: three levels up from build/recipes/<id>/.
REPO_ROOT="$(cd "$RECIPE_DIR/../../.." && pwd)"
OUT_DIR="$REPO_ROOT/build/output"

WANT_SBOM=0
for arg in "$@"; do
  case "$arg" in
    --sbom) WANT_SBOM=1 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

# 1. Placeholder guard. The build must never run against an unpinned base.
if grep -q "<pin-before-build>" Containerfile; then
  echo "ERROR: Containerfile base image digest is still a placeholder." >&2
  echo "Pin python:3.13-slim by its linux/amd64 manifest digest first." >&2
  exit 1
fi

# 2. Verify app sources against sources.lock (shasum format, comments stripped).
echo "Verifying sources.lock..."
if command -v sha256sum >/dev/null 2>&1; then
  grep -vE '^[[:space:]]*(#|$)' sources.lock | sha256sum -c -
else
  grep -vE '^[[:space:]]*(#|$)' sources.lock | shasum -a 256 -c -
fi

# 3. Build inputs.
REVISION="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
# SOURCE_DATE_EPOCH drives reproducible timestamps. Default to the recipe's last
# commit time; override by exporting SOURCE_DATE_EPOCH before running.
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
  SOURCE_DATE_EPOCH="$(git -C "$REPO_ROOT" log -1 --format=%ct -- "$RECIPE_DIR" 2>/dev/null || true)"
fi
# git prints nothing (and still succeeds) for uncommitted recipes; fall back
# to the repository's last commit, then to 0.
if [ -z "$SOURCE_DATE_EPOCH" ]; then
  SOURCE_DATE_EPOCH="$(git -C "$REPO_ROOT" log -1 --format=%ct 2>/dev/null || true)"
fi
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}"
export SOURCE_DATE_EPOCH

mkdir -p "$OUT_DIR"
OCI_OUT="$OUT_DIR/$ID.oci"
META_OUT="$OUT_DIR/$ID.metadata.json"
DIGEST_OUT="$OUT_DIR/$ID.digest"

echo "Building $ID (revision $REVISION, SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH)..."

# --network=none applies to RUN steps: the build itself is offline. The base
# image is fetched (with network) before these steps if it is not cached.
# --provenance=false and rewrite-timestamp keep the output bit-for-bit stable.
docker buildx build \
  --file Containerfile \
  --network=none \
  --provenance=false \
  --sbom=false \
  --build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" \
  --label "org.opencontainers.image.revision=$REVISION" \
  --label "foiled.catalogue.id=$CATALOGUE_ID" \
  --label "foiled.cves=$CVES" \
  --output "type=oci,dest=$OCI_OUT,rewrite-timestamp=true" \
  --metadata-file "$META_OUT" \
  "$RECIPE_DIR"

# 4. Extract the image digest from the buildx metadata file.
DIGEST="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1])).get("containerimage.digest",""))' "$META_OUT")"
if [ -z "$DIGEST" ]; then
  echo "ERROR: could not read containerimage.digest from $META_OUT" >&2
  exit 1
fi
printf '%s\n' "$DIGEST" > "$DIGEST_OUT"
echo "Image digest: $DIGEST"
echo "Wrote $DIGEST_OUT and OCI archive $OCI_OUT"

# 5. Optional SBOM (CycloneDX JSON) via Syft, invoked by hand in MVP.
if [ "$WANT_SBOM" -eq 1 ]; then
  if command -v syft >/dev/null 2>&1; then
    SBOM_OUT="$OUT_DIR/$ID.cyclonedx.json"
    echo "Generating SBOM with Syft..."
    syft "oci-archive:$OCI_OUT" -o cyclonedx-json="$SBOM_OUT"
    echo "Wrote $SBOM_OUT"
  else
    echo "WARNING: --sbom requested but syft is not installed; skipping SBOM." >&2
  fi
fi

# 6. The line to paste into catalogue/entries/foiled/demo-app/1.0.0.yaml once the
#    image is pushed to a registry the operator controls. Replace REGISTRY/REPO.
echo
echo "Catalogue artefact line (after pushing to your registry):"
echo "    image: REGISTRY/REPO/${ID}@${DIGEST}"
