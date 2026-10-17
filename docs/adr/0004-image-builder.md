# ADR 0004: Image builder for digest-pinned vulnerable versions

## Status

Accepted (18 Oct 2026). Issue #6. Related: #5 (catalogue), #3 and [ADR 0002](0002-sandbox-runtime.md) (runtime), #9 (capture), #32 (hooks), #22 (MVP slice), #38 (licences).

## Context

"Product X at version Y" only means something if we can rebuild exactly Y. Pulling `product:latest` from a random registry defeats the project and invites supply-chain risk (threat model R8). The builder must pin every input, record provenance, and never become a honeypot host itself. It must also be cheap enough for contributors to run on a laptop.

## Decision

### Tooling

- **OCI images with Docker Buildx** for the MVP. One recipe directory per catalogue artefact under `build/recipes/<recipe_id>/`.
- **Firecracker rootfs** is derived from the same OCI image rather than built separately, so both runtimes run the same bytes:

  ```sh
  cid=$(docker create --platform linux/amd64 "<image@sha256:...>")
  docker export "$cid" -o rootfs.tar && docker rm "$cid"
  mkdir rootfs && tar -xf rootfs.tar -C rootfs
  truncate -s 1G rootfs.ext4 && mkfs.ext4 -F -d rootfs rootfs.ext4
  ```

  The ext4 image is recorded with its own SHA-256 next to the OCI digest. A dedicated script lands with the Firecracker runtime work (#3, #41).

### Recipe layout

```text
build/recipes/<recipe_id>/
  Containerfile   base image pinned by @sha256 digest, never a floating tag
  VERSION         the upstream or demo version being built
  sources.lock    SHA-256 of every source copied into the image (and upstream URLs, when fetched)
  build.sh        verify, build offline, label, write digest, optional SBOM
  README.md       clean-machine steps
  app/ or src/    vendored sources
build/output/     gitignored: OCI archive, digest, metadata, SBOM
```

### Inputs and outputs

- **Inputs:** the recipe directory (its catalogue entry is named in `build.sh`), an optional upstream git ref override for real-software recipes, and `SOURCE_DATE_EPOCH`.
- **Outputs:** OCI archive, image digest (`build/output/<id>.digest`), Buildx metadata, optional CycloneDX SBOM, and the `image: <registry>/<repo>@sha256:...` line to paste into the catalogue entry after pushing to a registry the operator controls. The catalogue's `artefact.image` field must be digest-pinned (#5 schema), and `foiled-lint` checks that a verified entry's `recipe_id` exists.

### Provenance labels

Every image carries:

| Label | Value |
| --- | --- |
| `org.opencontainers.image.revision` | Git commit of this repository |
| `foiled.catalogue.id` | Catalogue entry id, for example `foiled/demo-app/1.0.0` |
| `foiled.cves` | Comma-separated CVE or `FOILED-DEMO-` ids |
| `org.opencontainers.image.licenses` | SPDX id of what is inside |

### Builder network policy

1. **Fetch step, with network:** pull the pinned base image and any upstream source tarballs listed in `sources.lock`, checking hashes.
2. **Build step, without network:** `docker buildx build --network=none`. `RUN` steps cannot reach anything, so a compromised build script cannot fetch a second stage or exfiltrate.
3. **Builders are never honeypot hosts.** Build on a developer machine or a CI runner, push to a registry, and let sandbox hosts pull by digest only. Hosts allow-list digests from signed jobs (#41).

### Reproducibility

- `SOURCE_DATE_EPOCH` (defaults to the recipe's last commit time), `--provenance=false`, `--sbom=false` inside the image, and the OCI exporter's `rewrite-timestamp=true` give byte-identical output for the same inputs.
- CI (`Demo image (reproducible build)`) builds the demo recipe twice with the build cache pruned in between and fails if the digests differ.
- What can still differ between builds: a different `SOURCE_DATE_EPOCH`, a different repository revision label, or a different base digest. All three are explicit inputs.

### SBOM

Syft generates a CycloneDX JSON SBOM from the OCI archive (`build.sh --sbom`). In the MVP this is run by hand and the SBOM is kept with the published image. Automating SBOM upload and attestation is a follow-up.

### Licence checks

A recipe may only use upstream software and base images whose licences allow redistribution of the built image. Record the licence in the image label and in the licence register (#38). The MVP recipe is the in-repo synthetic demo app (`build/recipes/foiled-demo-app`, MIT) with synthetic id `FOILED-DEMO-0001`, so no contributor has to publish a real vulnerable product mirror on day one.

### Follow-ups

- Image signing with Sigstore cosign and verification on the host before start.
- Automated rootfs export for Firecracker.
- A scheduled rebuild is out of scope for now (costly, #19).

## Consequences

- Every sandbox decoy can be traced from catalogue entry to recipe to digest to SBOM.
- Recipes cannot `apt-get install` at build time. Packages must come from the pinned base image or be vendored with hashes. This is deliberate friction.
- Contributors need Docker with Buildx, nothing else. CI proves the demo recipe builds and is reproducible on every pull request.

## Alternatives considered

- **Nix or Bazel for hermetic builds.** Stronger guarantees, much steeper entry for contributors. Revisit if Buildx reproducibility proves too weak.
- **Packer images per runtime.** Two build paths for the same software would drift. Deriving the rootfs from the OCI image keeps one source of truth.
- **Pulling vendor images by tag.** Rejected: tags move, and provenance is lost.
- **Building on sandbox hosts.** Rejected: a build host with network and registry credentials is exactly what an attacker on a compromised host would want.
