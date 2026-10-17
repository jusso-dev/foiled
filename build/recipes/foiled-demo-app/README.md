# foiled-demo-app recipe

Builds the synthetic demo decoy for catalogue entry `foiled/demo-app/1.0.0` (#5, #6). The app is in-repo MIT code: a small Python standard-library HTTP server with one deliberate, synthetic weakness, `FOILED-DEMO-0001`, an unauthenticated arbitrary file write through `POST /api/upload?path=...`. It is not a real CVE and does not mirror any real product.

What the app does, for the capture layer (#9) and hooks (#32):

- Logs every request as one JSON line on stdout: `ts`, `src`, `method`, `path`, `status`, `bytes`, `user_agent`.
- When an upload path resolves outside the upload directory, emits a hook line `{"kind": "hook", "hook_id": "demo-app.upload-path-traversal", "cve_id": "FOILED-DEMO-0001", "stage": "trigger", ...}`. The hook fails open: the decoy keeps working if the line cannot be written.
- Never executes, imports or parses uploaded content. Bodies are capped at 1 MiB.
- Serves `Server: demo-app/1.0.0`, runs as UID 10001, and only needs `/srv/demo-app` and `/tmp` writable.

## Build on a clean machine

Needs Docker with Buildx (`docker buildx version`) and Python 3 for the digest step. Run from anywhere:

```sh
build/recipes/foiled-demo-app/build.sh          # add --sbom if syft is installed
cat build/output/foiled-demo-app.digest
```

`build.sh` verifies `sources.lock`, builds with `--network=none`, labels the image with the repository revision, catalogue id and CVE ids, and writes the OCI archive and digest to `build/output/` (gitignored). It prints the `image:` line for the catalogue entry; push the OCI archive to a registry you control first, then paste the line into `catalogue/entries/foiled/demo-app/1.0.0.yaml`.

## Reproducible builds

Two builds with the same `SOURCE_DATE_EPOCH` produce the same digest. CI checks this on every pull request. To check by hand:

```sh
export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
build/recipes/foiled-demo-app/build.sh && cp build/output/foiled-demo-app.digest /tmp/a
build/recipes/foiled-demo-app/build.sh && diff /tmp/a build/output/foiled-demo-app.digest
```

## Tests

```sh
python3 -m unittest discover -s build/recipes/foiled-demo-app/app -v
```

## Changing the app

Edit `app/server.py`, update `sources.lock` (`shasum -a 256 app/server.py app/test_app.py`), and keep the deliberate weakness clearly marked. Do not add third-party dependencies: the build is offline by design (ADR 0004).

## Running it

Only ever under the Firecracker runtime with deny-by-default egress on a public IP ([ADR 0002](../../../docs/adr/0002-sandbox-runtime.md), [ADR 0003](../../../docs/adr/0003-network-isolation.md)). A local Docker run is fine for development:

```sh
docker run --rm --read-only --tmpfs /tmp --tmpfs /srv/demo-app/uploads -p 127.0.0.1:8080:8080 <image>
```
