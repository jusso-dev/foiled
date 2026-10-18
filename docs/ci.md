# Continuous integration

CI runs on every pull request and on every push to `main`, using GitHub-hosted runners. It needs no secrets and no Cloudflare account. The workflow lives in [`.github/workflows/ci.yml`](../.github/workflows/ci.yml).

## Jobs

| Job | What it checks |
| --- | --- |
| Rust (fmt, clippy, test) | `cargo fmt --check`, `cargo clippy` with warnings as errors, and `cargo test` for the whole workspace on the host target. |
| Rust (wasm32 Worker build) | `crates/api` passes clippy and builds in release mode for `wasm32-unknown-unknown`. Every crate the API Worker pulls in must build for Workers (ADR 0009, #40). |
| Front end (lint, typecheck, test, build) | Biome lint and format check, `wrangler types` plus React Router typegen plus `tsc`, Vitest unit tests and a production build of every package in the pnpm workspace. |
| Docs and schemas | `foiled-lint` checks that every `*.schema.json` is a valid JSON Schema and that catalogue entries and other bound data files validate against their schema. The OASIS `stix2-validator` (pinned 3.2.0) validates the golden STIX bundles in strict mode (#13). Lychee checks internal Markdown links offline. |

## Run the same checks locally

You need a stable Rust toolchain with the `wasm32-unknown-unknown` target, Node 22.22 or later, and pnpm 10.

```sh
rustup target add wasm32-unknown-unknown

# Rust
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo clippy -p foiled-api --target wasm32-unknown-unknown -- -D warnings
cargo build -p foiled-api --target wasm32-unknown-unknown --release

# Schemas and catalogue
cargo run -p foiled-lint -- .

# Front end
pnpm install
pnpm lint
pnpm typecheck
pnpm test
pnpm build

# STIX fixtures (optional locally, needs Python 3)
python3 -m venv .venv-stix && .venv-stix/bin/pip install stix2-validator==3.2.0
.venv-stix/bin/stix2_validator --version 2.1 --strict -d 103,245,302,401 testdata/exports/stix/

# Markdown links (optional, needs lychee installed)
lychee --offline --include-fragments './**/*.md'
```

## Rules

- Never skip, weaken or delete a test or check to get a pull request green. Fix the code or the test.
- No secrets in workflows. If a later job needs one, refer to it by name through GitHub Actions secrets and keep the job off pull requests from forks.
- No expensive matrix builds on every commit. Nightly image rebuilds are out of scope (#19).
- Tests that would need a real third-party API key use a mock or local emulation instead.

## Recommended branch protection

Maintainers should mark these checks as required on `main`:

- `Rust (fmt, clippy, test)`
- `Rust (wasm32 Worker build)`
- `Front end (lint, typecheck, test, build)`
- `Docs and schemas`

Squash merge only, and require branches to be up to date before merging.
