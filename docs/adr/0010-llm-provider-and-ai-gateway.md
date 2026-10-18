# ADR 0010: LLM provider and AI Gateway

## Status

Accepted (18 Oct 2026). Issue #28. Related: #25 (attempts), #26 and [attack-mapping.md](../attack-mapping.md) (ATT&CK), #27 (confidence layer), #12 (matchers), #13 (exports), #16 and [privacy-and-retention.md](../privacy-and-retention.md) (retention), #17 (canaries), #24 (MCP), [ADR 0001](0001-architecture.md), [ADR 0009](0009-axum-workers-and-front-end.md), [threat-model.md](../threat-model.md) (C23, R6).

Design detail, defences and the eval set: [llm-correlation.md](../llm-correlation.md). Config: [configs/llm.yaml](../../configs/llm.yaml). Code: [crates/core/src/llm.rs](../../crates/core/src/llm.rs).

## Context

Rule matchers (#12) and ATT&CK rules (#26) are deterministic and miss novel paths. A language model can propose candidate CVE and technique links for an analyst to review. It reads attacker-controlled text, so every payload, header and file extract is a prompt-injection attempt until proven otherwise (threat model R6). It costs money per token, and anything sent to a provider may be logged by the provider or by the gateway in front of it.

ADR 0009 already puts AI Gateway in front of every model call and runs background work as Queue consumer Workers. This ADR fixes the provider interface, the gateway settings, where the token budget is enforced, and the retrieval store.

## Decision

### Worker shape

The LLM correlation worker is a Rust Queue consumer Worker (`foiled-llm` queue), not a long-running process. One message carries one `attempt_id`. The consumer loads the attempt summary from Postgres, retrieves reference chunks from Vectorize, checks the budget in D1, calls the model through AI Gateway, validates the output and writes the proposal to Postgres as `source=llm` evidence for #27. It never writes to exports (#13), never calls MCP tools (#24) and never calls a control-plane write API. Queue consumers get 15 minutes of wall time and up to 5 minutes of CPU per invocation; one attempt needs a few seconds of each, plus the provider wait.

The pure parts (sampling, redaction, prompt building, output validation, budget arithmetic, wire formats) live in `foiled_core::llm`, so they are tested offline and build for `wasm32-unknown-unknown`. The Worker supplies `fetch`, D1 and Vectorize.

### Provider interface

```rust
pub trait Provider {
    fn id(&self) -> &str;
    fn complete<'a>(&'a self, request: &'a CompletionRequest) -> ProviderFuture<'a>;
}
// CompletionRequest { system, user, max_output_tokens }
// Completion { raw: String, usage: Usage { input_tokens, output_tokens } }
// ProviderFuture<'a> = Pin<Box<dyn Future<Output = Result<Completion, ProviderError>> + 'a>>
```

This is the issue's `Complete(ctx, Prompt) -> (StructuredJSON, usage, error)` in Rust. The future is not `Send` because Workers are single-threaded. The raw text is untrusted until `parse_and_validate` accepts it. There is no way to pass tools through the interface.

Adapters:

| Adapter | Wire format (`WireFormat`) | Route | Key (Worker secret, name in config) | Default |
| --- | --- | --- | --- | --- |
| Workers AI, open model (example `@cf/meta/llama-3.3-70b-instruct-fp8-fast`) | `open_ai_chat`: OpenAI-compatible chat completions with `response_format` JSON schema | Workers AI REST endpoint with the `cf-aig-gateway-id` header, so the call goes through the gateway | `WORKERS_AI_TOKEN` | On (first in order) |
| Anthropic, commercial (example `claude-sonnet-5-5`) | `anthropic`: Messages API with `output_config.format` JSON schema | Gateway `anthropic` provider route, `https://gateway.ai.cloudflare.com/v1/{account}/{gateway}/anthropic/v1/messages` | `ANTHROPIC_API_KEY` | Off (opt in) |
| `FakeProvider` | none | none, offline | none | Tests and the default eval run |

Model ids are configuration, not code. Any other provider AI Gateway supports can be added as a new `WireFormat` arm without touching validation. The open adapter is first because data stays on Cloudflare; the commercial adapter sends redacted extracts to a third party, so an operator turns it on deliberately.

### AI Gateway setup

One gateway is dedicated to LLM correlation, so its settings do not leak into other uses.

| Setting | Value | Why |
| --- | --- | --- |
| Authentication | Authenticated gateway; token in the `AI_GATEWAY_TOKEN` secret, sent as `cf-aig-authorization` | Nobody else can spend through it. |
| Rate limit | 60 requests per 60 seconds, sliding window | Backstop against a consumer bug or a queue flood. Counts requests, not tokens. |
| Caching | **Off.** Gateway caching is off by default; leave it off. The worker also sends `cf-aig-skip-cache: true` on every request. | Prompts hold attacker data and a per-attempt id. A cache hit would replay one attempt's answer for another, and cache entries are another copy of attacker data. |
| Logging | **Off.** Gateway logging is on by default; turn it off in the gateway settings. The worker also sends `cf-aig-collect-log: false` on every request. | Gateway logs hold prompt text, which can hold personal information (#16). With logging off there is nothing to retain or purge. Usage and outcomes are recorded by the worker in Postgres without prompt text. An operator who must debug can allow metadata-only logs (log on, with `cf-aig-collect-log-payload: false`) for a time-boxed window. |
| Retries | `cf-aig-max-attempts: 2`, `cf-aig-retry-delay: 1000`, `cf-aig-backoff: exponential` | Absorbs transient provider errors at the gateway. |
| Timeout | `cf-aig-request-timeout: 60000` | A stuck provider triggers the next provider instead of eating wall time. |
| Provider fallback | Consumer-side, in `providers` order, at most `calls_per_attempt` (2) calls, on transport errors and rate limits only | Each fallback call is budgeted and validated the same way. A dropped (invalid or ungrounded) output, a refusal or a truncated answer is never retried on another provider. |

### Token budget enforcement

Both, with the consumer-side counter authoritative:

1. **Consumer-side daily counter in D1 (authoritative).** Before each call the consumer reserves the prompt estimate plus the full output cap with one conditional `UPDATE` on the row for the current UTC day; if no row changes, the call is not made. After the call it replaces the reservation with the usage the provider reported. Defaults: 2,000,000 tokens and 300 calls per day, 8,000 input and 1,000 output tokens per call, 2 calls per attempt. The SQL is in [llm-correlation.md](../llm-correlation.md#cost-controls).
2. **Gateway rate limit (backstop).** 60 requests per minute. It cannot count tokens, but it stops a runaway loop even if D1 is wrong.

AI Gateway's dynamic routing can also enforce a spend quota. Operators may add one as a third backstop; Foiled does not depend on it, so a plain gateway is enough.

### Retrieval store: Vectorize

Retrieval uses **Vectorize**, with embeddings from Workers AI (`@cf/baai/bge-base-en-v1.5`, 768 dimensions) and the chunk text in D1 keyed by `doc_id`.

- The corpus is small and public-ish: catalogue entries and matchers, KEV and OSV slices for catalogue products, the pinned ATT&CK sidecar, and advisories the operator mirrors. Tens of thousands of chunks at most, well inside Vectorize limits.
- The consumer queries it through a native binding, with no connection pooling, extension management or schema migration on the operator's Postgres. Not every Postgres host an operator brings has `pgvector`.
- The index is rebuilt from sources in the repository and D1 (catalogue sync, #12), so it holds nothing that needs backup or retention. Attacker data is never indexed: the index cannot be poisoned through a decoy.
- `top_k` is 6, under the Vectorize limit of 20 results (50 without values or metadata).

### Evidence and publishing

Validated proposals become #27 evidence with `source=llm` and a weight set in config (25), never by the model, hard-capped at 40. #27 keeps `high` and `publish_min` above that cap, so an LLM-only link never reaches `high` and never auto-publishes. Analysts can confirm a link, which adds `analyst` evidence.

## Consequences

- The worker is optional and ships off (`enabled: false`). Foiled works without it.
- No model weights are in the repository and no test calls a network. The offline fake provider and fixtures under `testdata/llm-eval/` cover the issue's validations in normal CI; a live eval runs only when `LLM_EVAL=1` and a key are present.
- Turning off gateway logging means debugging relies on the worker's own records (outcome, provider, usage, dropped ids, ignored keys), not prompt text.
- Provider fallback in the consumer means two provider calls can bill for one attempt; `calls_per_attempt` and the daily counter bound it.
- Vectorize is one more binding per environment and its index must be rebuilt when the catalogue or ATT&CK pin changes.
- Structured-output support differs by provider and model. Foiled sends a reduced schema (no length or count limits, which some providers reject) and enforces the full schema itself, so a provider that ignores the schema only costs a dropped output.

## Alternatives considered

- **Postgres with pgvector through Hyperdrive.** One store for attempts and vectors, SQL joins against attempts. Rejected for now: needs the extension on every operator's Postgres, adds query load to the attempt store, and the corpus does not need joins. Revisit if retrieval ever needs attempt-level data, which it must not include anyway.
- **Gateway Universal endpoint or dynamic routing for fallback.** Fewer round trips. Rejected as the primary mechanism because each fallback must be budgeted and validated by Foiled; it remains an option for operators.
- **Gateway caching on with a short TTL.** Cheaper for identical prompts. Rejected: identical prompts are rare (each holds an attempt id) and caching keeps another copy of attacker data.
- **Gateway logging on with short retention.** Easier debugging. Rejected as a default for the privacy reasons in #16; available as a time-boxed operator choice.
- **Tool use or function calling for structured output.** Rejected: the worker offers no tools, and a tool-use response is treated as an error.
- **Async runtime in `foiled-core`.** Rejected: core stays pure. The boxed-future trait needs no runtime, and the fake provider resolves immediately.
- **Only a commercial provider.** Rejected: an open model on Workers AI keeps data on Cloudflare and makes the worker usable without a third-party account.
