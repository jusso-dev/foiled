//! The `foiled-enrich` Queue consumer (#11).
//!
//! A queue batch holds up to 100 messages (`max_batch_size` in
//! `wrangler.jsonc`), each one observable seen by one tenant. For every message the consumer skips providers with a fresh
//! cache row the tenant may read, or a failure still backing off, and
//! answers `local_asn` from the operator's ASN table. Everything that needs
//! ThreatSieve is gathered across the batch and sent as one `POST
//! /v1/lookup` per `batch_size` observables, each lookup taking one unit of
//! rate-limit budget in D1. Answers become cache rows: shared rows when
//! every contributing source allows redistribution and commercial use,
//! otherwise rows kept for each tenant that asked (`threatsieve_restricted`,
//! never exported).
//!
//! D1 cost, worst case: per message one cache read, one failure read, one
//! `local_asn` write, one ThreatSieve write per scope (one, or one per
//! asking tenant for a restricted answer) and one failure clear (only when a
//! failure was on record); per lookup two or three budget statements and a
//! prune. A full batch of 100 is about 500 queries, inside the Workers Paid
//! plan's 1,000 per invocation; the Free plan's 50 needs `max_batch_size` 8
//! or less (`docs/enrichment.md`).
//!
//! The I/O sits behind [`Store`], [`ProviderHttp`] and a secret lookup, so
//! the whole flow is tested on the host with a fake ThreatSieve and no
//! network. The Worker wiring is in `worker_glue`. Design:
//! `docs/enrichment.md`.

use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;

use foiled_core::enrich_pipeline::{
    EnrichConfig, EnrichMessage, LookupError, MAX_LOOKUP_BATCH, Step, answer_for, day_limit_for,
    lookup_outcome, lookup_request, plan, valid_facts,
};
use foiled_core::enrichment::{
    AsnTable, CacheEntry, Fact, LOCAL_ASN, Observable, Provider, THREATSIEVE,
};

pub use foiled_core::enrich_pipeline::ProviderRequest;

use crate::store::{BudgetOutcome, Store};

/// An HTTP answer, body already read and capped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpReply {
    pub status: u16,
    pub body: String,
    /// The `Retry-After` header, when present.
    pub retry_after: Option<String>,
}

/// Why a call produced no answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendError {
    /// The timeout won. ThreatSieve may still have done the work (and spent
    /// its source budgets), so the messages are retried later, not recorded
    /// as a failure.
    TimedOut,
    /// The call failed, or the answer was unreadable or too large.
    Failed(String),
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TimedOut => write!(f, "timed out"),
            Self::Failed(e) => write!(f, "{e}"),
        }
    }
}

pub type HttpFuture<'a> = Pin<Box<dyn Future<Output = Result<HttpReply, SendError>> + 'a>>;

/// Sends a request. The Worker implementation calls ThreatSieve over its
/// service binding; tests use a fake.
pub trait ProviderHttp {
    fn send(&self, req: ProviderRequest) -> HttpFuture<'_>;
}

/// Everything a batch needs.
pub struct Deps<'a> {
    pub store: &'a dyn Store,
    /// The ThreatSieve service binding, when the Worker has one.
    pub threatsieve: Option<&'a dyn ProviderHttp>,
    /// Reads a Worker secret by name.
    pub secret: &'a dyn Fn(&str) -> Option<String>,
    /// The operator's ASN table, when one is uploaded.
    pub asn: Option<&'a AsnTable>,
    pub config: &'a EnrichConfig,
    pub now_ms: i64,
}

/// What happened with one provider for one message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderResult {
    Cached,
    BackingOff,
    /// A row written (possibly with no Facts: "not found"), Facts dropped by
    /// validation, and whether the row is kept for this tenant only.
    Written {
        facts: usize,
        dropped: usize,
        restricted: bool,
    },
    MinuteBudgetSpent,
    DayBudgetSpent,
    /// Not asked: the binding, the key or the ASN dataset is missing.
    NotConfigured(String),
    /// Asked and failed; recorded for backoff.
    Failed(String),
}

/// What to do with a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Ack,
    /// Retry the message later: D1 failed, a minute budget was spent, or
    /// ThreatSieve asked for a wait (`Retry-After`).
    Retry {
        delay_secs: u32,
    },
    /// The message itself is bad; acknowledge and log.
    Drop,
}

/// Delay before retrying after a store failure.
pub const STORE_RETRY_SECS: u32 = 30;
/// Delay before retrying after a spent minute budget.
pub const MINUTE_RETRY_SECS: u32 = 60;
/// Delay before retrying after a lookup timed out.
pub const TIMEOUT_RETRY_SECS: u32 = 120;

pub type MessageReport = (Outcome, Vec<(String, ProviderResult)>);

fn retry(out: &mut MessageReport, delay_secs: u32) {
    match out.0 {
        Outcome::Drop => {}
        Outcome::Retry { delay_secs: d } if d >= delay_secs => {}
        _ => out.0 = Outcome::Retry { delay_secs },
    }
}

/// Process one queue batch. Returns one report per message, in order.
/// Never panics; provider failures are recorded and acknowledged (the next
/// sighting retries after the backoff), store failures retry the message.
pub async fn process_batch(msgs: &[EnrichMessage], d: &Deps<'_>) -> Vec<MessageReport> {
    let mut out: Vec<MessageReport> = msgs.iter().map(|_| (Outcome::Ack, Vec::new())).collect();
    let mut lookups: Vec<usize> = Vec::new();
    // Observables with a ThreatSieve failure on record, so a success only
    // spends a D1 query clearing the ones that have something to clear.
    let mut had_failure: BTreeSet<Observable> = BTreeSet::new();
    for (i, msg) in msgs.iter().enumerate() {
        if !msg.problems().is_empty() {
            out[i].0 = Outcome::Drop;
            continue;
        }
        let o = &msg.observable;
        let fresh = match d
            .store
            .enrichment_cache(vec![o.clone()], d.now_ms, 1, Some(msg.tenant_id.clone()))
            .await
        {
            Ok(rows) => rows,
            Err(_) => {
                retry(&mut out[i], STORE_RETRY_SECS);
                continue;
            }
        };
        let failures = match d.store.enrich_failures(o.clone()).await {
            Ok(f) => {
                if f.iter().any(|f| f.provider == THREATSIEVE) {
                    had_failure.insert(o.clone());
                }
                f
            }
            Err(_) => {
                retry(&mut out[i], STORE_RETRY_SECS);
                continue;
            }
        };
        for (id, step) in plan(d.config, o, &fresh, &failures, d.now_ms) {
            let result = match step {
                Step::Cached => ProviderResult::Cached,
                Step::BackingOff { .. } => ProviderResult::BackingOff,
                Step::Local => match local(o, d).await {
                    Ok(r) => r,
                    Err(()) => {
                        retry(&mut out[i], STORE_RETRY_SECS);
                        continue;
                    }
                },
                Step::Lookup => {
                    lookups.push(i);
                    continue;
                }
            };
            out[i].1.push((id.to_string(), result));
        }
    }
    if !lookups.is_empty() {
        threatsieve(msgs, &lookups, &had_failure, d, &mut out).await;
    }
    out
}

/// Write one cache row. `Err(())` means the store failed.
async fn write(
    d: &Deps<'_>,
    provider: &str,
    o: &Observable,
    ttl_secs: u64,
    facts: Vec<Fact>,
    tenant_id: Option<String>,
) -> Result<(usize, usize), ()> {
    let (facts, dropped) = valid_facts(provider, facts);
    let n = facts.len();
    d.store
        .upsert_enrich_cache(CacheEntry {
            provider: provider.to_string(),
            observable: o.clone(),
            fetched_at: d.now_ms,
            ttl_secs,
            facts,
            tenant_id,
        })
        .await
        .map_err(|_| ())?;
    Ok((n, dropped))
}

async fn local(o: &Observable, d: &Deps<'_>) -> Result<ProviderResult, ()> {
    let Some(table) = d.asn else {
        return Ok(ProviderResult::NotConfigured(
            "no ASN dataset uploaded".into(),
        ));
    };
    match table.enrich(o, d.now_ms) {
        Ok(facts) => {
            let ttl = if facts.is_empty() {
                d.config.cache.negative_ttl_secs
            } else {
                d.config.providers.local_asn.ttl_secs
            };
            let (facts, dropped) = write(d, LOCAL_ASN, o, ttl, facts, None).await?;
            Ok(ProviderResult::Written {
                facts,
                dropped,
                restricted: false,
            })
        }
        Err(e) => Ok(ProviderResult::NotConfigured(e.to_string())),
    }
}

/// Error text kept in D1: one line, at most 200 characters.
fn clip(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(200).collect()
}

/// Ask ThreatSieve about every observable of `lookups` (indices into
/// `msgs`), `batch_size` at a time.
async fn threatsieve(
    msgs: &[EnrichMessage],
    lookups: &[usize],
    had_failure: &BTreeSet<Observable>,
    d: &Deps<'_>,
    out: &mut [MessageReport],
) {
    let t = &d.config.providers.threatsieve;
    let not_configured = |out: &mut [MessageReport], why: String| {
        for &i in lookups {
            out[i].1.push((
                THREATSIEVE.to_string(),
                ProviderResult::NotConfigured(why.clone()),
            ));
        }
    };
    let Some(http) = d.threatsieve else {
        not_configured(out, format!("service binding {} is not bound", t.binding));
        return;
    };
    let Some(key) = (d.secret)(&t.api_key_env).filter(|k| !k.is_empty()) else {
        not_configured(out, format!("secret {} is not set", t.api_key_env));
        return;
    };
    let mut order: Vec<Observable> = Vec::new();
    let mut seen: BTreeSet<&Observable> = BTreeSet::new();
    for &i in lookups {
        if seen.insert(&msgs[i].observable) {
            order.push(msgs[i].observable.clone());
        }
    }
    let size = t.batch_size.clamp(1, MAX_LOOKUP_BATCH);
    for chunk in order.chunks(size) {
        let asked: Vec<usize> = lookups
            .iter()
            .copied()
            .filter(|&i| chunk.contains(&msgs[i].observable))
            .collect();
        let priority = asked
            .iter()
            .map(|&i| msgs[i].priority)
            .max()
            .unwrap_or(foiled_core::enrich_pipeline::Priority::Normal);
        let mark = |out: &mut [MessageReport], r: ProviderResult| {
            for &i in &asked {
                out[i].1.push((THREATSIEVE.to_string(), r.clone()));
            }
        };
        match d
            .store
            .take_enrich_budget(
                THREATSIEVE,
                d.now_ms,
                t.rate_limit.per_minute,
                day_limit_for(t.rate_limit.per_day, priority),
            )
            .await
        {
            Ok(BudgetOutcome::Taken) => {}
            Ok(BudgetOutcome::MinuteSpent) => {
                mark(out, ProviderResult::MinuteBudgetSpent);
                for &i in &asked {
                    retry(&mut out[i], MINUTE_RETRY_SECS);
                }
                continue;
            }
            Ok(BudgetOutcome::DaySpent) => {
                mark(out, ProviderResult::DayBudgetSpent);
                continue;
            }
            Err(_) => {
                for &i in &asked {
                    retry(&mut out[i], STORE_RETRY_SECS);
                }
                continue;
            }
        }
        let reply = http.send(lookup_request(chunk, &t.include, &key)).await;
        let failed = |error: String, retry_at: Option<i64>| async move {
            for o in chunk {
                // A store failure here only loses the backoff record.
                let _ = d
                    .store
                    .record_enrich_failure(THREATSIEVE, o.clone(), d.now_ms, clip(&error), retry_at)
                    .await;
            }
            ProviderResult::Failed(error)
        };
        let reply = match reply {
            Ok(r) => r,
            Err(SendError::TimedOut) => {
                // Not a failure on record: retry these messages later.
                mark(out, ProviderResult::Failed("threatsieve: timed out".into()));
                for &i in &asked {
                    retry(&mut out[i], TIMEOUT_RETRY_SECS);
                }
                continue;
            }
            Err(SendError::Failed(e)) => {
                let r = failed(format!("threatsieve: {e}"), None).await;
                mark(out, r);
                continue;
            }
        };
        match lookup_outcome(
            reply.status,
            reply.retry_after.as_deref(),
            &reply.body,
            d.now_ms,
            d.config,
        ) {
            Ok(mapped) => {
                for o in chunk {
                    let askers: Vec<usize> = asked
                        .iter()
                        .copied()
                        .filter(|&i| &msgs[i].observable == o)
                        .collect();
                    // ThreatSieve answers every value it accepts, folding
                    // spellings it treats as one (`answer_for`). A value
                    // still left out is not cached as "not found": it backs
                    // off like a failure.
                    let Some(m) = answer_for(o, &mapped) else {
                        let error = "threatsieve: no answer for this value".to_string();
                        let _ = d
                            .store
                            .record_enrich_failure(
                                THREATSIEVE,
                                o.clone(),
                                d.now_ms,
                                error.clone(),
                                None,
                            )
                            .await;
                        for &i in &askers {
                            out[i].1.push((
                                THREATSIEVE.to_string(),
                                ProviderResult::Failed(error.clone()),
                            ));
                        }
                        continue;
                    };
                    // A value ThreatSieve rejected is not cached; it backs
                    // off like any failure.
                    if let Some(code) = &m.error {
                        let error = format!("threatsieve: rejected the value ({code})");
                        let _ = d
                            .store
                            .record_enrich_failure(
                                THREATSIEVE,
                                o.clone(),
                                d.now_ms,
                                clip(&error),
                                None,
                            )
                            .await;
                        for &i in &askers {
                            out[i].1.push((
                                THREATSIEVE.to_string(),
                                ProviderResult::Failed(error.clone()),
                            ));
                        }
                        continue;
                    }
                    // Restricted answers are kept for each tenant that asked
                    // and never shared; the rest are one shared row.
                    let scopes: Vec<Option<String>> = if m.restricted {
                        askers
                            .iter()
                            .map(|&i| Some(msgs[i].tenant_id.clone()))
                            .collect::<BTreeSet<_>>()
                            .into_iter()
                            .collect()
                    } else {
                        vec![None]
                    };
                    let mut result = None;
                    for scope in scopes {
                        match write(d, m.provider(), o, m.ttl_secs, m.facts.clone(), scope).await {
                            Ok((facts, dropped)) => {
                                result = Some(ProviderResult::Written {
                                    facts,
                                    dropped,
                                    restricted: m.restricted,
                                });
                            }
                            Err(()) => {
                                result = None;
                                break;
                            }
                        }
                    }
                    if result.is_some() && had_failure.contains(o) {
                        let _ = d.store.clear_enrich_failure(THREATSIEVE, o.clone()).await;
                    }
                    for &i in &askers {
                        match &result {
                            Some(r) => out[i].1.push((THREATSIEVE.to_string(), r.clone())),
                            None => retry(&mut out[i], STORE_RETRY_SECS),
                        }
                    }
                }
            }
            Err(LookupError::RateLimited { retry_after_secs }) => {
                let at = d.now_ms + i64::from(retry_after_secs) * 1000;
                let r = failed(
                    format!("threatsieve: rate limited, retry after {retry_after_secs} s"),
                    Some(at),
                )
                .await;
                mark(out, r);
                for &i in &asked {
                    retry(&mut out[i], retry_after_secs);
                }
            }
            Err(e) => {
                let r = failed(format!("threatsieve: {e}"), None).await;
                mark(out, r);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_are_clipped_to_one_short_line() {
        let e = clip(&format!("a\nb{}", "x".repeat(500)));
        assert!(!e.contains('\n'));
        assert_eq!(e.chars().count(), 200);
    }

    #[test]
    fn retries_keep_the_longest_delay_and_never_undo_a_drop() {
        let mut r: MessageReport = (Outcome::Ack, vec![]);
        retry(&mut r, 30);
        retry(&mut r, 10);
        assert_eq!(r.0, Outcome::Retry { delay_secs: 30 });
        retry(&mut r, 120);
        assert_eq!(r.0, Outcome::Retry { delay_secs: 120 });
        let mut dropped: MessageReport = (Outcome::Drop, vec![]);
        retry(&mut dropped, 30);
        assert_eq!(dropped.0, Outcome::Drop);
    }
}
