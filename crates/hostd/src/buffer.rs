//! Local buffer for capture envelopes while the control plane is
//! unreachable (#41), shared by edge sensors (#31, ADR 0007). Default cap:
//! 1 GiB on a research host, 256 MiB on an edge sensor.
//!
//! Segments of JSON lines under `<state_dir>/buffer/`. When the total size
//! passes the cap, whole oldest segments are dropped and counted. Delivery
//! is at least once: events are removed only after the control plane
//! accepts them, and ingest is idempotent on `event_id`, so a crash between
//! send and commit cannot create duplicates downstream.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use foiled_core::capture::CaptureEvent;

const SEGMENT_BYTES: u64 = 1024 * 1024;

pub struct OfflineBuffer {
    dir: PathBuf,
    cap_bytes: u64,
    segment_bytes: u64,
    dropped: u64,
}

fn segment_no(p: &Path) -> Option<u64> {
    p.file_name()?
        .to_str()?
        .strip_prefix("seg-")?
        .strip_suffix(".jsonl")?
        .parse()
        .ok()
}

/// One peeked batch from [`OfflineBuffer::peek_batch`].
pub struct PeekedBatch {
    /// Valid events paired with the cumulative raw-line count up to (and
    /// including) each event, so partial commits advance past any preceding
    /// corrupt lines as well.
    pub items: Vec<(CaptureEvent, usize)>,
    /// Total raw lines scanned (including corrupt lines). Pass this to
    /// [`OfflineBuffer::commit`] once the batch is handled.
    pub raw_lines: usize,
    /// Number of corrupt lines skipped within `raw_lines`.
    pub corrupt: u64,
}

impl OfflineBuffer {
    pub fn open(dir: PathBuf, cap_bytes: u64) -> std::io::Result<Self> {
        Self::open_with_segments(dir, cap_bytes, SEGMENT_BYTES)
    }

    /// Like [`OfflineBuffer::open`] with a custom segment size. Dropping
    /// happens a whole segment at a time.
    pub fn open_with_segments(
        dir: PathBuf,
        cap_bytes: u64,
        segment_bytes: u64,
    ) -> std::io::Result<Self> {
        fs::create_dir_all(&dir)?;
        Ok(OfflineBuffer {
            dir,
            cap_bytes,
            segment_bytes,
            dropped: 0,
        })
    }

    fn segments(&self) -> std::io::Result<Vec<(u64, PathBuf)>> {
        let mut segs: Vec<(u64, PathBuf)> = fs::read_dir(&self.dir)?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter_map(|p| segment_no(&p).map(|n| (n, p)))
            .collect();
        segs.sort();
        Ok(segs)
    }

    fn total_bytes(&self) -> std::io::Result<u64> {
        let mut total = 0;
        for (_, p) in self.segments()? {
            total += fs::metadata(p)?.len();
        }
        Ok(total)
    }

    /// Events dropped because the buffer was full, since this process started.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Count events dropped for another reason, for example refused by
    /// ingest as invalid, so heartbeats show every loss.
    pub fn note_dropped(&mut self, n: u64) {
        self.dropped += n;
    }

    pub fn len(&self) -> std::io::Result<u64> {
        let mut n = 0;
        for (_, p) in self.segments()? {
            n += BufReader::new(fs::File::open(p)?).lines().count() as u64;
        }
        Ok(n)
    }

    pub fn is_empty(&self) -> std::io::Result<bool> {
        Ok(self.len()? == 0)
    }

    pub fn push(&mut self, event: &CaptureEvent) -> std::io::Result<()> {
        let line = serde_json::to_string(event)?;
        let segs = self.segments()?;
        let path = match segs.last() {
            Some((_, p)) if fs::metadata(p)?.len() < self.segment_bytes => p.clone(),
            Some((n, _)) => self.dir.join(format!("seg-{:012}.jsonl", n + 1)),
            None => self.dir.join("seg-000000000000.jsonl"),
        };
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        writeln!(f, "{line}")?;
        f.sync_data()?;
        self.enforce_cap()
    }

    fn enforce_cap(&mut self) -> std::io::Result<()> {
        loop {
            let segs = self.segments()?;
            if segs.len() <= 1 || self.total_bytes()? <= self.cap_bytes {
                return Ok(());
            }
            let (_, oldest) = &segs[0];
            self.dropped += BufReader::new(fs::File::open(oldest)?).lines().count() as u64;
            fs::remove_file(oldest)?;
        }
    }

    /// Up to `max` of the oldest events, without removing them.
    pub fn peek(&self, max: usize) -> std::io::Result<Vec<CaptureEvent>> {
        Ok(self
            .peek_batch(max)?
            .items
            .into_iter()
            .map(|(e, _)| e)
            .collect())
    }

    /// Up to `max` of the oldest valid events together with raw line counts so
    /// [`Self::commit`] advances past corrupt JSONL lines cleanly.
    pub fn peek_batch(&self, max: usize) -> std::io::Result<PeekedBatch> {
        let mut items = Vec::new();
        let mut raw_lines = 0usize;
        let mut corrupt = 0u64;
        for (_, p) in self.segments()? {
            for line in BufReader::new(fs::File::open(p)?).lines() {
                if items.len() >= max {
                    return Ok(PeekedBatch {
                        items,
                        raw_lines,
                        corrupt,
                    });
                }
                raw_lines += 1;
                match serde_json::from_str(&line?) {
                    Ok(e) => items.push((e, raw_lines)),
                    Err(_) => corrupt += 1,
                }
            }
        }
        Ok(PeekedBatch {
            items,
            raw_lines,
            corrupt,
        })
    }

    /// Remove the `n` oldest events after the control plane accepted them.
    pub fn commit(&mut self, mut n: usize) -> std::io::Result<()> {
        for (_, p) in self.segments()? {
            if n == 0 {
                break;
            }
            let lines: Vec<String> = BufReader::new(fs::File::open(&p)?)
                .lines()
                .collect::<Result<_, _>>()?;
            if lines.len() <= n {
                n -= lines.len();
                fs::remove_file(&p)?;
            } else {
                let rest = lines[n..].join("\n") + "\n";
                let tmp = p.with_extension("tmp");
                fs::write(&tmp, rest)?;
                fs::rename(tmp, &p)?;
                n = 0;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(i: u32) -> CaptureEvent {
        serde_json::from_value(serde_json::json!({
            "event_id": format!("e{i}"),
            "ts": 1_800_000_000_000i64,
            "decoy_id": "d1",
            "catalogue_id": "foiled/demo-app/1.0.0",
            "decoy_kind": "sandbox",
            "channel": "application",
            "severity": "info",
            "src": {"ip": "203.0.113.7"},
            "data": {"pad": "x".repeat(200)}
        }))
        .unwrap()
    }

    #[test]
    fn events_survive_reopen_and_commit_in_order() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut b = OfflineBuffer::open(dir.path().join("buf"), 1 << 30).unwrap();
            for i in 0..5 {
                b.push(&event(i)).unwrap();
            }
        }
        let mut b = OfflineBuffer::open(dir.path().join("buf"), 1 << 30).unwrap();
        assert_eq!(b.len().unwrap(), 5);
        let first: Vec<String> = b.peek(2).unwrap().into_iter().map(|e| e.event_id).collect();
        assert_eq!(first, vec!["e0", "e1"]);
        b.commit(2).unwrap();
        assert_eq!(b.peek(1).unwrap()[0].event_id, "e2");
        b.commit(3).unwrap();
        assert!(b.is_empty().unwrap());
    }

    #[test]
    fn oldest_segments_are_dropped_over_the_cap() {
        let dir = tempfile::tempdir().unwrap();
        // ~400 byte events, 16 KiB segments, 64 KiB cap.
        let mut b = OfflineBuffer::open_with_segments(dir.path().join("buf"), 64 * 1024, 16 * 1024)
            .unwrap();
        for i in 0..600 {
            b.push(&event(i)).unwrap();
        }
        assert!(b.dropped() > 0, "something must have been dropped");
        assert!(b.total_bytes().unwrap() <= 64 * 1024 + 16 * 1024);
        let oldest = b.peek(1).unwrap()[0].event_id.clone();
        assert_ne!(oldest, "e0", "the oldest events go first");
        assert_eq!(b.len().unwrap() + b.dropped(), 600, "nothing lost silently");
    }

    #[test]
    fn corrupt_lines_advance_without_stalling_or_duplicating() {
        let dir = tempfile::tempdir().unwrap();
        let buf_dir = dir.path().join("buf");
        let mut b = OfflineBuffer::open(buf_dir.clone(), 1 << 30).unwrap();
        b.push(&event(0)).unwrap();
        let seg = b.segments().unwrap().pop().unwrap().1;
        let mut content = fs::read_to_string(&seg).unwrap();
        content = format!("not-json\n{content}also-corrupt\n");
        fs::write(&seg, content).unwrap();

        let batch = b.peek_batch(10).unwrap();
        assert_eq!(batch.items.len(), 1);
        assert_eq!(batch.items[0].0.event_id, "e0");
        assert_eq!(batch.items[0].1, 2);
        assert_eq!(batch.raw_lines, 3);
        assert_eq!(batch.corrupt, 2);

        b.commit(batch.raw_lines).unwrap();
        assert!(b.is_empty().unwrap());
    }
}
