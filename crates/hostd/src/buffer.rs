//! Local buffer for capture envelopes while the control plane is
//! unreachable (#41, same semantics as edge sensors in #31).
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
        let mut out = Vec::new();
        for (_, p) in self.segments()? {
            for line in BufReader::new(fs::File::open(p)?).lines() {
                if out.len() >= max {
                    return Ok(out);
                }
                if let Ok(e) = serde_json::from_str(&line?) {
                    out.push(e);
                }
            }
        }
        Ok(out)
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
}
