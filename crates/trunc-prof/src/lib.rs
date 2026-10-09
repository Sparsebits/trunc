//! A span profiler for trunc.
//!
//! Code marks regions with [`span`]: the returned guard measures until it is dropped, and can
//! carry a byte count so the summary shows throughput. Profiling is off unless [`enable`] is
//! called (the CLI does so for `--profile`); a span then costs one relaxed atomic load.
//!
//! When enabled, every span becomes an event: name, thread, start, duration, bytes. The CLI
//! turns them into
//! - a Chrome trace ([`chrome_trace`]): every thread on a timeline, for
//!   <https://ui.perfetto.dev>, `chrome://tracing` or <https://www.speedscope.app>;
//! - a summary table ([`summary`]): calls, total and self time (time not spent in nested
//!   spans on the same thread), bytes and throughput per span name, by self time.
//!
//! Span names are dotted by layer: `fs.*` for filesystem calls, `zstd.*`, `xz.*`, … for
//! decoders, `consume.*`, `extract.*`, `create.*` for engine phases.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::Instant;

static ENABLED: AtomicBool = AtomicBool::new(false);
static EPOCH: OnceLock<Instant> = OnceLock::new();
static EVENTS: Mutex<Vec<Event>> = Mutex::new(Vec::new());
static DROPPED: AtomicU64 = AtomicU64::new(0);
static NEXT_TID: AtomicU64 = AtomicU64::new(1);
/// Events kept at most (about 200 MiB); later ones are counted and dropped.
const MAX_EVENTS: usize = 5_000_000;

thread_local! {
    static TID: u64 = NEXT_TID.fetch_add(1, Ordering::Relaxed);
}

/// One finished span.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub name: &'static str,
    /// Small per-process thread number (1 is the first thread that recorded a span).
    pub tid: u64,
    /// Nanoseconds since profiling was enabled.
    pub start_ns: u64,
    pub dur_ns: u64,
    pub bytes: u64,
}

/// Start recording spans.
pub fn enable() {
    EPOCH.get_or_init(Instant::now);
    ENABLED.store(true, Ordering::Release);
}

/// Whether spans are being recorded.
#[inline]
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// A region being measured; recorded when dropped.
#[must_use = "a span measures until it is dropped"]
#[derive(Debug)]
pub struct Span {
    name: &'static str,
    start: Option<Instant>,
    bytes: u64,
}

/// Measure from now until the returned guard is dropped.
#[inline]
pub fn span(name: &'static str) -> Span {
    Span {
        name,
        start: if enabled() {
            Some(Instant::now())
        } else {
            None
        },
        bytes: 0,
    }
}

impl Span {
    /// Count `n` more bytes processed in this span.
    #[inline]
    pub fn add_bytes(&mut self, n: u64) {
        self.bytes += n;
    }

    /// The same span, counting `n` bytes.
    #[inline]
    pub fn bytes(mut self, n: u64) -> Self {
        self.bytes = n;
        self
    }
}

impl Drop for Span {
    #[inline]
    fn drop(&mut self) {
        if let Some(start) = self.start {
            record(self.name, start, self.bytes);
        }
    }
}

/// Run `f` inside a span named `name`.
#[inline]
pub fn time<T>(name: &'static str, f: impl FnOnce() -> T) -> T {
    let _s = span(name);
    f()
}

fn nanos(d: std::time::Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

#[cold]
fn record(name: &'static str, start: Instant, bytes: u64) {
    let end = Instant::now();
    let epoch = *EPOCH.get_or_init(Instant::now);
    let ev = Event {
        name,
        tid: TID.with(|t| *t),
        start_ns: nanos(start.saturating_duration_since(epoch)),
        dur_ns: nanos(end.saturating_duration_since(start)),
        bytes,
    };
    let mut events = EVENTS.lock().unwrap_or_else(PoisonError::into_inner);
    if events.len() < MAX_EVENTS {
        events.push(ev);
    } else {
        DROPPED.fetch_add(1, Ordering::Relaxed);
    }
}

/// Every event recorded so far (and the count of those dropped over the limit), leaving none.
pub fn take() -> (Vec<Event>, u64) {
    let events = std::mem::take(&mut *EVENTS.lock().unwrap_or_else(PoisonError::into_inner));
    (events, DROPPED.swap(0, Ordering::Relaxed))
}

fn json_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// The events as a Chrome trace (Trace Event Format, complete events in microseconds).
pub fn chrome_trace(events: &[Event], process: &str) -> String {
    let mut out = String::with_capacity(events.len() * 96 + 256);
    out.push_str("{\"displayTimeUnit\":\"ms\",\"traceEvents\":[");
    out.push_str("{\"ph\":\"M\",\"pid\":1,\"tid\":0,\"name\":\"process_name\",\"args\":{\"name\":");
    json_str(&mut out, process);
    out.push_str("}}");
    let mut tids: Vec<u64> = events.iter().map(|e| e.tid).collect();
    tids.sort_unstable();
    tids.dedup();
    for t in &tids {
        let _ = write!(
            out,
            ",{{\"ph\":\"M\",\"pid\":1,\"tid\":{t},\"name\":\"thread_name\",\"args\":{{\"name\":\"{}\"}}}}",
            if *t == 1 {
                "main".to_string()
            } else {
                format!("worker {t}")
            }
        );
    }
    for e in events {
        out.push_str(",{\"ph\":\"X\",\"pid\":1,\"tid\":");
        let _ = write!(out, "{},\"name\":", e.tid);
        json_str(&mut out, e.name);
        let _ = write!(
            out,
            ",\"ts\":{}.{:03},\"dur\":{}.{:03}",
            e.start_ns / 1000,
            e.start_ns % 1000,
            e.dur_ns / 1000,
            e.dur_ns % 1000
        );
        if e.bytes > 0 {
            let _ = write!(out, ",\"args\":{{\"bytes\":{}}}", e.bytes);
        }
        out.push('}');
    }
    out.push_str("]}\n");
    out
}

/// Totals for one span name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Row {
    pub name: &'static str,
    pub calls: u64,
    pub total_ns: u64,
    /// Time not covered by nested spans on the same thread.
    pub self_ns: u64,
    pub bytes: u64,
}

/// For each event, the time covered by spans nested in it and the span it is nested in. Spans
/// on one thread nest, because guards drop in reverse order.
fn nesting(events: &[Event]) -> (Vec<u64>, Vec<Option<usize>>) {
    let mut by_thread: HashMap<u64, Vec<usize>> = HashMap::new();
    for (i, e) in events.iter().enumerate() {
        by_thread.entry(e.tid).or_default().push(i);
    }
    let mut nested = vec![0u64; events.len()];
    let mut parent_of = vec![None; events.len()];
    for idx in by_thread.values_mut() {
        idx.sort_by_key(|&i| (events[i].start_ns, std::cmp::Reverse(events[i].dur_ns)));
        let mut stack: Vec<usize> = Vec::new();
        for &i in idx.iter() {
            let e = &events[i];
            let end = e.start_ns + e.dur_ns;
            while let Some(&top) = stack.last() {
                let t = &events[top];
                if e.start_ns >= t.start_ns + t.dur_ns {
                    stack.pop();
                } else {
                    break;
                }
            }
            if let Some(&parent) = stack.last() {
                let p = &events[parent];
                if end <= p.start_ns + p.dur_ns {
                    nested[parent] += e.dur_ns;
                    parent_of[i] = Some(parent);
                }
            }
            stack.push(i);
        }
    }
    (nested, parent_of)
}

/// Per-name totals, by self time (largest first).
pub fn rows(events: &[Event]) -> Vec<Row> {
    let (nested, _) = nesting(events);
    let mut map: HashMap<&'static str, Row> = HashMap::new();
    for (i, e) in events.iter().enumerate() {
        let r = map.entry(e.name).or_insert_with(|| Row {
            name: e.name,
            ..Row::default()
        });
        r.calls += 1;
        r.total_ns += e.dur_ns;
        r.self_ns += e.dur_ns.saturating_sub(nested[i]);
        r.bytes += e.bytes;
    }
    let mut rows: Vec<Row> = map.into_values().collect();
    rows.sort_by(|a, b| b.self_ns.cmp(&a.self_ns).then(a.name.cmp(b.name)));
    rows
}

/// Totals for one call path (`outer > inner > leaf`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PathRow {
    pub path: String,
    pub calls: u64,
    pub self_ns: u64,
}

/// Self time by call path, largest first: where the time went, and who asked for it.
pub fn paths(events: &[Event]) -> Vec<PathRow> {
    let (nested, parent_of) = nesting(events);
    // Intern each event's path as (parent path id, name).
    let mut ids: HashMap<(usize, &'static str), usize> = HashMap::new();
    let mut names: Vec<(usize, &'static str)> = vec![(0, "")];
    let mut path_id = vec![usize::MAX; events.len()];
    fn resolve(
        i: usize,
        events: &[Event],
        parent_of: &[Option<usize>],
        path_id: &mut [usize],
        ids: &mut HashMap<(usize, &'static str), usize>,
        names: &mut Vec<(usize, &'static str)>,
    ) -> usize {
        // Walk up to the first ancestor with a known path, then intern on the way down.
        let mut chain = vec![i];
        while let Some(p) = parent_of[*chain.last().expect("non-empty")] {
            if path_id[p] != usize::MAX {
                break;
            }
            chain.push(p);
        }
        let top = *chain.last().expect("non-empty");
        let mut id = parent_of[top].map_or(0, |p| path_id[p]);
        for &k in chain.iter().rev() {
            let key = (id, events[k].name);
            id = *ids.entry(key).or_insert_with(|| {
                names.push(key);
                names.len() - 1
            });
            path_id[k] = id;
        }
        id
    }
    let mut totals: HashMap<usize, (u64, u64)> = HashMap::new();
    for i in 0..events.len() {
        let id = if path_id[i] == usize::MAX {
            resolve(i, events, &parent_of, &mut path_id, &mut ids, &mut names)
        } else {
            path_id[i]
        };
        let t = totals.entry(id).or_default();
        t.0 += 1;
        t.1 += events[i].dur_ns.saturating_sub(nested[i]);
    }
    let text = |mut id: usize| {
        let mut parts = Vec::new();
        while id != 0 {
            let (parent, name) = names[id];
            parts.push(name);
            id = parent;
        }
        parts.reverse();
        parts.join(" > ")
    };
    let mut out: Vec<PathRow> = totals
        .into_iter()
        .map(|(id, (calls, self_ns))| PathRow {
            path: text(id),
            calls,
            self_ns,
        })
        .collect();
    out.sort_by(|a, b| b.self_ns.cmp(&a.self_ns).then(a.path.cmp(&b.path)));
    out
}

fn dur(ns: u64) -> String {
    #[allow(clippy::cast_precision_loss)]
    let f = ns as f64;
    if ns >= 1_000_000_000 {
        format!("{:.2} s", f / 1e9)
    } else if ns >= 1_000_000 {
        format!("{:.1} ms", f / 1e6)
    } else if ns >= 1_000 {
        format!("{:.1} us", f / 1e3)
    } else {
        format!("{ns} ns")
    }
}

fn size(b: u64) -> String {
    #[allow(clippy::cast_precision_loss)]
    let f = b as f64;
    if b >= 1 << 30 {
        format!("{:.2} GiB", f / f64::from(1u32 << 30))
    } else if b >= 1 << 20 {
        format!("{:.1} MiB", f / f64::from(1u32 << 20))
    } else if b >= 1 << 10 {
        format!("{:.1} KiB", f / 1024.0)
    } else {
        format!("{b} B")
    }
}

/// A readable table of [`rows`], headed by wall time and span count. `limit` caps the rows.
pub fn summary(events: &[Event], dropped: u64, limit: usize) -> String {
    let mut out = String::new();
    let start = events.iter().map(|e| e.start_ns).min().unwrap_or(0);
    let end = events
        .iter()
        .map(|e| e.start_ns + e.dur_ns)
        .max()
        .unwrap_or(0);
    let mut threads: Vec<u64> = events.iter().map(|e| e.tid).collect();
    threads.sort_unstable();
    threads.dedup();
    let _ = writeln!(
        out,
        "profile: {} wall, {} spans on {} thread{}{}",
        dur(end - start),
        events.len(),
        threads.len(),
        if threads.len() == 1 { "" } else { "s" },
        if dropped > 0 {
            format!(" ({dropped} more dropped over the limit)")
        } else {
            String::new()
        }
    );
    let _ = writeln!(
        out,
        "{:>10} {:>10} {:>9} {:>10} {:>11} {:>10}  span",
        "self", "total", "calls", "mean", "bytes", "MB/s"
    );
    let all = rows(events);
    for r in all.iter().take(limit) {
        #[allow(clippy::cast_precision_loss)]
        let rate = if r.bytes > 0 && r.total_ns > 0 {
            format!("{:.1}", r.bytes as f64 / (r.total_ns as f64 / 1e9) / 1e6)
        } else {
            String::new()
        };
        let _ = writeln!(
            out,
            "{:>10} {:>10} {:>9} {:>10} {:>11} {:>10}  {}",
            dur(r.self_ns),
            dur(r.total_ns),
            r.calls,
            dur(r.total_ns / r.calls.max(1)),
            if r.bytes > 0 {
                size(r.bytes)
            } else {
                String::new()
            },
            rate,
            r.name
        );
    }
    if all.len() > limit {
        let _ = writeln!(
            out,
            "({} more span names; see the trace file)",
            all.len() - limit
        );
    }
    let _ = writeln!(out, "hot paths (self time by call path):");
    for p in paths(events).iter().take(limit.min(15)) {
        let _ = writeln!(out, "{:>10} {:>9}  {}", dur(p.self_ns), p.calls, p.path);
    }
    out.push_str(
        "(self: time not spent in nested spans on the same thread; parallel threads add up)\n",
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(name: &'static str, tid: u64, start_ns: u64, dur_ns: u64, bytes: u64) -> Event {
        Event {
            name,
            tid,
            start_ns,
            dur_ns,
            bytes,
        }
    }

    #[test]
    fn self_time_subtracts_nested_spans_per_thread() {
        let events = [
            ev("outer", 1, 0, 120, 0),
            ev("inner", 1, 10, 30, 0),
            ev("inner", 1, 50, 20, 0),
            ev("leaf", 1, 55, 5, 0),
            // Another thread overlapping in time is not nested.
            ev("other", 2, 20, 50, 4096),
        ];
        let r = rows(&events);
        let get = |n: &str| r.iter().find(|x| x.name == n).unwrap().clone();
        assert_eq!((get("outer").total_ns, get("outer").self_ns), (120, 70));
        assert_eq!((get("inner").calls, get("inner").self_ns), (2, 45));
        assert_eq!(get("leaf").self_ns, 5);
        assert_eq!((get("other").self_ns, get("other").bytes), (50, 4096));
        assert_eq!(r[0].name, "outer");
        let p = paths(&events);
        let get = |n: &str| p.iter().find(|x| x.path == n).unwrap().clone();
        assert_eq!(get("outer").self_ns, 70);
        assert_eq!(
            (get("outer > inner").calls, get("outer > inner").self_ns),
            (2, 45)
        );
        assert_eq!(get("outer > inner > leaf").self_ns, 5);
        assert_eq!(get("other").self_ns, 50);
        let s = summary(&events, 0, 10);
        assert!(s.contains("2 threads") && s.contains("outer"), "{s}");
    }

    #[test]
    fn spans_record_only_when_enabled_and_export_as_json() {
        drop(span("before"));
        enable();
        {
            let _s = span("work").bytes(10);
            time("nested", || ());
        }
        let (events, dropped) = take();
        assert_eq!(dropped, 0);
        let names: Vec<_> = events.iter().map(|e| e.name).collect();
        assert!(names.contains(&"work") && names.contains(&"nested"));
        assert!(!names.contains(&"before"));
        let json = chrome_trace(&events, "trunc \"x\"");
        assert!(json.starts_with("{\"displayTimeUnit\""), "{json}");
        assert!(json.contains("\"name\":\"work\"") && json.contains("\"bytes\":10"));
        assert!(json.contains("trunc \\\"x\\\""));
    }
}
