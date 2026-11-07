//! `bench.run` through the engine: its cells as `Partial` events, and a cancel part-way
//! (docs/M6.md §10).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::{Arc, Mutex};

use beezip_commands::{
    Engine, ErrorCode, EventSink, JobEvent, NonInteractive, commands::BenchRunOutput, registry,
};
use serde_json::{Value, json};

/// Runs `bench.run`; `cancel_after` cancels the job once that many cells have arrived.
fn bench(args: Value, cancel_after: Option<usize>) -> (Result<Value, ErrorCode>, Vec<JobEvent>) {
    let engine = Engine::new(registry());
    let events = Arc::new(Mutex::new(Vec::new()));
    let (sink_events, eng) = (Arc::clone(&events), engine.clone());
    let job = Arc::new(Mutex::new(None));
    let sink_job = Arc::clone(&job);
    let sink: EventSink = Arc::new(move |e: JobEvent| {
        let mut events = sink_events.lock().unwrap();
        if let JobEvent::Started { job } = &e {
            *sink_job.lock().unwrap() = Some(*job);
        }
        events.push(e);
        let partials = events
            .iter()
            .filter(|e| matches!(e, JobEvent::Partial { .. }))
            .count();
        if cancel_after.is_some_and(|n| partials >= n)
            && let Some(id) = *sink_job.lock().unwrap()
        {
            eng.cancel(id);
        }
    });
    let result = engine
        .invoke("bench.run", args, Arc::new(NonInteractive), sink)
        .unwrap()
        .join()
        .map_err(|e| e.code);
    let events = events.lock().unwrap().clone();
    (result, events)
}

fn partials(events: &[JobEvent]) -> Vec<Value> {
    events
        .iter()
        .filter_map(|e| match e {
            JobEvent::Partial { output } => Some(output.clone()),
            _ => None,
        })
        .collect()
}

#[test]
fn cells_go_out_as_they_finish() {
    let (result, events) = bench(
        json!({ "grid": [{ "codec": "lz4" }, { "codec": "zstd", "level": 1 }], "bytes": "64k" }),
        None,
    );
    let out: BenchRunOutput = serde_json::from_value(result.unwrap()).unwrap();
    assert_eq!(out.sample.source, "built-in");
    assert_eq!(out.sample.bytes, 64 * 1024);
    assert!(!out.cancelled);
    assert_eq!(out.cells.len(), 2);
    assert!(out.cells.iter().all(|c| c.error.is_none() && c.ratio > 0.0));
    assert_eq!(out.cells[1].level, Some(1));
    // Each cell went out on its own, before the end, as the output has it.
    let sent = partials(&events);
    assert_eq!(
        sent,
        serde_json::to_value(&out.cells)
            .unwrap()
            .as_array()
            .unwrap()[..]
    );
    let finished = events
        .iter()
        .position(|e| matches!(e, JobEvent::Finished { .. }))
        .unwrap();
    assert_eq!(finished, events.len() - 1);
    // Progress names the cell and counts them.
    let last = events
        .iter()
        .rev()
        .find_map(|e| match e {
            JobEvent::Progress(p) => Some(p.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(last.entries_total, Some(2));
    assert!(last.current.unwrap().starts_with("zstd -1"));
}

#[test]
fn a_cancelled_run_returns_the_cells_it_finished() {
    let (result, events) = bench(
        json!({ "grid": [{ "codec": "lz4" }, { "codec": "snappy" }, { "codec": "gzip" }, { "codec": "xz", "level": 9 }], "bytes": "1m" }),
        Some(1),
    );
    // Not an error: the output says it was cancelled.
    let out: BenchRunOutput = serde_json::from_value(result.unwrap()).unwrap();
    assert!(out.cancelled);
    assert!(
        !out.cells.is_empty() && out.cells.len() < 4,
        "{}",
        out.cells.len()
    );
    assert_eq!(partials(&events).len(), out.cells.len());
}

#[test]
fn a_file_is_sampled() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("data.bin");
    std::fs::write(&path, vec![7u8; 100_000]).unwrap();
    let (result, _) = bench(
        json!({ "sample": path, "grid": [{ "codec": "gzip", "level": 9 }], "bytes": 32_000 }),
        None,
    );
    let out: BenchRunOutput = serde_json::from_value(result.unwrap()).unwrap();
    assert_eq!(out.sample.bytes, 32_000);
    assert_eq!(out.sample.source, path.display().to_string());
    assert!(out.cells[0].ratio < 0.05);
}

#[test]
fn bad_grids_and_sizes_are_refused() {
    for args in [
        json!({ "grid": [] }),
        json!({ "grid": [{ "codec": "gzip", "level": 10 }] }),
        json!({ "grid": [{ "codec": "lz4", "level": 1 }] }),
        json!({ "bytes": 0 }),
        json!({ "bytes": "2g" }),
        json!({ "grid": "fastest" }),
    ] {
        let (result, _) = bench(args.clone(), None);
        assert_eq!(result.unwrap_err(), ErrorCode::InvalidArgs, "{args}");
    }
    let (result, _) = bench(json!({ "sample": "C:/no/such/file.bin" }), None);
    assert_eq!(result.unwrap_err(), ErrorCode::NotFound);
}
