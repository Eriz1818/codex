//! Lightweight hooks performance measurements.
//!
//! This is intentionally not a Criterion benchmark: it should run quickly and
//! without extra dependencies, and produce copy/pasteable numbers for docs.

use std::io::Write;
use std::process::Command;
use std::process::Stdio;
use std::time::Duration;
use std::time::Instant;

use codex_core::hooks::HookNotification;
use codex_core::hooks::HookPayload;
use codex_core::hooks::ToolCallStatus;
use uuid::Uuid;

#[derive(serde::Serialize)]
struct HookHostLine<'a> {
    #[serde(rename = "schema-version")]
    schema_version: u32,
    #[serde(rename = "type")]
    ty: &'static str,
    seq: u64,
    event: &'a HookPayload,
}

fn build_payload() -> HookPayload {
    HookPayload::new(HookNotification::ToolCallFinished {
        thread_id: "thread-1".to_string(),
        turn_id: "turn-1".to_string(),
        cwd: "/tmp".to_string(),
        model_request_id: Uuid::new_v4(),
        attempt: 1,
        tool_name: "exec".to_string(),
        call_id: "call-1".to_string(),
        status: ToolCallStatus::Completed,
        duration_ms: 12,
        success: true,
        output_bytes: 34,
        output_preview: None,
    })
}

fn avg_per_iter(elapsed: Duration, iters: u64) -> Duration {
    if iters == 0 {
        return Duration::ZERO;
    }
    Duration::from_nanos((elapsed.as_nanos() / iters as u128) as u64)
}

fn bench_json_serialize(iters: u64, payload: &HookPayload) -> anyhow::Result<Duration> {
    let started = Instant::now();
    for i in 0..iters {
        let line = HookHostLine {
            schema_version: payload.schema_version(),
            ty: "hook-event",
            seq: i,
            event: payload,
        };
        let _ = serde_json::to_vec(&line)?;
    }
    Ok(started.elapsed())
}

fn bench_external_spawn(iters: u64, payload_json: &[u8]) -> anyhow::Result<Duration> {
    if !cfg!(unix) {
        anyhow::bail!("external spawn benchmark only supported on unix");
    }

    let started = Instant::now();
    for _ in 0..iters {
        let mut child = Command::new("/bin/sh")
            .args(["-c", "cat >/dev/null"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(payload_json)?;
        }
        let _ = child.wait()?;
    }
    Ok(started.elapsed())
}

fn bench_out_of_proc_host(iters: u64, payload: &HookPayload) -> anyhow::Result<Duration> {
    if !cfg!(unix) {
        anyhow::bail!("out-of-proc host benchmark only supported on unix");
    }

    let mut child = Command::new("/bin/sh")
        .args(["-c", "while IFS= read -r _line; do :; done"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow::anyhow!("host stdin pipe not available"))?;

    let started = Instant::now();
    for i in 0..iters {
        let line = HookHostLine {
            schema_version: payload.schema_version(),
            ty: "hook-event",
            seq: i,
            event: payload,
        };
        let mut bytes = serde_json::to_vec(&line)?;
        bytes.push(b'\n');
        stdin.write_all(&bytes)?;
    }
    drop(stdin);
    let _ = child.wait()?;
    Ok(started.elapsed())
}

fn bench_in_proc(iters: u64, payload: &HookPayload) -> Duration {
    let started = Instant::now();
    for _ in 0..iters {
        std::hint::black_box(payload.event_type());
    }
    started.elapsed()
}

fn parse_iters() -> u64 {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--iters"
            && let Some(value) = args.next()
            && let Ok(iters) = value.parse::<u64>()
        {
            return iters;
        }
    }
    200
}

fn main() -> anyhow::Result<()> {
    let iters = parse_iters();
    let payload = build_payload();

    let serialize_elapsed = bench_json_serialize(iters, &payload)?;

    let external_payload_json = serde_json::to_vec(&payload)?;
    let external_elapsed = bench_external_spawn(iters.min(50), &external_payload_json)?;

    let host_elapsed = bench_out_of_proc_host(iters, &payload)?;
    let inproc_elapsed = bench_in_proc(iters, &payload);

    println!("hooks perf (iters={iters})");
    println!(
        "serialize hook-event json: total={:?} avg/iter={:?}",
        serialize_elapsed,
        avg_per_iter(serialize_elapsed, iters)
    );
    println!(
        "external per-event spawn (iters={}): total={:?} avg/iter={:?}",
        iters.min(50),
        external_elapsed,
        avg_per_iter(external_elapsed, iters.min(50))
    );
    println!(
        "out-of-proc host jsonl: total={:?} avg/iter={:?}",
        host_elapsed,
        avg_per_iter(host_elapsed, iters)
    );
    println!(
        "in-proc (no-op): total={:?} avg/iter={:?}",
        inproc_elapsed,
        avg_per_iter(inproc_elapsed, iters)
    );
    println!("pyo3 in-proc: TBD");

    Ok(())
}
