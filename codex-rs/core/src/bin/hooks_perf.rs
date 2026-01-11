use std::io::Write;
use std::process::Command;
use std::process::Stdio;
use std::time::Duration;
use std::time::Instant;

use codex_core::hooks::HookNotification;
use codex_core::hooks::HookPayload;
use codex_core::hooks::HookStdinEnvelope;

#[derive(Debug, Clone, Copy)]
struct BenchResult {
    iterations: usize,
    elapsed: Duration,
}

impl BenchResult {
    fn ns_per_iter(self) -> f64 {
        (self.elapsed.as_nanos() as f64) / (self.iterations as f64)
    }

    fn iters_per_sec(self) -> f64 {
        (self.iterations as f64) / self.elapsed.as_secs_f64()
    }
}

fn parse_usize_flag(args: &[String], flag: &str) -> Option<usize> {
    let idx = args.iter().position(|arg| arg == flag)?;
    let value = args.get(idx + 1)?;
    value.parse::<usize>().ok()
}

fn parse_string_flag<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    let idx = args.iter().position(|arg| arg == flag)?;
    let value = args.get(idx + 1)?;
    Some(value.as_str())
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|arg| arg == flag)
}

fn build_payload(payload_bytes_target: Option<usize>) -> HookPayload {
    let base = HookPayload::new(
        HookNotification::ToolCallFinished {
            thread_id: "thread-1".to_string(),
            turn_id: "turn-1".to_string(),
            cwd: "/tmp".to_string(),
            model_request_id: uuid::Uuid::nil(),
            attempt: 1,
            tool_name: "shell".to_string(),
            call_id: "call-1".to_string(),
            status: codex_core::hooks::ToolCallStatus::Completed,
            duration_ms: 1,
            success: true,
            output_bytes: 0,
            output_preview: None,
            tool_input: None,
            tool_response: None,
        },
        "PostToolUse",
    );

    let Some(target) = payload_bytes_target else {
        return base;
    };

    let base_len = serde_json::to_vec(&base)
        .map(|json| json.len())
        .unwrap_or(0);
    if target <= base_len {
        return base;
    }

    let pad_len = target.saturating_sub(base_len);
    HookPayload::new(
        HookNotification::ToolCallFinished {
            thread_id: "thread-1".to_string(),
            turn_id: "turn-1".to_string(),
            cwd: "/tmp".to_string(),
            model_request_id: uuid::Uuid::nil(),
            attempt: 1,
            tool_name: "shell".to_string(),
            call_id: "call-1".to_string(),
            status: codex_core::hooks::ToolCallStatus::Completed,
            duration_ms: 1,
            success: true,
            output_bytes: 0,
            output_preview: Some("x".repeat(pad_len)),
            tool_input: None,
            tool_response: None,
        },
        "PostToolUse",
    )
}

fn bench_inproc_baseline(iters: usize, warmup: usize) -> BenchResult {
    let mut x = 0u64;
    let inc = std::hint::black_box(1u64);

    for _ in 0..warmup {
        x = x.wrapping_add(inc);
        std::hint::black_box(x);
    }

    let start = Instant::now();
    for _ in 0..iters {
        x = x.wrapping_add(inc);
        std::hint::black_box(x);
    }
    let elapsed = start.elapsed();

    std::hint::black_box(x);
    BenchResult {
        iterations: iters,
        elapsed,
    }
}

fn bench_external_python_spawn(
    python: &str,
    payload: &HookPayload,
    payload_dir: &std::path::Path,
    max_stdin_bytes: usize,
    iters: usize,
    warmup: usize,
) -> anyhow::Result<BenchResult> {
    let payload_json = serde_json::to_vec(payload)?;
    let payload_path = payload_dir.join("payload.json");
    let envelope_json = serde_json::to_vec(&HookStdinEnvelope::from_payload(
        payload,
        payload_path.clone(),
    ))?;

    for _ in 0..warmup {
        let stdin_payload = if payload_json.len() <= max_stdin_bytes {
            payload_json.as_slice()
        } else {
            std::fs::write(&payload_path, &payload_json)?;
            envelope_json.as_slice()
        };
        run_python_once(python, stdin_payload)?;
    }

    let start = Instant::now();
    for _ in 0..iters {
        let stdin_payload = if payload_json.len() <= max_stdin_bytes {
            payload_json.as_slice()
        } else {
            std::fs::write(&payload_path, &payload_json)?;
            envelope_json.as_slice()
        };
        run_python_once(python, stdin_payload)?;
    }
    Ok(BenchResult {
        iterations: iters,
        elapsed: start.elapsed(),
    })
}

fn run_python_once(python: &str, stdin_payload: &[u8]) -> anyhow::Result<()> {
    let script = r#"
import json
import sys

stdin = sys.stdin.read()
obj = json.loads(stdin)
if isinstance(obj, dict) and "payload_path" in obj:
    with open(obj["payload_path"], "r") as f:
        json.loads(f.read())
"#;
    let mut child = Command::new(python)
        .args(["-c", script])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow::anyhow!("expected stdin"))?;
        stdin.write_all(stdin_payload)?;
    }

    let status = child.wait()?;
    if !status.success() {
        anyhow::bail!("{python} exited with {status}");
    }
    Ok(())
}

fn bench_out_of_proc_python_host(
    python: &str,
    payload: &HookPayload,
    iters: usize,
    warmup: usize,
) -> anyhow::Result<BenchResult> {
    let script = r#"
import json
import sys

def noop(event):
    return None

for line in sys.stdin:
    noop(json.loads(line))
"#;

    let mut child = Command::new(python)
        .args(["-u", "-c", script])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow::anyhow!("expected stdin"))?;

    for _ in 0..warmup {
        let payload_json = serde_json::to_string(payload)?;
        stdin.write_all(payload_json.as_bytes())?;
        stdin.write_all(b"\n")?;
    }

    let start = Instant::now();
    for _ in 0..iters {
        let payload_json = serde_json::to_string(payload)?;
        stdin.write_all(payload_json.as_bytes())?;
        stdin.write_all(b"\n")?;
    }

    drop(stdin);
    let status = child.wait()?;
    if !status.success() {
        anyhow::bail!("{python} host exited with {status}");
    }

    Ok(BenchResult {
        iterations: iters,
        elapsed: start.elapsed(),
    })
}

#[cfg(feature = "pyo3-hooks")]
fn bench_inproc_pyo3(
    payload: &HookPayload,
    iters: usize,
    warmup: usize,
) -> anyhow::Result<BenchResult> {
    use pyo3::IntoPy;
    use pyo3::PyAny;
    use pyo3::PyResult;
    use pyo3::Python;
    use pyo3::types::PyAnyMethods;
    use pyo3::types::PyDict;
    use pyo3::types::PyDictMethods;
    use pyo3::types::PyList;
    use pyo3::types::PyListMethods;
    use pyo3::types::PyModule;
    use serde_json::Value as JsonValue;

    static PY_INIT: std::sync::Once = std::sync::Once::new();
    PY_INIT.call_once(pyo3::prepare_freethreaded_python);

    fn json_value_to_py(py: Python<'_>, value: &JsonValue) -> PyResult<pyo3::Py<pyo3::PyAny>> {
        match value {
            JsonValue::Null => Ok(().into_py(py)),
            JsonValue::Bool(value) => Ok((*value).into_py(py)),
            JsonValue::Number(value) => {
                if let Some(value) = value.as_i64() {
                    Ok(value.into_py(py))
                } else if let Some(value) = value.as_u64() {
                    Ok(value.into_py(py))
                } else if let Some(value) = value.as_f64() {
                    Ok(value.into_py(py))
                } else {
                    Err(pyo3::exceptions::PyValueError::new_err(
                        "unsupported JSON number",
                    ))
                }
            }
            JsonValue::String(value) => Ok(value.as_str().into_py(py)),
            JsonValue::Array(values) => {
                let list = PyList::empty_bound(py);
                for value in values {
                    list.append(json_value_to_py(py, value)?)?;
                }
                Ok(list.into_py(py))
            }
            JsonValue::Object(values) => {
                let dict = PyDict::new_bound(py);
                for (key, value) in values {
                    dict.set_item(key.as_str(), json_value_to_py(py, value)?)?;
                }
                Ok(dict.into_py(py))
            }
        }
    }

    let noop = Python::with_gil(|py| -> PyResult<pyo3::Py<PyAny>> {
        let module = PyModule::from_code_bound(
            py,
            r#"
def noop(event):
    return None
"#,
            "hooks_perf.py",
            "hooks_perf",
        )?;

        Ok(module.getattr("noop")?.into_py(py))
    })?;

    for _ in 0..warmup {
        let payload_value = serde_json::to_value(payload)?;
        Python::with_gil(|py| -> PyResult<()> {
            let event_obj = json_value_to_py(py, &payload_value)?;
            noop.call1(py, (event_obj,))?;
            Ok(())
        })?;
    }

    let start = Instant::now();
    for _ in 0..iters {
        let payload_value = serde_json::to_value(payload)?;
        Python::with_gil(|py| -> PyResult<()> {
            let event_obj = json_value_to_py(py, &payload_value)?;
            noop.call1(py, (event_obj,))?;
            Ok(())
        })?;
    }

    Ok(BenchResult {
        iterations: iters,
        elapsed: start.elapsed(),
    })
}

#[cfg(not(feature = "pyo3-hooks"))]
fn bench_inproc_pyo3(
    _payload: &HookPayload,
    _iters: usize,
    _warmup: usize,
) -> anyhow::Result<BenchResult> {
    anyhow::bail!(
        "pyo3 is disabled: rebuild with `--features pyo3-hooks` and ensure PYO3_PYTHON points at a linkable Python"
    )
}

fn print_markdown(
    payload: &HookPayload,
    external: BenchResult,
    host: BenchResult,
    inproc: BenchResult,
    pyo3: Option<BenchResult>,
) -> anyhow::Result<()> {
    let payload_json = serde_json::to_string(payload)?;
    println!("| Mode | Approx cost | Throughput | Notes |");
    println!("|---|---:|---:|---|");
    println!(
        "| External hook (Python, per-event spawn) | {:.2} ms/event | {:.1} ev/s | `python3 -c json.loads(stdin)` |",
        external.ns_per_iter() / 1_000_000.0,
        external.iters_per_sec(),
    );
    println!(
        "| Out-of-proc host (Python, persistent) | {:.2} µs/event | {:.1} ev/s | JSONL over stdin + Python callable |",
        host.ns_per_iter() / 1_000.0,
        host.iters_per_sec(),
    );
    println!(
        "| In-proc baseline | {:.2} ns/iter | {:.1} it/s | Rust loop only |",
        inproc.ns_per_iter(),
        inproc.iters_per_sec(),
    );

    if let Some(pyo3) = pyo3 {
        println!(
            "| In-proc PyO3 | {:.2} µs/event | {:.1} ev/s | `serde_json::to_value` + Rust→Python dict conversion + Python callable |",
            pyo3.ns_per_iter() / 1_000.0,
            pyo3.iters_per_sec(),
        );
    } else {
        println!("| In-proc PyO3 | (disabled) | - | build with `--features pyo3-hooks` |");
    }

    println!();
    println!("Payload bytes: {}", payload_json.len());
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    if has_flag(&args, "--help") {
        println!("hooks_perf (codex-core)");
        println!();
        println!("Usage:");
        println!("  cargo run -p codex-core --bin hooks_perf --release -- [flags]");
        println!();
        println!("Flags:");
        println!("  --iters N           Iterations for host + PyO3 (default: 2000)");
        println!("  --baseline-iters N  Iterations for in-proc baseline (default: 5000000)");
        println!("  --warmup N          Warmup iterations (default: 200)");
        println!("  --external-iters N  Iterations for external spawn (default: 200)");
        println!(
            "  --python PATH       Python executable for external/host benches (default: python3)"
        );
        println!(
            "  --payload-bytes N   Approx payload JSON size target (default: current payload)"
        );
        println!(
            "  --max-stdin-bytes N Max bytes to pass via stdin before using payload_path envelope (default: 16384)"
        );
        println!("  --markdown          Print a markdown table");
        println!("  --no-pyo3           Skip PyO3 even if enabled");
        return Ok(());
    }

    let iters = parse_usize_flag(&args, "--iters").unwrap_or(2000);
    let baseline_iters = parse_usize_flag(&args, "--baseline-iters").unwrap_or(5_000_000);
    let warmup = parse_usize_flag(&args, "--warmup").unwrap_or(200);
    let external_iters = parse_usize_flag(&args, "--external-iters").unwrap_or(200);
    let python = parse_string_flag(&args, "--python").unwrap_or("python3");
    let payload_bytes_target = parse_usize_flag(&args, "--payload-bytes");
    let max_stdin_bytes = parse_usize_flag(&args, "--max-stdin-bytes").unwrap_or(16_384);
    let print_md = has_flag(&args, "--markdown");
    let skip_pyo3 = has_flag(&args, "--no-pyo3");

    let payload = build_payload(payload_bytes_target);
    let payload_json = serde_json::to_vec(&payload)?;
    let payload_dir = tempfile::tempdir()?;

    let external = bench_external_python_spawn(
        python,
        &payload,
        payload_dir.path(),
        max_stdin_bytes,
        external_iters,
        10,
    )?;
    let host = bench_out_of_proc_python_host(python, &payload, iters, warmup)?;
    let inproc = bench_inproc_baseline(baseline_iters, warmup);

    let pyo3 = if skip_pyo3 {
        None
    } else {
        Some(bench_inproc_pyo3(&payload, iters, warmup)?)
    };

    if print_md {
        return print_markdown(&payload, external, host, inproc, pyo3);
    }

    println!("hooks_perf results");
    println!(
        "- external python spawn: {:.2} ms/event (iters={})",
        external.ns_per_iter() / 1_000_000.0,
        external.iterations
    );
    println!(
        "- python host (persistent): {:.2} µs/event (iters={})",
        host.ns_per_iter() / 1_000.0,
        host.iterations
    );
    println!(
        "- in-proc baseline: {:.2} ns/iter (iters={})",
        inproc.ns_per_iter(),
        inproc.iterations
    );
    if let Some(pyo3) = pyo3 {
        println!(
            "- in-proc PyO3: {:.2} µs/event (iters={})",
            pyo3.ns_per_iter() / 1_000.0,
            pyo3.iterations
        );
    } else {
        println!("- in-proc PyO3: skipped/disabled");
    }

    println!("Payload bytes: {}", payload_json.len());
    Ok(())
}
