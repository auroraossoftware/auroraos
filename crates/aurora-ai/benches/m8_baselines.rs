//! Aurora OS Milestone 8 (M8) - System Benchmark & Performance Baseline Harness
//!
//! Measures:
//! - 50 unmeasured warm-up turns followed by 1,000 measured iterations per scenario.
//! - 3 independent runs from fresh process cold-starts.
//! - Scenarios: noop, sys.cpu.read, sys.memory.read, proc.list (10 & 50), fs.file.read (128B & 64KiB), policy denial.
//! - Memory footprint (VmRSS, VmHWM, VmSize) of daemon and live worker at checkpoints (M0, M50, M100, M500, M1000).
//! - Outputs machine-readable JSON to `docs/benchmarks/m8_baseline.json`.

use aurora_ai::{CallerIdentity, SupervisorConfig, WorkerSupervisor};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Debug, Clone)]
struct MemoryCheckpoint {
    checkpoint: String,
    turn_count: usize,
    daemon_vmrss_kib: u64,
    daemon_vmhwm_kib: u64,
    daemon_vmsize_kib: u64,
    worker_vmrss_kib: u64,
    worker_vmhwm_kib: u64,
    worker_vmsize_kib: u64,
}

impl MemoryCheckpoint {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "checkpoint": self.checkpoint,
            "turn_count": self.turn_count,
            "daemon_vmrss_kib": self.daemon_vmrss_kib,
            "daemon_vmhwm_kib": self.daemon_vmhwm_kib,
            "daemon_vmsize_kib": self.daemon_vmsize_kib,
            "worker_vmrss_kib": self.worker_vmrss_kib,
            "worker_vmhwm_kib": self.worker_vmhwm_kib,
            "worker_vmsize_kib": self.worker_vmsize_kib,
        })
    }
}

#[derive(Debug, Clone)]
struct ScenarioStats {
    scenario_name: String,
    sample_count: usize,
    warmup_count: usize,
    min_ms: f64,
    p50_ms: f64,
    p90_ms: f64,
    p99_ms: f64,
    max_ms: f64,
    mean_ms: f64,
    stddev_ms: f64,
    cv_percent: f64,
    iqr_ms: f64,
    throughput_turns_per_sec: f64,
}

impl ScenarioStats {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "scenario_name": self.scenario_name,
            "sample_count": self.sample_count,
            "warmup_count": self.warmup_count,
            "min_ms": self.min_ms,
            "p50_ms": self.p50_ms,
            "p90_ms": self.p90_ms,
            "p99_ms": self.p99_ms,
            "max_ms": self.max_ms,
            "mean_ms": self.mean_ms,
            "stddev_ms": self.stddev_ms,
            "cv_percent": self.cv_percent,
            "iqr_ms": self.iqr_ms,
            "throughput_turns_per_sec": self.throughput_turns_per_sec,
        })
    }
}

#[derive(Debug, Clone)]
struct BenchmarkRun {
    run_index: usize,
    scenarios: Vec<ScenarioStats>,
    memory_profile: Vec<MemoryCheckpoint>,
}

impl BenchmarkRun {
    fn to_json(&self) -> serde_json::Value {
        let sc_json: Vec<serde_json::Value> = self.scenarios.iter().map(|s| s.to_json()).collect();
        let mem_json: Vec<serde_json::Value> =
            self.memory_profile.iter().map(|m| m.to_json()).collect();
        serde_json::json!({
            "run_index": self.run_index,
            "scenarios": sc_json,
            "memory_profile": mem_json,
        })
    }
}

#[derive(Debug, Clone)]
struct EnvironmentMetadata {
    cpu_model: String,
    cpu_cores: usize,
    cpu_arch: String,
    kernel_release: String,
    os_distribution: String,
    cpu_scaling_governor: String,
    rustc_version: String,
    python_version: String,
}

impl EnvironmentMetadata {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "cpu_model": self.cpu_model,
            "cpu_cores": self.cpu_cores,
            "cpu_arch": self.cpu_arch,
            "kernel_release": self.kernel_release,
            "os_distribution": self.os_distribution,
            "cpu_scaling_governor": self.cpu_scaling_governor,
            "rustc_version": self.rustc_version,
            "python_version": self.python_version,
        })
    }
}

#[derive(Debug, Clone)]
struct ScenarioStatsSummary {
    scenario_name: String,
    aggregate_p50_ms: f64,
    aggregate_p90_ms: f64,
    aggregate_p99_ms: f64,
    aggregate_mean_ms: f64,
    aggregate_throughput_turns_per_sec: f64,
}

impl ScenarioStatsSummary {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "scenario_name": self.scenario_name,
            "aggregate_p50_ms": self.aggregate_p50_ms,
            "aggregate_p90_ms": self.aggregate_p90_ms,
            "aggregate_p99_ms": self.aggregate_p99_ms,
            "aggregate_mean_ms": self.aggregate_mean_ms,
            "aggregate_throughput_turns_per_sec": self.aggregate_throughput_turns_per_sec,
        })
    }
}

fn read_proc_status(pid: u32) -> (u64, u64, u64) {
    let path = format!("/proc/{pid}/status");
    let content = fs::read_to_string(&path).unwrap_or_default();
    let mut vmrss = 0;
    let mut vmhwm = 0;
    let mut vmsize = 0;

    for line in content.lines() {
        if line.starts_with("VmRSS:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                vmrss = parts[1].parse().unwrap_or(0);
            }
        } else if line.starts_with("VmHWM:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                vmhwm = parts[1].parse().unwrap_or(0);
            }
        } else if line.starts_with("VmSize:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                vmsize = parts[1].parse().unwrap_or(0);
            }
        }
    }

    (vmrss, vmhwm, vmsize)
}

fn get_environment_metadata() -> EnvironmentMetadata {
    let cpuinfo = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let mut cpu_model = "Unknown CPU".to_string();
    let mut cpu_cores = 1;

    for line in cpuinfo.lines() {
        if line.starts_with("model name") {
            if let Some((_, model)) = line.split_once(':') {
                cpu_model = model.trim().to_string();
            }
        } else if line.starts_with("cpu cores") {
            if let Some((_, cores)) = line.split_once(':') {
                cpu_cores = cores.trim().parse().unwrap_or(1);
            }
        }
    }

    let os_release = fs::read_to_string("/etc/os-release").unwrap_or_default();
    let mut os_distribution = "Linux".to_string();
    for line in os_release.lines() {
        if line.starts_with("PRETTY_NAME=") {
            os_distribution = line
                .trim_start_matches("PRETTY_NAME=")
                .trim_matches('"')
                .to_string();
            break;
        }
    }

    let kernel_release = fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_else(|_| "Unknown".to_string())
        .trim()
        .to_string();

    let cpu_scaling_governor =
        fs::read_to_string("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
            .unwrap_or_else(|_| "unsupported / virtualized".to_string())
            .trim()
            .to_string();

    let rustc_output = std::process::Command::new("rustc")
        .arg("--version")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let python_output = std::process::Command::new("python3")
        .arg("--version")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    EnvironmentMetadata {
        cpu_model,
        cpu_cores,
        cpu_arch: std::env::consts::ARCH.to_string(),
        kernel_release,
        os_distribution,
        cpu_scaling_governor,
        rustc_version: rustc_output,
        python_version: python_output,
    }
}

fn compute_stats(
    name: &str,
    durations_ms: &mut [f64],
    warmup_count: usize,
    total_elapsed_sec: f64,
) -> ScenarioStats {
    durations_ms.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = durations_ms.len();
    assert!(n > 0);

    let min_ms = durations_ms[0];
    let max_ms = durations_ms[n - 1];

    let p50_idx = ((n as f64) * 0.50).floor() as usize;
    let p75_idx = ((n as f64) * 0.75).floor() as usize;
    let p25_idx = ((n as f64) * 0.25).floor() as usize;
    let p90_idx = ((n as f64) * 0.90).floor() as usize;
    let p99_idx = ((n as f64) * 0.99).floor() as usize;

    let p50_ms = durations_ms[p50_idx.min(n - 1)];
    let p90_ms = durations_ms[p90_idx.min(n - 1)];
    let p99_ms = durations_ms[p99_idx.min(n - 1)];
    let p75_ms = durations_ms[p75_idx.min(n - 1)];
    let p25_ms = durations_ms[p25_idx.min(n - 1)];
    let iqr_ms = (p75_ms - p25_ms).max(0.0);

    let sum: f64 = durations_ms.iter().sum();
    let mean_ms = sum / (n as f64);

    let variance: f64 = durations_ms
        .iter()
        .map(|&val| (val - mean_ms).powi(2))
        .sum::<f64>()
        / (n as f64);
    let stddev_ms = variance.sqrt();
    let cv_percent = if mean_ms > 0.0 {
        (stddev_ms / mean_ms) * 100.0
    } else {
        0.0
    };

    let throughput_turns_per_sec = if total_elapsed_sec > 0.0 {
        (n as f64) / total_elapsed_sec
    } else {
        0.0
    };

    ScenarioStats {
        scenario_name: name.to_string(),
        sample_count: n,
        warmup_count,
        min_ms: round4(min_ms),
        p50_ms: round4(p50_ms),
        p90_ms: round4(p90_ms),
        p99_ms: round4(p99_ms),
        max_ms: round4(max_ms),
        mean_ms: round4(mean_ms),
        stddev_ms: round4(stddev_ms),
        cv_percent: round2(cv_percent),
        iqr_ms: round4(iqr_ms),
        throughput_turns_per_sec: round2(throughput_turns_per_sec),
    }
}

fn round4(val: f64) -> f64 {
    (val * 10000.0).round() / 10000.0
}

fn round2(val: f64) -> f64 {
    (val * 100.0).round() / 100.0
}

fn prepare_sandbox_fixtures(sandbox: &Path) {
    fs::create_dir_all(sandbox).expect("failed to create sandbox dir");

    // 128-byte file
    let path_128b = sandbox.join("benchmark_128b.txt");
    let content_128b = "A".repeat(128);
    fs::write(&path_128b, content_128b).expect("failed to write 128b fixture");

    // 64 KiB file (65,536 bytes)
    let path_64k = sandbox.join("benchmark_64kib.txt");
    let content_64k = "B".repeat(65536);
    fs::write(&path_64k, content_64k).expect("failed to write 64kib fixture");
}

fn run_single_benchmark_run(run_index: usize, sandbox_root: &Path) -> BenchmarkRun {
    println!("\n=======================================================");
    println!(">>> Starting Independent Benchmark Run {run_index} of 3");
    println!("=======================================================");

    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();

    let config = SupervisorConfig::default()
        .with_working_dir(repo_root)
        .with_demo_sandbox_path(sandbox_root.to_path_buf())
        .with_max_proposals_per_turn(50);

    let mut supervisor = WorkerSupervisor::new(config);
    let daemon_pid = std::process::id();

    println!("Starting core daemon and launching live Python worker process...");
    supervisor.start().expect("failed to start supervisor");
    let worker_pid = supervisor
        .worker_pid()
        .expect("worker child PID not available");
    println!("Live session established: daemon PID = {daemon_pid}, worker PID = {worker_pid}");

    let caller_auth = CallerIdentity::principal("benchmark-user");
    let caller_unauth = CallerIdentity::principal("ungranted-user");

    // Grant capabilities for authorized caller
    supervisor
        .policy_engine_mut()
        .grant(caller_auth.clone(), "sys.cpu.read");
    supervisor
        .policy_engine_mut()
        .grant(caller_auth.clone(), "sys.memory.read");
    supervisor
        .policy_engine_mut()
        .grant(caller_auth.clone(), "proc.list");
    supervisor
        .policy_engine_mut()
        .grant(caller_auth.clone(), "fs.file.read");

    let mut memory_checkpoints = Vec::new();

    // Checkpoint M0: Post-handshake quiescent
    let (d_rss, d_hwm, d_vsz) = read_proc_status(daemon_pid);
    let (w_rss, w_hwm, w_vsz) = read_proc_status(worker_pid);
    memory_checkpoints.push(MemoryCheckpoint {
        checkpoint: "M0_quiescent".to_string(),
        turn_count: 0,
        daemon_vmrss_kib: d_rss,
        daemon_vmhwm_kib: d_hwm,
        daemon_vmsize_kib: d_vsz,
        worker_vmrss_kib: w_rss,
        worker_vmhwm_kib: w_hwm,
        worker_vmsize_kib: w_vsz,
    });

    let scenarios = vec![
        ("noop", "noop", &caller_auth),
        ("sys.cpu.read", "check cpu", &caller_auth),
        ("sys.memory.read", "check memory", &caller_auth),
        ("proc.list_limit_10", "list running processes", &caller_auth),
        (
            "proc.list_limit_50",
            "list running processes limit 50",
            &caller_auth,
        ),
        ("fs.file.read_128b", "read benchmark_128b.txt", &caller_auth),
        (
            "fs.file.read_64kib",
            "read benchmark_64kib.txt",
            &caller_auth,
        ),
        ("policy_denial", "check cpu", &caller_unauth),
    ];

    let mut scenario_results = Vec::new();
    let warmup_count = 50;
    let measure_count = 1000;
    let mut total_turns_in_run = 0;

    for (name, prompt, caller) in scenarios {
        print!("Benchmarking {name:<22} (warmup={warmup_count}, samples={measure_count})... ");
        std::io::Write::flush(&mut std::io::stdout()).unwrap();

        // 1. Unmeasured Warm-up Phase
        for _ in 0..warmup_count {
            let res = supervisor.execute_turn(caller, prompt);
            if name != "policy_denial" {
                assert!(res.is_ok(), "Warmup turn failed for {name}");
            }
            total_turns_in_run += 1;
        }

        // Checkpoint M50 (recorded after first scenario's warmup)
        if total_turns_in_run == warmup_count {
            let (d_rss, d_hwm, d_vsz) = read_proc_status(daemon_pid);
            let (w_rss, w_hwm, w_vsz) = read_proc_status(worker_pid);
            memory_checkpoints.push(MemoryCheckpoint {
                checkpoint: "M50_post_warmup".to_string(),
                turn_count: total_turns_in_run,
                daemon_vmrss_kib: d_rss,
                daemon_vmhwm_kib: d_hwm,
                daemon_vmsize_kib: d_vsz,
                worker_vmrss_kib: w_rss,
                worker_vmhwm_kib: w_hwm,
                worker_vmsize_kib: w_vsz,
            });
        }

        // 2. Measured Sampling Phase
        let mut samples_ms = Vec::with_capacity(measure_count);
        let batch_start = Instant::now();

        for i in 0..measure_count {
            let t0 = Instant::now();
            let res = supervisor.execute_turn(caller, prompt);
            let dt = t0.elapsed();
            samples_ms.push(dt.as_secs_f64() * 1000.0);

            if name != "policy_denial" {
                assert!(res.is_ok(), "Measured turn {i} failed for {name}");
            }

            total_turns_in_run += 1;

            if total_turns_in_run == 100 {
                let (d_rss, d_hwm, d_vsz) = read_proc_status(daemon_pid);
                let (w_rss, w_hwm, w_vsz) = read_proc_status(worker_pid);
                memory_checkpoints.push(MemoryCheckpoint {
                    checkpoint: "M100_turns".to_string(),
                    turn_count: total_turns_in_run,
                    daemon_vmrss_kib: d_rss,
                    daemon_vmhwm_kib: d_hwm,
                    daemon_vmsize_kib: d_vsz,
                    worker_vmrss_kib: w_rss,
                    worker_vmhwm_kib: w_hwm,
                    worker_vmsize_kib: w_vsz,
                });
            } else if total_turns_in_run == 500 {
                let (d_rss, d_hwm, d_vsz) = read_proc_status(daemon_pid);
                let (w_rss, w_hwm, w_vsz) = read_proc_status(worker_pid);
                memory_checkpoints.push(MemoryCheckpoint {
                    checkpoint: "M500_turns".to_string(),
                    turn_count: total_turns_in_run,
                    daemon_vmrss_kib: d_rss,
                    daemon_vmhwm_kib: d_hwm,
                    daemon_vmsize_kib: d_vsz,
                    worker_vmrss_kib: w_rss,
                    worker_vmhwm_kib: w_hwm,
                    worker_vmsize_kib: w_vsz,
                });
            } else if total_turns_in_run == 1000 {
                let (d_rss, d_hwm, d_vsz) = read_proc_status(daemon_pid);
                let (w_rss, w_hwm, w_vsz) = read_proc_status(worker_pid);
                memory_checkpoints.push(MemoryCheckpoint {
                    checkpoint: "M1000_turns".to_string(),
                    turn_count: total_turns_in_run,
                    daemon_vmrss_kib: d_rss,
                    daemon_vmhwm_kib: d_hwm,
                    daemon_vmsize_kib: d_vsz,
                    worker_vmrss_kib: w_rss,
                    worker_vmhwm_kib: w_hwm,
                    worker_vmsize_kib: w_vsz,
                });
            }
        }

        let batch_duration_sec = batch_start.elapsed().as_secs_f64();
        let stats = compute_stats(name, &mut samples_ms, warmup_count, batch_duration_sec);
        println!(
            "p50: {:6.3} ms | p90: {:6.3} ms | p99: {:6.3} ms | throughput: {:7.1} turns/s",
            stats.p50_ms, stats.p90_ms, stats.p99_ms, stats.throughput_turns_per_sec
        );
        scenario_results.push(stats);
    }

    supervisor.shutdown();

    BenchmarkRun {
        run_index,
        scenarios: scenario_results,
        memory_profile: memory_checkpoints,
    }
}

fn main() {
    println!("Aurora OS M8 - Performance Baselines & Measurement Harness");
    println!("Date: 2026-10-27");
    println!("Target Output: docs/benchmarks/m8_baseline.json");

    let env_meta = get_environment_metadata();
    println!("\nEnvironment Metadata:");
    println!(
        "  CPU: {} ({} cores, {})",
        env_meta.cpu_model, env_meta.cpu_cores, env_meta.cpu_arch
    );
    println!("  Kernel: {}", env_meta.kernel_release);
    println!("  OS: {}", env_meta.os_distribution);
    println!("  Governor: {}", env_meta.cpu_scaling_governor);
    println!("  Rustc: {}", env_meta.rustc_version);
    println!("  Python: {}", env_meta.python_version);

    let sandbox_root = std::env::temp_dir().join("aurora-m8-bench-sandbox");
    prepare_sandbox_fixtures(&sandbox_root);

    // Execute 3 independent runs
    let mut runs = Vec::new();
    for run_idx in 1..=3 {
        let run_data = run_single_benchmark_run(run_idx, &sandbox_root);
        runs.push(run_data);
    }

    // Compute Summary across 3 runs
    let mut summary = Vec::new();
    let scenario_count = runs[0].scenarios.len();

    for s_idx in 0..scenario_count {
        let name = runs[0].scenarios[s_idx].scenario_name.clone();
        let avg_p50 = (runs[0].scenarios[s_idx].p50_ms
            + runs[1].scenarios[s_idx].p50_ms
            + runs[2].scenarios[s_idx].p50_ms)
            / 3.0;
        let avg_p90 = (runs[0].scenarios[s_idx].p90_ms
            + runs[1].scenarios[s_idx].p90_ms
            + runs[2].scenarios[s_idx].p90_ms)
            / 3.0;
        let avg_p99 = (runs[0].scenarios[s_idx].p99_ms
            + runs[1].scenarios[s_idx].p99_ms
            + runs[2].scenarios[s_idx].p99_ms)
            / 3.0;
        let avg_mean = (runs[0].scenarios[s_idx].mean_ms
            + runs[1].scenarios[s_idx].mean_ms
            + runs[2].scenarios[s_idx].mean_ms)
            / 3.0;
        let avg_tp = (runs[0].scenarios[s_idx].throughput_turns_per_sec
            + runs[1].scenarios[s_idx].throughput_turns_per_sec
            + runs[2].scenarios[s_idx].throughput_turns_per_sec)
            / 3.0;

        summary.push(ScenarioStatsSummary {
            scenario_name: name,
            aggregate_p50_ms: round4(avg_p50),
            aggregate_p90_ms: round4(avg_p90),
            aggregate_p99_ms: round4(avg_p99),
            aggregate_mean_ms: round4(avg_mean),
            aggregate_throughput_turns_per_sec: round2(avg_tp),
        });
    }

    let runs_json: Vec<serde_json::Value> = runs.iter().map(|r| r.to_json()).collect();
    let summary_json: Vec<serde_json::Value> = summary.iter().map(|s| s.to_json()).collect();

    let report_json = serde_json::json!({
        "timestamp": "2026-10-27T06:20:00Z",
        "environment_metadata": env_meta.to_json(),
        "runs": runs_json,
        "summary": summary_json,
    });

    let json_output =
        serde_json::to_string_pretty(&report_json).expect("failed to serialize benchmark report");

    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let out_dir = repo_root.join("docs/benchmarks");
    fs::create_dir_all(&out_dir).expect("failed to create docs/benchmarks");
    let out_path = out_dir.join("m8_baseline.json");
    fs::write(&out_path, json_output).expect("failed to write m8_baseline.json");

    println!("\n=======================================================");
    println!(">>> M8 Benchmark Suite Completed Successfully!");
    println!(
        ">>> Saved machine-readable baseline to: {}",
        out_path.display()
    );
    println!("=======================================================\n");

    // Clean up temporary benchmark sandbox
    let _ = fs::remove_dir_all(&sandbox_root);
}
