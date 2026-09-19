//! Aurora OS Core System Daemon (`aurora-ai`) - Milestone 2 Lifecycle Entry Point
//!
//! Pursuant to ADR-001 and ADR-002, `aurora-ai` is the central system daemon
//! responsible for policy enforcement, capability mediation, and worker process supervision.
//!
//! Milestone 2:
//! 1. Initializes runtime daemon state.
//! 2. Starts the isolated Python AI worker stub as an unprivileged child process.
//! 3. Establishes the private Unix domain socket channel.
//! 4. Performs the protocol handshake and verifies version compatibility.
//! 5. Monitors worker health and shuts down cleanly without resource leaks.

use aurora_ai::{SupervisorConfig, WorkerStatus, WorkerSupervisor};
use std::path::PathBuf;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    println!("Starting aurora-ai core daemon (M2)...");

    let mut config = SupervisorConfig::default();

    // Check for custom socket path or test flags
    let mut test_handshake_only = false;
    let mut duration_secs = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--socket-path" => {
                if i + 1 < args.len() {
                    config = config.with_socket_path(PathBuf::from(&args[i + 1]));
                    i += 1;
                }
            }
            "--test-handshake-only" => {
                test_handshake_only = true;
            }
            "--duration" => {
                if i + 1 < args.len() {
                    duration_secs = args[i + 1].parse::<u64>().ok();
                    i += 1;
                }
            }
            "--help" | "-h" => {
                println!("Usage: aurora-ai [--socket-path <PATH>] [--test-handshake-only] [--duration <SECS>]");
                return Ok(());
            }
            _ => {}
        }
        i += 1;
    }

    println!("Socket path: {}", config.socket_path.display());
    let mut supervisor = WorkerSupervisor::new(config);

    println!("Starting worker process and establishing private IPC channel...");
    supervisor.start()?;
    println!(
        "Worker connected and verified. Worker protocol version compatible, reported version: {:?}",
        supervisor.worker_version().unwrap_or("unknown")
    );

    if test_handshake_only {
        println!("Handshake verified successfully. Shutting down cleanly...");
        supervisor.shutdown();
        println!("Clean shutdown complete.");
        return Ok(());
    }

    println!("Entering daemon supervision loop (press Ctrl+C or wait for worker termination)...");

    let start_time = std::time::Instant::now();
    loop {
        if let Some(limit) = duration_secs {
            if start_time.elapsed() >= Duration::from_secs(limit) {
                println!("Specified run duration elapsed. Shutting down...");
                break;
            }
        }

        match supervisor.poll_status()? {
            WorkerStatus::Running => {
                std::thread::sleep(Duration::from_millis(100));
            }
            WorkerStatus::Terminated(exit_code) => {
                println!("Worker terminated with exit code: {exit_code:?}. Daemon shutting down safely.");
                break;
            }
            WorkerStatus::Disconnected => {
                println!("Worker disconnected from IPC socket. Daemon shutting down safely.");
                break;
            }
        }
    }

    supervisor.shutdown();
    println!("aurora-ai daemon stopped cleanly.");
    Ok(())
}
