//! Aurora OS Core System Daemon (`aurora-ai`) - Milestone 5 Vertical Slice Entry Point
//!
//! Pursuant to ADR-001 and ADR-002, `aurora-ai` is the central system daemon
//! responsible for policy enforcement, capability mediation, and worker process supervision.
//!
//! Milestone 5:
//! 1. Initializes runtime daemon state.
//! 2. Starts the isolated Python AI worker stub as an unprivileged child process.
//! 3. Establishes the private Unix domain socket channel and performs handshake.
//! 4. Exercises the complete end-to-end request flow (caller -> daemon -> worker -> proposal
//!    -> policy -> provider -> outcome -> worker synthesis -> complete turn -> caller).
//! 5. Monitors worker health and shuts down cleanly without resource leaks.

use aurora_ai::{CallerIdentity, SupervisorConfig, WorkerStatus, WorkerSupervisor};
use std::path::PathBuf;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    println!("Starting aurora-ai core daemon (M5 vertical slice)...");

    let mut config = SupervisorConfig::default();

    // Check for custom socket path or test flags
    let mut test_handshake_only = false;
    let mut duration_secs = None;
    let mut request_prompt = None;
    let mut caller_name = None;
    let mut unauthorized = false;
    let mut anonymous = false;

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
            "--request" => {
                if i + 1 < args.len() {
                    request_prompt = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "--caller" => {
                if i + 1 < args.len() {
                    caller_name = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "--unauthorized" => {
                unauthorized = true;
            }
            "--anonymous" => {
                anonymous = true;
            }
            "--duration" => {
                if i + 1 < args.len() {
                    duration_secs = args[i + 1].parse::<u64>().ok();
                    i += 1;
                }
            }
            "--help" | "-h" => {
                println!("Usage: aurora-ai [OPTIONS]");
                println!("Options:");
                println!("  --request <PROMPT>       Execute an end-to-end request turn and print output");
                println!("  --caller <NAME>          Set caller principal identity (default: 'desktop-user')");
                println!("  --unauthorized           Simulate ungranted caller (policy denial test)");
                println!("  --anonymous              Simulate unauthenticated anonymous caller");
                println!("  --socket-path <PATH>     Custom private Unix domain socket path");
                println!("  --test-handshake-only    Perform startup handshake and exit");
                println!("  --duration <SECS>        Run daemon supervision loop for N seconds");
                println!("  --help, -h               Show this help message");
                return Ok(());
            }
            _ => {}
        }
        i += 1;
    }

    println!("Socket path: {}", config.socket_path.display());
    let mut supervisor = WorkerSupervisor::new(config);

    // If running a request, configure policy grants accordingly
    let caller = if anonymous {
        CallerIdentity::anonymous()
    } else {
        let name = caller_name.unwrap_or_else(|| "desktop-user".to_string());
        CallerIdentity::principal(&name)
    };

    if !unauthorized && caller.is_authenticated() {
        supervisor
            .policy_engine_mut()
            .grant(caller.clone(), "sys.cpu.read");
        supervisor
            .policy_engine_mut()
            .grant(caller.clone(), "sys.memory.read");
        supervisor
            .policy_engine_mut()
            .grant(caller.clone(), "proc.list");
    }

    println!("Starting worker process and establishing private IPC channel...");
    supervisor.start()?;
    println!(
        "Worker connected and verified. Protocol version compatible, reported worker version: {:?}",
        supervisor.worker_version().unwrap_or("unknown")
    );

    if test_handshake_only {
        println!("Handshake verified successfully. Shutting down cleanly...");
        supervisor.shutdown();
        println!("Clean shutdown complete.");
        return Ok(());
    }

    if let Some(prompt) = request_prompt {
        println!(
            "Dispatching request turn for caller '{}' with prompt: '{}'",
            caller.id().unwrap_or("anonymous"),
            prompt
        );
        match supervisor.execute_turn(&caller, &prompt) {
            Ok(complete_turn) => {
                println!("Turn execution completed with status: {:?}", complete_turn.status);
                println!("Response:\n{}", complete_turn.response_text);
            }
            Err(e) => {
                eprintln!("Turn execution failed with error: {e}");
                supervisor.shutdown();
                std::process::exit(1);
            }
        }
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
