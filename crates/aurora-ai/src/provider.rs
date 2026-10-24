//! Capability provider abstractions and implementation for `sys.cpu.read`.
//!
//! Pursuant to ADR-001 and ADR-002:
//! - Capability providers execute system observation or action operations.
//! - Providers DO NOT perform authorization; authorization belongs strictly
//!   to the policy boundary before a provider is ever invoked.
//! - The Linux `/proc/stat` implementation is a prototype implementation choice,
//!   abstracted behind the `CpuProvider` trait so it can be replaced in future releases.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// Errors occurring during capability execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityExecutionError {
    /// Machine-readable error code (e.g. `IO_ERROR`, `PARSE_ERROR`).
    pub code: String,
    /// Diagnostic error message.
    pub message: String,
}

impl CapabilityExecutionError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for CapabilityExecutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

impl std::error::Error for CapabilityExecutionError {}

/// Abstract provider interface for retrieving host CPU metrics.
pub trait CpuProvider: Send + Sync {
    /// Reads CPU telemetry data and returns structured JSON value.
    fn read_cpu(&self) -> Result<serde_json::Value, CapabilityExecutionError>;
}

/// Linux prototype implementation of `CpuProvider` reading from `/proc/stat`.
///
/// Architectural Note: This is a prototype implementation choice for Linux development
/// environments, not a permanent architectural commitment.
pub struct LinuxProcStatCpuProvider {
    proc_stat_path: PathBuf,
}

impl LinuxProcStatCpuProvider {
    /// Creates a provider pointing to the default `/proc/stat` path.
    pub fn new() -> Self {
        Self {
            proc_stat_path: PathBuf::from("/proc/stat"),
        }
    }

    /// Creates a provider with a custom file path (useful for deterministic tests).
    pub fn with_path(path: impl Into<PathBuf>) -> Self {
        Self {
            proc_stat_path: path.into(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.proc_stat_path
    }
}

impl Default for LinuxProcStatCpuProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CpuProvider for LinuxProcStatCpuProvider {
    fn read_cpu(&self) -> Result<serde_json::Value, CapabilityExecutionError> {
        let content = std::fs::read_to_string(&self.proc_stat_path).map_err(|e| {
            CapabilityExecutionError::new(
                "IO_ERROR",
                format!("Failed to read {}: {e}", self.proc_stat_path.display()),
            )
        })?;

        parse_proc_stat(&content)
    }
}

/// Parses the aggregated `cpu` line from a `/proc/stat` formatted string.
pub fn parse_proc_stat(content: &str) -> Result<serde_json::Value, CapabilityExecutionError> {
    for line in content.lines() {
        if line.starts_with("cpu ") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            // Expected fields: "cpu" user nice system idle [iowait irq softirq steal ...]
            if parts.len() < 5 {
                return Err(CapabilityExecutionError::new(
                    "PARSE_ERROR",
                    "Malformed /proc/stat: insufficient fields in cpu line",
                ));
            }

            let user: u64 = parts[1].parse().map_err(|_| {
                CapabilityExecutionError::new("PARSE_ERROR", "Invalid user ticks in /proc/stat")
            })?;
            let nice: u64 = parts[2].parse().map_err(|_| {
                CapabilityExecutionError::new("PARSE_ERROR", "Invalid nice ticks in /proc/stat")
            })?;
            let system: u64 = parts[3].parse().map_err(|_| {
                CapabilityExecutionError::new("PARSE_ERROR", "Invalid system ticks in /proc/stat")
            })?;
            let idle: u64 = parts[4].parse().map_err(|_| {
                CapabilityExecutionError::new("PARSE_ERROR", "Invalid idle ticks in /proc/stat")
            })?;
            let iowait: u64 = parts.get(5).and_then(|s| s.parse().ok()).unwrap_or(0);
            let irq: u64 = parts.get(6).and_then(|s| s.parse().ok()).unwrap_or(0);
            let softirq: u64 = parts.get(7).and_then(|s| s.parse().ok()).unwrap_or(0);
            let steal: u64 = parts.get(8).and_then(|s| s.parse().ok()).unwrap_or(0);

            let total_ticks = user + nice + system + idle + iowait + irq + softirq + steal;
            let (user_pct, system_pct, idle_pct) = if total_ticks > 0 {
                (
                    ((user + nice) as f64 / total_ticks as f64) * 100.0,
                    ((system + irq + softirq) as f64 / total_ticks as f64) * 100.0,
                    (idle as f64 / total_ticks as f64) * 100.0,
                )
            } else {
                (0.0, 0.0, 0.0)
            };

            return Ok(serde_json::json!({
                "user_percent": (user_pct * 100.0).round() / 100.0,
                "system_percent": (system_pct * 100.0).round() / 100.0,
                "idle_percent": (idle_pct * 100.0).round() / 100.0,
                "total_ticks": total_ticks,
                "idle_ticks": idle,
            }));
        }
    }

    Err(CapabilityExecutionError::new(
        "PARSE_ERROR",
        "No aggregated 'cpu' metric line found in stat source",
    ))
}

/// Mock implementation of `CpuProvider` for deterministic testing.
///
/// Tracks invocation counts to verify whether the provider was called or bypassed.
pub struct MockCpuProvider {
    invocation_count: AtomicUsize,
    simulated_result: Mutex<Result<serde_json::Value, CapabilityExecutionError>>,
}

impl MockCpuProvider {
    /// Creates a mock provider that returns the specified data on invocation.
    pub fn with_success(data: serde_json::Value) -> Self {
        Self {
            invocation_count: AtomicUsize::new(0),
            simulated_result: Mutex::new(Ok(data)),
        }
    }

    /// Creates a mock provider that returns a specified execution failure.
    pub fn with_failure(error: CapabilityExecutionError) -> Self {
        Self {
            invocation_count: AtomicUsize::new(0),
            simulated_result: Mutex::new(Err(error)),
        }
    }

    /// Returns the number of times `read_cpu()` was invoked.
    pub fn invocation_count(&self) -> usize {
        self.invocation_count.load(Ordering::SeqCst)
    }

    /// Configures the simulated outcome for future invocations.
    pub fn set_result(&self, result: Result<serde_json::Value, CapabilityExecutionError>) {
        *self.simulated_result.lock().unwrap() = result;
    }
}

impl CpuProvider for MockCpuProvider {
    fn read_cpu(&self) -> Result<serde_json::Value, CapabilityExecutionError> {
        self.invocation_count.fetch_add(1, Ordering::SeqCst);
        self.simulated_result.lock().unwrap().clone()
    }
}

/// Abstract provider interface for retrieving host memory metrics.
pub trait MemoryProvider: Send + Sync {
    /// Reads memory telemetry data and returns structured JSON value.
    fn read_memory(&self) -> Result<serde_json::Value, CapabilityExecutionError>;
}

/// Linux prototype implementation of `MemoryProvider` reading from `/proc/meminfo`.
///
/// Architectural Note: This is a prototype implementation choice for Linux development
/// environments, not a permanent architectural commitment.
pub struct LinuxProcMeminfoMemoryProvider {
    proc_meminfo_path: PathBuf,
}

impl LinuxProcMeminfoMemoryProvider {
    /// Creates a provider pointing to the default `/proc/meminfo` path.
    pub fn new() -> Self {
        Self {
            proc_meminfo_path: PathBuf::from("/proc/meminfo"),
        }
    }

    /// Creates a provider with a custom file path (useful for deterministic tests).
    pub fn with_path(path: impl Into<PathBuf>) -> Self {
        Self {
            proc_meminfo_path: path.into(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.proc_meminfo_path
    }
}

impl Default for LinuxProcMeminfoMemoryProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryProvider for LinuxProcMeminfoMemoryProvider {
    fn read_memory(&self) -> Result<serde_json::Value, CapabilityExecutionError> {
        let content = std::fs::read_to_string(&self.proc_meminfo_path).map_err(|e| {
            CapabilityExecutionError::new(
                "IO_ERROR",
                format!("Failed to read {}: {e}", self.proc_meminfo_path.display()),
            )
        })?;

        parse_proc_meminfo(&content)
    }
}

/// Parses memory metrics from a `/proc/meminfo` formatted string.
///
/// # Field Naming and Unit Conventions
/// Linux `/proc/meminfo` expresses memory in units labeled `kB` (where 1 kB = 1024 bytes, i.e. kibibytes).
/// Dividing by 1024 converts these values into binary mebibytes (MiB = 1024 * 1024 bytes).
/// The public JSON schema fields (`total_mb`, `used_mb`, `free_mb`, `available_mb`) retain the `_mb`
/// suffix for backwards compatibility with the MVP capability specification in `docs/vertical-slice-prototype-design.md`,
/// but represent binary mebibytes (MiB). Renaming to `_mib` would break the established protocol contracts
/// across supervisor, worker, and existing test suites.
///
/// # Calculation and Fallback Semantics
/// - `used_mb` is computed as `total_mb.saturating_sub(available_mb)`. This is an estimate of memory
///   actively consumed by user and system processes (analogous to the calculation used by modern `free`),
///   not a direct hardware counter or raw kernel page allocation measurement.
/// - If `MemAvailable` is absent (supported in Linux kernel >= 3.14), the parser falls back to `MemFree`.
///   This fallback is a conservative lower-bound approximation (counting only completely unallocated pages
///   and ignoring reclaimable buffer/cache memory) and is NOT equivalent to modern available-memory semantics.
///
/// # Validation and Error Handling
/// - Missing `MemTotal` or `MemFree` produces a `PARSE_ERROR`.
/// - Duplicate entries for `MemTotal`, `MemFree`, or `MemAvailable` produce a `PARSE_ERROR`.
/// - Malformed numeric values or unexpected unit labels produce a `PARSE_ERROR`.
/// - Inconsistent states (such as `MemTotal == 0`, `MemFree > MemTotal`, or `MemAvailable > MemTotal`)
///   produce an explicit `PARSE_ERROR` to prevent misleading telemetry.
pub fn parse_proc_meminfo(content: &str) -> Result<serde_json::Value, CapabilityExecutionError> {
    let mut mem_total_kb: Option<u64> = None;
    let mut mem_free_kb: Option<u64> = None;
    let mut mem_available_kb: Option<u64> = None;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Some((key, rest)) = trimmed.split_once(':') {
            let key = key.trim();
            match key {
                "MemTotal" => {
                    if mem_total_kb.is_some() {
                        return Err(CapabilityExecutionError::new(
                            "PARSE_ERROR",
                            "Duplicate 'MemTotal' field in meminfo source",
                        ));
                    }
                    mem_total_kb = Some(parse_meminfo_value(key, rest)?);
                }
                "MemFree" => {
                    if mem_free_kb.is_some() {
                        return Err(CapabilityExecutionError::new(
                            "PARSE_ERROR",
                            "Duplicate 'MemFree' field in meminfo source",
                        ));
                    }
                    mem_free_kb = Some(parse_meminfo_value(key, rest)?);
                }
                "MemAvailable" => {
                    if mem_available_kb.is_some() {
                        return Err(CapabilityExecutionError::new(
                            "PARSE_ERROR",
                            "Duplicate 'MemAvailable' field in meminfo source",
                        ));
                    }
                    mem_available_kb = Some(parse_meminfo_value(key, rest)?);
                }
                _ => {
                    // Other fields (Buffers, Cached, SwapTotal, etc.) are safely ignored
                }
            }
        }
    }

    let total_kb = mem_total_kb.ok_or_else(|| {
        CapabilityExecutionError::new("PARSE_ERROR", "Missing 'MemTotal' line in meminfo source")
    })?;

    if total_kb == 0 {
        return Err(CapabilityExecutionError::new(
            "PARSE_ERROR",
            "Invalid meminfo: MemTotal cannot be zero",
        ));
    }

    let free_kb = mem_free_kb.ok_or_else(|| {
        CapabilityExecutionError::new("PARSE_ERROR", "Missing 'MemFree' line in meminfo source")
    })?;

    if free_kb > total_kb {
        return Err(CapabilityExecutionError::new(
            "PARSE_ERROR",
            "Invalid meminfo: MemFree cannot exceed MemTotal",
        ));
    }

    if let Some(available_kb) = mem_available_kb {
        if available_kb > total_kb {
            return Err(CapabilityExecutionError::new(
                "PARSE_ERROR",
                "Invalid meminfo: MemAvailable cannot exceed MemTotal",
            ));
        }
    }

    // Fallback when MemAvailable is absent (Linux kernels < 3.14):
    // Documented approximation using MemFree.
    let available_kb = mem_available_kb.unwrap_or(free_kb);

    // Binary mebibytes (MiB):
    let total_mb = total_kb / 1024;
    let free_mb = free_kb / 1024;
    let available_mb = available_kb / 1024;
    let used_mb = total_mb.saturating_sub(available_mb);

    Ok(serde_json::json!({
        "total_mb": total_mb,
        "used_mb": used_mb,
        "free_mb": free_mb,
        "available_mb": available_mb,
    }))
}

fn parse_meminfo_value(field_name: &str, rest: &str) -> Result<u64, CapabilityExecutionError> {
    let mut parts = rest.split_whitespace();
    let num_str = parts.next().ok_or_else(|| {
        CapabilityExecutionError::new(
            "PARSE_ERROR",
            format!("Missing numeric value for '{field_name}' in meminfo source"),
        )
    })?;

    let val = num_str.parse::<u64>().map_err(|_| {
        CapabilityExecutionError::new(
            "PARSE_ERROR",
            format!("Invalid numeric value '{num_str}' for '{field_name}' in meminfo source"),
        )
    })?;

    if let Some(unit) = parts.next() {
        if unit != "kB" {
            return Err(CapabilityExecutionError::new(
                "PARSE_ERROR",
                format!("Unexpected unit '{unit}' for '{field_name}' in meminfo source (expected 'kB')"),
            ));
        }
    }

    Ok(val)
}

/// Mock implementation of `MemoryProvider` for deterministic testing.
///
/// Tracks invocation counts to verify whether the provider was called or bypassed.
pub struct MockMemoryProvider {
    invocation_count: AtomicUsize,
    simulated_result: Mutex<Result<serde_json::Value, CapabilityExecutionError>>,
}

impl MockMemoryProvider {
    /// Creates a mock provider returning a success payload.
    pub fn with_success(data: serde_json::Value) -> Self {
        Self {
            invocation_count: AtomicUsize::new(0),
            simulated_result: Mutex::new(Ok(data)),
        }
    }

    /// Creates a mock provider returning a failure error.
    pub fn with_failure(error: CapabilityExecutionError) -> Self {
        Self {
            invocation_count: AtomicUsize::new(0),
            simulated_result: Mutex::new(Err(error)),
        }
    }

    /// Returns the number of times `read_memory()` was invoked.
    pub fn invocation_count(&self) -> usize {
        self.invocation_count.load(Ordering::SeqCst)
    }

    /// Configures the simulated outcome for future invocations.
    pub fn set_result(&self, result: Result<serde_json::Value, CapabilityExecutionError>) {
        *self.simulated_result.lock().unwrap() = result;
    }
}

impl MemoryProvider for MockMemoryProvider {
    fn read_memory(&self) -> Result<serde_json::Value, CapabilityExecutionError> {
        self.invocation_count.fetch_add(1, Ordering::SeqCst);
        self.simulated_result.lock().unwrap().clone()
    }
}

/// Abstract provider interface for retrieving active system processes.
pub trait ProcessProvider: Send + Sync {
    /// Lists active system processes bounded by the validated limit.
    fn list_processes(&self, limit: usize) -> Result<serde_json::Value, CapabilityExecutionError>;
}

/// Linux prototype implementation of `ProcessProvider` reading `/proc` directly.
///
/// # Confinement and Minimal Information Exposure
/// - Discovers numeric PID directories (`/proc/<pid>`).
/// - Reads only minimal required process metadata:
///   - Process name: read from `/proc/<pid>/comm` (clean executable basename, max 16 chars).
///   - Resident memory: read from `/proc/<pid>/status` (`VmRSS:` line) in binary mebibytes (MiB).
/// - Prohibited fields: Never reads `/proc/<pid>/cmdline` (arguments may contain secrets),
///   `/proc/<pid>/environ` (environment variables), or file descriptors.
/// - Zero shell execution: Inspects `/proc` strictly using Rust standard library filesystem APIs;
///   no subshells, `ps`, `pgrep`, `top`, or subprocesses are ever invoked.
///
/// # Resiliency and Ephemeral Processes
/// - Processes that exit or have permission restrictions during directory traversal are
///   skipped gracefully without failing the entire capability.
/// - Systemic failures (e.g. inability to read `/proc` directory) return an explicit `IO_ERROR`.
///
/// # Deterministic Ordering and Bounding
/// - Results are sorted deterministically in ascending order by PID.
/// - Results are truncated to return no more than the requested `limit`.
pub struct LinuxProcFsProcessProvider {
    proc_path: PathBuf,
}

impl LinuxProcFsProcessProvider {
    /// Creates a provider pointing to the default `/proc` path.
    pub fn new() -> Self {
        Self {
            proc_path: PathBuf::from("/proc"),
        }
    }

    /// Creates a provider with a custom file path (useful for testing with synthetic directory trees).
    pub fn with_path(path: impl Into<PathBuf>) -> Self {
        Self {
            proc_path: path.into(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.proc_path
    }
}

impl Default for LinuxProcFsProcessProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessProvider for LinuxProcFsProcessProvider {
    fn list_processes(&self, limit: usize) -> Result<serde_json::Value, CapabilityExecutionError> {
        let entries = std::fs::read_dir(&self.proc_path).map_err(|e| {
            CapabilityExecutionError::new(
                "IO_ERROR",
                format!("Failed to read process directory {}: {e}", self.proc_path.display()),
            )
        })?;

        let mut processes = Vec::new();

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    // Systemic failure while iterating the directory stream must return an error,
                    // not be silently ignored into a successful but incomplete process list.
                    return Err(CapabilityExecutionError::new(
                        "IO_ERROR",
                        format!(
                            "Error while enumerating directory entries in {}: {e}",
                            self.proc_path.display()
                        ),
                    ));
                }
            };

            let file_name = entry.file_name();
            let name_str = match file_name.to_str() {
                Some(s) => s,
                None => continue,
            };

            // Filter for numeric PID directories
            let pid: u32 = match name_str.parse() {
                Ok(n) => n,
                Err(_) => continue,
            };

            let pid_dir = entry.path();
            if !pid_dir.is_dir() {
                continue;
            }

            // Read process name from /proc/<pid>/comm (executable basename)
            let comm_path = pid_dir.join("comm");
            let comm = match std::fs::read_to_string(&comm_path) {
                Ok(c) => c.trim().to_string(),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue, // Ephemeral process exited
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => continue, // Inaccessible/restricted process
                Err(_) => continue, // Other per-process read error
            };

            if comm.is_empty() {
                continue;
            }

            // Read memory from /proc/<pid>/status (VmRSS line in binary MiB)
            let status_path = pid_dir.join("status");
            let memory_mb = match std::fs::read_to_string(&status_path) {
                Ok(status_content) => match parse_vmrss(&status_content) {
                    VmRssStatus::Present(mib) => mib,
                    VmRssStatus::Absent => {
                        // Kernel threads and processes without user address space (no mm_struct)
                        // legitimately have no VmRSS in /proc/<pid>/status; resident memory is 0.
                        0
                    }
                    VmRssStatus::Malformed => {
                        // VmRSS was present but corrupted/non-numeric.
                        // Skip process rather than silently misrepresenting corrupt data as measured 0.
                        continue;
                    }
                },
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue, // Process exited
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => continue, // Inaccessible status
                Err(_) => continue,
            };

            processes.push(ProcessEntry {
                pid,
                name: comm,
                memory_mb,
            });
        }

        // Sort deterministically in ascending order by PID
        processes.sort_by_key(|p| p.pid);

        // Truncate to limit
        if processes.len() > limit {
            processes.truncate(limit);
        }

        let json_entries: Vec<serde_json::Value> = processes
            .into_iter()
            .map(|p| {
                serde_json::json!({
                    "pid": p.pid,
                    "name": p.name,
                    "memory_mb": p.memory_mb,
                })
            })
            .collect();

        Ok(serde_json::Value::Array(json_entries))
    }
}

struct ProcessEntry {
    pid: u32,
    name: String,
    memory_mb: u64,
}

/// Status of resident memory parsing from `/proc/<pid>/status`.
#[derive(Debug, PartialEq, Eq)]
pub enum VmRssStatus {
    /// Measured resident memory in binary MiB.
    Present(u64),
    /// Kernel thread or process without userspace memory (no VmRSS line in status).
    Absent,
    /// VmRSS line was present but contained malformed/non-numeric data or unexpected units.
    Malformed,
}

/// Parses resident set size (VmRSS) from `/proc/<pid>/status` content.
pub fn parse_vmrss(status_content: &str) -> VmRssStatus {
    for line in status_content.lines() {
        if line.starts_with("VmRSS:") {
            let mut parts = line.split_whitespace();
            let _ = parts.next(); // "VmRSS:"
            if let Some(val_str) = parts.next() {
                if let Ok(kb) = val_str.parse::<u64>() {
                    if let Some(unit) = parts.next() {
                        if unit != "kB" {
                            return VmRssStatus::Malformed;
                        }
                    }
                    return VmRssStatus::Present(kb / 1024); // Binary MiB
                }
            }
            return VmRssStatus::Malformed;
        }
    }
    VmRssStatus::Absent
}

/// Parses the resident set size (VmRSS) from `/proc/<pid>/status` and converts from kB to binary MiB.
pub fn parse_vmrss_mb(status_content: &str) -> u64 {
    match parse_vmrss(status_content) {
        VmRssStatus::Present(mib) => mib,
        _ => 0,
    }
}

/// Mock implementation of `ProcessProvider` for deterministic testing.
///
/// Tracks invocation counts and the exact limit parameter received.
pub struct MockProcessProvider {
    invocation_count: AtomicUsize,
    last_limit: AtomicUsize,
    simulated_result: Mutex<Result<serde_json::Value, CapabilityExecutionError>>,
}

impl MockProcessProvider {
    /// Creates a mock provider returning a success payload.
    pub fn with_success(data: serde_json::Value) -> Self {
        Self {
            invocation_count: AtomicUsize::new(0),
            last_limit: AtomicUsize::new(0),
            simulated_result: Mutex::new(Ok(data)),
        }
    }

    /// Creates a mock provider returning a failure error.
    pub fn with_failure(error: CapabilityExecutionError) -> Self {
        Self {
            invocation_count: AtomicUsize::new(0),
            last_limit: AtomicUsize::new(0),
            simulated_result: Mutex::new(Err(error)),
        }
    }

    /// Returns the number of times `list_processes()` was invoked.
    pub fn invocation_count(&self) -> usize {
        self.invocation_count.load(Ordering::SeqCst)
    }

    /// Returns the last limit parameter passed to `list_processes()`.
    pub fn last_limit(&self) -> usize {
        self.last_limit.load(Ordering::SeqCst)
    }

    /// Configures the simulated outcome for future invocations.
    pub fn set_result(&self, result: Result<serde_json::Value, CapabilityExecutionError>) {
        *self.simulated_result.lock().unwrap() = result;
    }
}

impl ProcessProvider for MockProcessProvider {
    fn list_processes(&self, limit: usize) -> Result<serde_json::Value, CapabilityExecutionError> {
        self.invocation_count.fetch_add(1, Ordering::SeqCst);
        self.last_limit.store(limit, Ordering::SeqCst);
        let guard = self.simulated_result.lock().unwrap();
        match &*guard {
            Ok(val) => {
                if let serde_json::Value::Array(arr) = val {
                    let mut truncated = arr.clone();
                    if truncated.len() > limit {
                        truncated.truncate(limit);
                    }
                    Ok(serde_json::Value::Array(truncated))
                } else {
                    Ok(val.clone())
                }
            }
            Err(err) => Err(err.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_proc_stat_valid_line() {
        let sample = "cpu  130548 200 51788 1317091 39132 0 2374 0 0 0\ncpu0 32555 29 13110 328389 10404 0 737 0 0 0\n";
        let result = parse_proc_stat(sample);
        assert!(result.is_ok());
        let val = result.unwrap();
        assert!(val.get("user_percent").is_some());
        assert!(val.get("system_percent").is_some());
        assert!(val.get("idle_percent").is_some());
        assert!(val.get("total_ticks").is_some());
    }

    #[test]
    fn test_parse_proc_stat_missing_cpu_line() {
        let sample = "intr 23423423\nctxt 324234\nbtime 12345678\n";
        let result = parse_proc_stat(sample);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, "PARSE_ERROR");
    }

    #[test]
    fn test_mock_provider_invocation_counting() {
        let mock = MockCpuProvider::with_success(serde_json::json!({"test": true}));
        assert_eq!(mock.invocation_count(), 0);

        let res = mock.read_cpu();
        assert!(res.is_ok());
        assert_eq!(mock.invocation_count(), 1);

        let _ = mock.read_cpu();
        assert_eq!(mock.invocation_count(), 2);
    }

    #[test]
    fn test_parse_proc_meminfo_valid() {
        let sample = "MemTotal:       16377436 kB\nMemFree:         2962928 kB\nMemAvailable:   14088084 kB\nBuffers:          278904 kB\n";
        let result = parse_proc_meminfo(sample);
        assert!(result.is_ok());
        let val = result.unwrap();
        assert_eq!(val["total_mb"], 15993);
        assert_eq!(val["free_mb"], 2893);
        assert_eq!(val["available_mb"], 13757);
        assert_eq!(val["used_mb"], 15993 - 13757);
    }

    #[test]
    fn test_parse_proc_meminfo_fallback_when_available_missing() {
        let sample = "MemTotal:       8388608 kB\nMemFree:         2097152 kB\n";
        let result = parse_proc_meminfo(sample);
        assert!(result.is_ok());
        let val = result.unwrap();
        assert_eq!(val["total_mb"], 8192);
        assert_eq!(val["free_mb"], 2048);
        assert_eq!(val["available_mb"], 2048);
        assert_eq!(val["used_mb"], 8192 - 2048);
    }

    #[test]
    fn test_parse_proc_meminfo_missing_total_or_free() {
        let sample = "MemFree: 2097152 kB\n";
        let result = parse_proc_meminfo(sample);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, "PARSE_ERROR");

        let sample2 = "MemTotal: 8388608 kB\n";
        let result2 = parse_proc_meminfo(sample2);
        assert!(result2.is_err());
        assert_eq!(result2.unwrap_err().code, "PARSE_ERROR");
    }

    #[test]
    fn test_mock_memory_provider_invocation_counting() {
        let mock = MockMemoryProvider::with_success(serde_json::json!({
            "total_mb": 16000,
            "used_mb": 4000,
            "free_mb": 2000,
            "available_mb": 12000,
        }));
        assert_eq!(mock.invocation_count(), 0);

        let res = mock.read_memory();
        assert!(res.is_ok());
        assert_eq!(mock.invocation_count(), 1);

        let _ = mock.read_memory();
        assert_eq!(mock.invocation_count(), 2);
    }

    #[test]
    fn test_parse_proc_meminfo_colon_without_whitespace() {
        let sample = "MemTotal:16377436 kB\nMemFree:2962928 kB\nMemAvailable:14088084 kB\n";
        let result = parse_proc_meminfo(sample);
        assert!(result.is_ok());
        let val = result.unwrap();
        assert_eq!(val["total_mb"], 15993);
        assert_eq!(val["free_mb"], 2893);
        assert_eq!(val["available_mb"], 13757);
    }

    #[test]
    fn test_parse_proc_meminfo_duplicate_fields() {
        let sample = "MemTotal: 8388608 kB\nMemTotal: 4194304 kB\nMemFree: 2097152 kB\n";
        let result = parse_proc_meminfo(sample);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, "PARSE_ERROR");
        assert!(err.message.contains("Duplicate 'MemTotal'"));
    }

    #[test]
    fn test_parse_proc_meminfo_malformed_numeric() {
        let sample = "MemTotal: notanumber kB\nMemFree: 2097152 kB\n";
        let result = parse_proc_meminfo(sample);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, "PARSE_ERROR");
        assert!(err.message.contains("Invalid numeric value"));
    }

    #[test]
    fn test_parse_proc_meminfo_unexpected_unit() {
        let sample = "MemTotal: 8388608 MB\nMemFree: 2097152 kB\n";
        let result = parse_proc_meminfo(sample);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, "PARSE_ERROR");
        assert!(err.message.contains("Unexpected unit 'MB'"));
    }

    #[test]
    fn test_parse_proc_meminfo_zero_total_memory() {
        let sample = "MemTotal: 0 kB\nMemFree: 0 kB\n";
        let result = parse_proc_meminfo(sample);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, "PARSE_ERROR");
        assert!(err.message.contains("MemTotal cannot be zero"));
    }

    #[test]
    fn test_parse_proc_meminfo_free_exceeds_total() {
        let sample = "MemTotal: 1048576 kB\nMemFree: 2097152 kB\n";
        let result = parse_proc_meminfo(sample);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, "PARSE_ERROR");
        assert!(err.message.contains("MemFree cannot exceed MemTotal"));
    }

    #[test]
    fn test_parse_proc_meminfo_available_exceeds_total() {
        let sample = "MemTotal: 1048576 kB\nMemFree: 524288 kB\nMemAvailable: 2097152 kB\n";
        let result = parse_proc_meminfo(sample);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, "PARSE_ERROR");
        assert!(err.message.contains("MemAvailable cannot exceed MemTotal"));
    }

    #[test]
    fn test_parse_proc_meminfo_malformed_available_does_not_silently_fallback() {
        // If MemAvailable is present but corrupt, it must FAIL with PARSE_ERROR,
        // rather than silently masking corruption and falling back to MemFree.
        let sample = "MemTotal: 8388608 kB\nMemFree: 2097152 kB\nMemAvailable: corrupt_data kB\n";
        let result = parse_proc_meminfo(sample);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, "PARSE_ERROR");
        assert!(err.message.contains("Invalid numeric value"));
    }

    #[test]
    fn test_mock_process_provider_counting_and_limit() {
        let mock = MockProcessProvider::with_success(serde_json::json!([
            {"pid": 1, "name": "systemd", "memory_mb": 12},
            {"pid": 2, "name": "kthreadd", "memory_mb": 0},
            {"pid": 100, "name": "bash", "memory_mb": 5},
        ]));
        assert_eq!(mock.invocation_count(), 0);

        let res = mock.list_processes(2);
        assert!(res.is_ok());
        assert_eq!(mock.invocation_count(), 1);
        assert_eq!(mock.last_limit(), 2);

        let val = res.unwrap();
        let arr = val.as_array().expect("Expected array");
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["pid"], 1);
        assert_eq!(arr[1]["pid"], 2);
    }

    #[test]
    fn test_parse_vmrss_mb() {
        let sample = "Name:\tbash\nState:\tS (sleeping)\nVmRSS:\t   16384 kB\nThreads:\t1\n";
        assert_eq!(parse_vmrss(sample), VmRssStatus::Present(16));
        assert_eq!(parse_vmrss_mb(sample), 16);

        let sample_zero = "Name:\tkthreadd\nState:\tS (sleeping)\n";
        assert_eq!(parse_vmrss(sample_zero), VmRssStatus::Absent);
        assert_eq!(parse_vmrss_mb(sample_zero), 0);

        let sample_malformed_num = "Name:\tcorrupt\nVmRSS:\tnot_a_number kB\n";
        assert_eq!(parse_vmrss(sample_malformed_num), VmRssStatus::Malformed);

        let sample_unexpected_unit = "Name:\tcorrupt\nVmRSS:\t1024 MB\n";
        assert_eq!(parse_vmrss(sample_unexpected_unit), VmRssStatus::Malformed);
    }

    #[test]
    fn test_linux_procfs_process_provider_with_synthetic_dir() {
        let temp_dir = std::env::temp_dir().join(format!("aurora_test_proc_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();

        // 1. Create numeric PID directories
        let pid10 = temp_dir.join("10");
        std::fs::create_dir_all(&pid10).unwrap();
        std::fs::write(pid10.join("comm"), "init\n").unwrap();
        std::fs::write(pid10.join("status"), "VmRSS: 2048 kB\n").unwrap();

        let pid5 = temp_dir.join("5");
        std::fs::create_dir_all(&pid5).unwrap();
        std::fs::write(pid5.join("comm"), "kworker\n").unwrap();
        // Kernel thread status without VmRSS line -> memory_mb is 0
        std::fs::write(pid5.join("status"), "Name: kworker\nState: S\n").unwrap();

        let pid20 = temp_dir.join("20");
        std::fs::create_dir_all(&pid20).unwrap();
        std::fs::write(pid20.join("comm"), "daemon\n").unwrap();
        std::fs::write(pid20.join("status"), "VmRSS: 4096 kB\n").unwrap();

        // 2. Create PID directory with malformed VmRSS (should be skipped, not falsely measured as 0)
        let pid30 = temp_dir.join("30");
        std::fs::create_dir_all(&pid30).unwrap();
        std::fs::write(pid30.join("comm"), "corrupt_proc\n").unwrap();
        std::fs::write(pid30.join("status"), "VmRSS: not_a_number kB\n").unwrap();

        // 3. Create non-numeric directory (should be ignored)
        let non_num = temp_dir.join("sys");
        std::fs::create_dir_all(&non_num).unwrap();

        // 4. Create vanishing process directory (status missing / process exited after comm, should be skipped)
        let pid99 = temp_dir.join("99");
        std::fs::create_dir_all(&pid99).unwrap();
        std::fs::write(pid99.join("comm"), "vanishing\n").unwrap();
        // status file intentionally omitted to simulate process exit between comm and status read

        let provider = LinuxProcFsProcessProvider::with_path(&temp_dir);
        let res = provider.list_processes(2).expect("Failed to list processes");
        let arr = res.as_array().expect("Expected JSON array");

        // Must be sorted by PID ascending (5, then 10) and truncated to limit (2)
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["pid"], 5);
        assert_eq!(arr[0]["name"], "kworker");
        assert_eq!(arr[0]["memory_mb"], 0);

        assert_eq!(arr[1]["pid"], 10);
        assert_eq!(arr[1]["name"], "init");
        assert_eq!(arr[1]["memory_mb"], 2);

        // When listing with a larger limit (10), corrupt_proc (pid 30) must be skipped
        let res_all = provider.list_processes(10).expect("Failed to list processes");
        let arr_all = res_all.as_array().expect("Expected JSON array");
        assert_eq!(arr_all.len(), 3); // 5, 10, 20 (30 is skipped due to malformed VmRSS, 99 skipped due to missing comm)
        assert_eq!(arr_all[0]["pid"], 5);
        assert_eq!(arr_all[1]["pid"], 10);
        assert_eq!(arr_all[2]["pid"], 20);

        // Clean up
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_linux_procfs_process_provider_inaccessible_dir_returns_io_error() {
        let non_existent = PathBuf::from("/non_existent_proc_test_path_12345");
        let provider = LinuxProcFsProcessProvider::with_path(non_existent);
        let res = provider.list_processes(10);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.code, "IO_ERROR");
        assert!(err.message.contains("Failed to read process directory"));
    }
}
