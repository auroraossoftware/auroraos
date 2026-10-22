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
/// Extracts `MemTotal`, `MemFree`, and `MemAvailable` (or falls back to `MemFree` if `MemAvailable` is absent),
/// and calculates total, used, free, and available memory in megabytes (MB).
pub fn parse_proc_meminfo(content: &str) -> Result<serde_json::Value, CapabilityExecutionError> {
    let mut mem_total_kb: Option<u64> = None;
    let mut mem_free_kb: Option<u64> = None;
    let mut mem_available_kb: Option<u64> = None;

    for line in content.lines() {
        if line.starts_with("MemTotal:") {
            mem_total_kb = parse_meminfo_kb(line);
        } else if line.starts_with("MemFree:") {
            mem_free_kb = parse_meminfo_kb(line);
        } else if line.starts_with("MemAvailable:") {
            mem_available_kb = parse_meminfo_kb(line);
        }
    }

    let total_kb = mem_total_kb.ok_or_else(|| {
        CapabilityExecutionError::new("PARSE_ERROR", "Missing 'MemTotal' line in meminfo source")
    })?;

    let free_kb = mem_free_kb.ok_or_else(|| {
        CapabilityExecutionError::new("PARSE_ERROR", "Missing 'MemFree' line in meminfo source")
    })?;

    let available_kb = mem_available_kb.unwrap_or(free_kb);

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

fn parse_meminfo_kb(line: &str) -> Option<u64> {
    let mut parts = line.split_whitespace();
    let _prefix = parts.next()?;
    let value_str = parts.next()?;
    value_str.parse::<u64>().ok()
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
}
