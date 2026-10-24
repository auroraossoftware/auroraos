//! Capability registry and parameter validation for Aurora OS.
//!
//! Pursuant to ADR-002, capabilities are narrow, typed, declarative operations.
//! At Milestone 3, capabilities are definitions only: they specify schema,
//! nature, and parameter/scope constraints, but do NOT execute system actions.

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};

/// Classification of a capability's operational behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityNature {
    /// Read-only observation of system state or telemetry.
    Observational,
    /// Action that modifies system state or environment.
    Mutating,
}

/// Metadata and constraints defining an available system capability.
#[derive(Debug, Clone)]
pub struct CapabilityDefinition {
    /// Canonical capability identifier (e.g. `sys.cpu.read`).
    pub id: String,
    /// Human-readable explanation of capability purpose.
    pub description: String,
    /// Whether the capability is an observation or mutation.
    pub nature: CapabilityNature,
    /// Whether this capability mandates an explicit caller permission grant.
    pub requires_authorization: bool,
}

/// Registry of known capability definitions and prototype scope constraints.
pub struct CapabilityRegistry {
    capabilities: HashMap<String, CapabilityDefinition>,
    sandbox_root: PathBuf,
}

impl CapabilityRegistry {
    /// Creates an empty registry with a designated filesystem sandbox root.
    pub fn new(sandbox_root: PathBuf) -> Self {
        Self {
            capabilities: HashMap::new(),
            sandbox_root,
        }
    }

    /// Creates the standard MVP registry containing definitions for the 4 MVP capabilities:
    /// - `sys.cpu.read`
    /// - `sys.memory.read`
    /// - `proc.list`
    /// - `fs.file.read`
    pub fn new_mvp(sandbox_root: PathBuf) -> Self {
        let mut registry = Self::new(sandbox_root);

        // 1. sys.cpu.read
        registry.register(CapabilityDefinition {
            id: "sys.cpu.read".to_string(),
            description: "Reads host CPU telemetry metrics".to_string(),
            nature: CapabilityNature::Observational,
            requires_authorization: true,
        });

        // 2. sys.memory.read
        registry.register(CapabilityDefinition {
            id: "sys.memory.read".to_string(),
            description: "Reads host memory telemetry metrics".to_string(),
            nature: CapabilityNature::Observational,
            requires_authorization: true,
        });

        // 3. proc.list
        registry.register(CapabilityDefinition {
            id: "proc.list".to_string(),
            description: "Lists active processes with resource usage metrics".to_string(),
            nature: CapabilityNature::Observational,
            requires_authorization: true,
        });

        // 4. fs.file.read
        registry.register(CapabilityDefinition {
            id: "fs.file.read".to_string(),
            description: "Reads file contents strictly within the demonstration sandbox"
                .to_string(),
            nature: CapabilityNature::Observational,
            requires_authorization: true,
        });

        registry
    }

    /// Registers a capability definition into the registry.
    pub fn register(&mut self, definition: CapabilityDefinition) {
        self.capabilities.insert(definition.id.clone(), definition);
    }

    /// Retrieves a capability definition by its canonical ID.
    pub fn get(&self, id: &str) -> Option<&CapabilityDefinition> {
        self.capabilities.get(id)
    }

    /// Returns true if the capability ID is registered.
    pub fn contains(&self, id: &str) -> bool {
        self.capabilities.contains_key(id)
    }

    /// Returns the current sandbox root path.
    pub fn sandbox_root(&self) -> &Path {
        &self.sandbox_root
    }

    /// Validates structured parameters against the capability's schema and scope constraints.
    pub fn validate_parameters(
        &self,
        capability_id: &str,
        params: &serde_json::Value,
    ) -> Result<(), String> {
        match capability_id {
            "sys.cpu.read" | "sys.memory.read" => {
                // Telemetry capabilities accept null or empty object {}
                match params {
                    serde_json::Value::Null => Ok(()),
                    serde_json::Value::Object(map) if map.is_empty() => Ok(()),
                    serde_json::Value::Object(map) => {
                        Err(format!("Unexpected parameters for telemetry capability: {map:?}"))
                    }
                    _ => Err("Expected JSON object or null for telemetry parameters".to_string()),
                }
            }
            "proc.list" => {
                // Optional parameter: "limit" (integer, 1 <= limit <= 50)
                match params {
                    serde_json::Value::Null => Ok(()),
                    serde_json::Value::Object(map) => {
                        // Reject any unexpected fields
                        for key in map.keys() {
                            if key != "limit" {
                                return Err(format!("Unexpected parameter for proc.list: '{key}'"));
                            }
                        }

                        if let Some(val) = map.get("limit") {
                            match val.as_i64() {
                                Some(limit) if (1..=50).contains(&limit) => Ok(()),
                                Some(limit) => Err(format!(
                                    "Parameter 'limit' must be between 1 and 50 (got {limit})"
                                )),
                                None => Err("Parameter 'limit' must be an integer".to_string()),
                            }
                        } else {
                            Ok(())
                        }
                    }
                    _ => Err("Expected JSON object or null for proc.list parameters".to_string()),
                }
            }
            "fs.file.read" => {
                // Required parameter: "path" (strictly relative, clean subpath bounded to sandbox)
                match params {
                    serde_json::Value::Object(map) => {
                        for key in map.keys() {
                            if key != "path" {
                                return Err(format!(
                                    "Unexpected parameter for fs.file.read: '{key}'"
                                ));
                            }
                        }

                        let path_val = map
                            .get("path")
                            .ok_or_else(|| "Missing required parameter 'path'".to_string())?;

                        let path_str = path_val
                            .as_str()
                            .ok_or_else(|| "Parameter 'path' must be a string".to_string())?;

                        validate_fs_path(path_str)?;
                        is_component_contained(&self.sandbox_root, path_str)
                    }
                    _ => Err(
                        "Expected JSON object with 'path' parameter for fs.file.read".to_string(),
                    ),
                }
            }
            _ if self.capabilities.contains_key(capability_id) => Ok(()),
            _ => Err(format!(
                "No parameter validation defined for unknown capability: '{capability_id}'"
            )),
        }
    }
}

/// Validates raw input path strings before any path parser or normalization runs.
///
/// Security & Contract Requirements:
/// - Path must be relative to the sandbox root (cannot start with '/' or '~').
/// - Length bounded to 1..=255 bytes.
/// - Cannot be empty or whitespace-only.
/// - Cannot contain null bytes ('\0') or ASCII control characters (< 32 or 127).
/// - Raw segment inspection: explicitly rejects '.' (e.g. 'dir/./file.txt') and '..'.
/// - Rejects empty segments (e.g. 'dir//file.txt' or trailing '/').
pub fn validate_fs_path(path_str: &str) -> Result<(), String> {
    if path_str.is_empty() || path_str.trim().is_empty() {
        return Err("Path parameter cannot be empty or whitespace-only".to_string());
    }

    if path_str.len() > 255 {
        return Err("Path parameter exceeds maximum permitted length of 255 bytes".to_string());
    }

    if path_str.contains('\0') {
        return Err("Path contains illegal null byte".to_string());
    }

    if path_str.chars().any(|c| (c as u32) < 32 || c == '\x7f') {
        return Err("Path contains illegal control characters".to_string());
    }

    // Relative-only path contract: must not start with '/' or '~'
    if path_str.starts_with('/') || path_str.starts_with('~') {
        return Err("Path must be relative to the sandbox root".to_string());
    }

    // Inspect raw path segments before any path parser or normalization runs
    for segment in path_str.split('/') {
        if segment == "." {
            return Err("Explicit '.' path components are not permitted".to_string());
        }
        if segment == ".." {
            return Err("Explicit '..' path components are not permitted".to_string());
        }
        if segment.is_empty() {
            return Err(
                "Empty path segments and consecutive slashes are not permitted".to_string(),
            );
        }
    }

    Ok(())
}

/// Normalizes a path by resolving '.' and '..' components without accessing the filesystem.
///
/// Returns an error if '..' attempts to traverse past the path's root.
pub fn normalize_path(path: &Path) -> Result<PathBuf, String> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(p) => normalized.push(Component::Prefix(p)),
            Component::RootDir => normalized.push(Component::RootDir),
            Component::CurDir => {} // ignore '.'
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err("Path traversal escape via '..' component".to_string());
                }
            }
            Component::Normal(c) => normalized.push(c),
        }
    }
    Ok(normalized)
}

/// Verifies that `requested_path` is strictly contained within `sandbox_root`
/// using component-aware analysis.
///
/// Security Guarantees:
/// 1. Never relies on textual string prefix matching (e.g. `/demo` vs `/demo-secret`).
/// 2. Resolves path components (`.` and `..`) deterministically in memory.
/// 3. Rejects path traversal escapes (`../`).
/// 4. Rejects empty paths or paths targeting the sandbox root directory itself.
pub fn is_component_contained(sandbox_root: &Path, requested_path: &str) -> Result<(), String> {
    if requested_path.trim().is_empty() {
        return Err("Path parameter cannot be empty".to_string());
    }

    if requested_path.contains('\0') {
        return Err("Path contains illegal null byte".to_string());
    }

    let raw_path = Path::new(requested_path);

    // Resolve relative path against sandbox root, or keep absolute path
    let candidate = if raw_path.is_relative() {
        sandbox_root.join(raw_path)
    } else {
        raw_path.to_path_buf()
    };

    // Normalize candidate path
    let normalized = normalize_path(&candidate)?;

    // Normalize sandbox root
    let normalized_sandbox = normalize_path(sandbox_root)?;

    // Component-aware containment check:
    // Path::starts_with compares component-by-component!
    if !normalized.starts_with(&normalized_sandbox) {
        return Err(format!(
            "Path '{}' escapes demo sandbox '{}'",
            requested_path,
            sandbox_root.display()
        ));
    }

    // Must not be the sandbox root directory itself for a file read
    if normalized == normalized_sandbox {
        return Err("Target path cannot be the sandbox root directory itself".to_string());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_component_aware_sandbox_containment() {
        let sandbox = Path::new("/demo");

        // Allowed: relative paths inside sandbox
        assert!(is_component_contained(sandbox, "test.txt").is_ok());
        assert!(is_component_contained(sandbox, "subdir/notes.md").is_ok());
        assert!(is_component_contained(sandbox, "./test.txt").is_ok());
        assert!(is_component_contained(sandbox, "subdir/../test.txt").is_ok());

        // Allowed: absolute paths strictly inside sandbox
        assert!(is_component_contained(sandbox, "/demo/test.txt").is_ok());
        assert!(is_component_contained(sandbox, "/demo/subdir/notes.md").is_ok());

        // Denied: sibling prefix mismatch (CRITICAL: /demo vs /demo-secret)
        assert!(is_component_contained(sandbox, "/demo-secret").is_err());
        assert!(is_component_contained(sandbox, "/demo-secret/secret.txt").is_err());
        assert!(is_component_contained(sandbox, "../demo-secret/secret.txt").is_err());

        // Denied: path traversal escaping sandbox
        assert!(is_component_contained(sandbox, "../../etc/passwd").is_err());
        assert!(is_component_contained(sandbox, "/etc/shadow").is_err());
        assert!(is_component_contained(sandbox, "sub/../../etc/passwd").is_err());

        // Denied: empty or root path
        assert!(is_component_contained(sandbox, "").is_err());
        assert!(is_component_contained(sandbox, "   ").is_err());
        assert!(is_component_contained(sandbox, "/demo").is_err());
    }

    #[test]
    fn test_mvp_registry_definitions() {
        let registry = CapabilityRegistry::new_mvp(PathBuf::from("/tmp/demo"));

        assert!(registry.contains("sys.cpu.read"));
        assert!(registry.contains("sys.memory.read"));
        assert!(registry.contains("proc.list"));
        assert!(registry.contains("fs.file.read"));
        assert!(!registry.contains("fake.admin.tool"));

        let cpu = registry.get("sys.cpu.read").unwrap();
        assert_eq!(cpu.nature, CapabilityNature::Observational);
        assert!(cpu.requires_authorization);
    }

    #[test]
    fn test_proc_list_parameter_validation() {
        let registry = CapabilityRegistry::new_mvp(PathBuf::from("/tmp/demo"));

        // Valid limits
        assert!(registry
            .validate_parameters("proc.list", &serde_json::Value::Null)
            .is_ok());
        assert!(registry
            .validate_parameters("proc.list", &serde_json::json!({}))
            .is_ok());
        assert!(registry
            .validate_parameters("proc.list", &serde_json::json!({"limit": 10}))
            .is_ok());
        assert!(registry
            .validate_parameters("proc.list", &serde_json::json!({"limit": 50}))
            .is_ok());

        // Invalid limits and unexpected parameters
        assert!(registry
            .validate_parameters("proc.list", &serde_json::json!({"limit": 0}))
            .is_err());
        assert!(registry
            .validate_parameters("proc.list", &serde_json::json!({"limit": -5}))
            .is_err());
        assert!(registry
            .validate_parameters("proc.list", &serde_json::json!({"limit": 51}))
            .is_err());
        assert!(registry
            .validate_parameters("proc.list", &serde_json::json!({"limit": "ten"}))
            .is_err());
        assert!(registry
            .validate_parameters("proc.list", &serde_json::json!({"limit": 10.5}))
            .is_err());
        assert!(registry
            .validate_parameters("proc.list", &serde_json::json!({"limit": 10, "extra": "field"}))
            .is_err());
        assert!(registry
            .validate_parameters("proc.list", &serde_json::json!({"unexpected": 123}))
            .is_err());
        assert!(registry
            .validate_parameters("proc.list", &serde_json::json!([1, 2, 3]))
            .is_err());
    }

    #[test]
    fn test_fs_file_read_parameter_validation() {
        let registry = CapabilityRegistry::new_mvp(PathBuf::from("/tmp/demo"));

        // Valid relative paths
        assert!(registry
            .validate_parameters("fs.file.read", &serde_json::json!({"path": "test.txt"}))
            .is_ok());
        assert!(registry
            .validate_parameters(
                "fs.file.read",
                &serde_json::json!({"path": "subdir/notes.md"})
            )
            .is_ok());

        // Rejection of explicit '.' components (raw segment inspection)
        assert!(registry
            .validate_parameters("fs.file.read", &serde_json::json!({"path": "./test.txt"}))
            .is_err());
        assert!(registry
            .validate_parameters(
                "fs.file.read",
                &serde_json::json!({"path": "dir/./file.txt"})
            )
            .is_err());
        assert!(registry
            .validate_parameters("fs.file.read", &serde_json::json!({"path": "."}))
            .is_err());
        assert!(registry
            .validate_parameters("fs.file.read", &serde_json::json!({"path": "dir/."}))
            .is_err());

        // Rejection of '..' components
        assert!(registry
            .validate_parameters(
                "fs.file.read",
                &serde_json::json!({"path": "../secret.txt"})
            )
            .is_err());
        assert!(registry
            .validate_parameters(
                "fs.file.read",
                &serde_json::json!({"path": "dir/../file.txt"})
            )
            .is_err());

        // Rejection of absolute paths
        assert!(registry
            .validate_parameters(
                "fs.file.read",
                &serde_json::json!({"path": "/tmp/demo/test.txt"})
            )
            .is_err());
        assert!(registry
            .validate_parameters("fs.file.read", &serde_json::json!({"path": "/etc/passwd"}))
            .is_err());

        // Rejection of empty segments and consecutive slashes
        assert!(registry
            .validate_parameters(
                "fs.file.read",
                &serde_json::json!({"path": "dir//file.txt"})
            )
            .is_err());
        assert!(registry
            .validate_parameters("fs.file.read", &serde_json::json!({"path": "dir/"}))
            .is_err());

        // Rejection of empty, whitespace, null, control chars, length > 255
        assert!(registry
            .validate_parameters("fs.file.read", &serde_json::json!({"path": ""}))
            .is_err());
        assert!(registry
            .validate_parameters("fs.file.read", &serde_json::json!({"path": "   "}))
            .is_err());
        assert!(registry
            .validate_parameters("fs.file.read", &serde_json::json!({"path": "foo\0bar"}))
            .is_err());
        assert!(registry
            .validate_parameters("fs.file.read", &serde_json::json!({"path": "foo\nbar"}))
            .is_err());
        let long_path = "a".repeat(256);
        assert!(registry
            .validate_parameters("fs.file.read", &serde_json::json!({"path": long_path}))
            .is_err());

        // Rejection of unexpected extra fields
        assert!(registry
            .validate_parameters(
                "fs.file.read",
                &serde_json::json!({"path": "test.txt", "extra": 123})
            )
            .is_err());

        // Rejection of non-object / non-string
        assert!(registry
            .validate_parameters("fs.file.read", &serde_json::json!({}))
            .is_err());
        assert!(registry
            .validate_parameters("fs.file.read", &serde_json::json!({"path": 123}))
            .is_err());
        assert!(registry
            .validate_parameters("fs.file.read", &serde_json::Value::Null)
            .is_err());
    }
}
