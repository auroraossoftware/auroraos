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
            description: "Reads file contents strictly within the demonstration sandbox".to_string(),
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
                    _ => Err("Expected JSON object for proc.list parameters".to_string()),
                }
            }
            "fs.file.read" => {
                // Required parameter: "path" (string, must be component-contained in sandbox)
                match params {
                    serde_json::Value::Object(map) => {
                        let path_val = map
                            .get("path")
                            .ok_or_else(|| "Missing required parameter 'path'".to_string())?;

                        let path_str = path_val
                            .as_str()
                            .ok_or_else(|| "Parameter 'path' must be a string".to_string())?;

                        is_component_contained(&self.sandbox_root, path_str)
                    }
                    _ => Err("Expected JSON object with 'path' parameter for fs.file.read".to_string()),
                }
            }
            _ => Err(format!("No parameter validation defined for unknown capability: '{capability_id}'")),
        }
    }
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
            .validate_parameters("proc.list", &serde_json::json!({}))
            .is_ok());
        assert!(registry
            .validate_parameters("proc.list", &serde_json::json!({"limit": 10}))
            .is_ok());
        assert!(registry
            .validate_parameters("proc.list", &serde_json::json!({"limit": 50}))
            .is_ok());

        // Invalid limits
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
    }
}
