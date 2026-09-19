//! Minimal deterministic policy engine for Aurora OS.
//!
//! Pursuant to ADR-002, the policy engine is the deterministic authority deciding:
//! "Is this caller allowed to request this capability with these parameters?"
//!
//! Core Invariants:
//! - Strictly deterministic (no probabilistic reasoning or AI models).
//! - Default-deny (anything not known and explicitly granted is rejected).
//! - Fail-closed on all validation or configuration errors.

use crate::capability::CapabilityRegistry;
use crate::identity::CallerIdentity;
use std::collections::HashSet;
use std::path::PathBuf;

/// The outcome of a deterministic authorization evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    /// The requested capability invocation is explicitly permitted.
    Allow,
    /// The requested capability invocation is denied with a deterministic reason.
    Deny { reason: String },
}

impl PolicyDecision {
    /// Returns true if the policy decision is `Allow`.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// Returns true if the policy decision is `Deny`.
    pub fn is_denied(&self) -> bool {
        !self.is_allowed()
    }

    /// Returns the denial reason if denied, or None if allowed.
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Allow => None,
            Self::Deny { reason } => Some(reason.as_str()),
        }
    }
}

impl std::fmt::Display for PolicyDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allow => write!(f, "ALLOW"),
            Self::Deny { reason } => write!(f, "DENY: {reason}"),
        }
    }
}

/// In-memory deterministic policy engine.
pub struct PolicyEngine {
    registry: CapabilityRegistry,
    allowed_grants: HashSet<(CallerIdentity, String)>,
}

impl PolicyEngine {
    /// Creates a new policy engine with the given capability registry.
    pub fn new(registry: CapabilityRegistry) -> Self {
        Self {
            registry,
            allowed_grants: HashSet::new(),
        }
    }

    /// Creates an MVP policy engine with the standard 4 capabilities and a demo sandbox directory.
    pub fn new_mvp(sandbox_root: PathBuf) -> Self {
        let registry = CapabilityRegistry::new_mvp(sandbox_root);
        Self::new(registry)
    }

    /// Returns a reference to the underlying capability registry.
    pub fn registry(&self) -> &CapabilityRegistry {
        &self.registry
    }

    /// Grants a caller explicit permission to invoke a specific capability.
    pub fn grant(&mut self, caller: CallerIdentity, capability_id: impl Into<String>) {
        if caller.is_authenticated() {
            self.allowed_grants.insert((caller, capability_id.into()));
        }
    }

    /// Grants a caller permission for all 4 MVP capabilities.
    pub fn grant_all_mvp(&mut self, caller: &CallerIdentity) {
        if caller.is_authenticated() {
            self.grant(caller.clone(), "sys.cpu.read");
            self.grant(caller.clone(), "sys.memory.read");
            self.grant(caller.clone(), "proc.list");
            self.grant(caller.clone(), "fs.file.read");
        }
    }

    /// Deterministically evaluates whether a caller may invoke a capability with the specified parameters.
    ///
    /// Evaluation Pipeline:
    /// 1. Validate caller identity (reject anonymous / missing callers).
    /// 2. Validate capability name format (reject malformed identifiers).
    /// 3. Registry lookup (reject unknown capabilities).
    /// 4. Parameter & scope validation (reject malformed arguments or sandbox escapes).
    /// 5. Policy grant check (reject callers lacking explicit grants).
    /// 6. Allow.
    pub fn evaluate(
        &self,
        caller: &CallerIdentity,
        capability_id: &str,
        parameters: &serde_json::Value,
    ) -> PolicyDecision {
        // Step 1: Verify caller identity is authenticated
        if !caller.is_authenticated() {
            return PolicyDecision::Deny {
                reason: "Caller identity is missing or unauthenticated".to_string(),
            };
        }

        // Step 2: Validate capability identifier syntax
        if !aurora_protocol::is_valid_capability_name(capability_id) {
            return PolicyDecision::Deny {
                reason: format!("Malformed capability name: '{capability_id}'"),
            };
        }

        // Step 3: Verify capability exists in registry (Default-Deny for unknown capabilities)
        let capability = match self.registry.get(capability_id) {
            Some(cap) => cap,
            None => {
                return PolicyDecision::Deny {
                    reason: format!("Unknown or unregistered capability: '{capability_id}'"),
                };
            }
        };

        // Step 4: Validate parameters and scope constraints (fail-closed)
        if let Err(err_msg) = self.registry.validate_parameters(capability_id, parameters) {
            return PolicyDecision::Deny {
                reason: format!("Parameter or scope validation failed: {err_msg}"),
            };
        }

        // Step 5: Check explicit permission grant (Default-Deny for ungranted callers)
        if capability.requires_authorization {
            let key = (caller.clone(), capability_id.to_string());
            if !self.allowed_grants.contains(&key) {
                return PolicyDecision::Deny {
                    reason: format!(
                        "Caller '{}' is not permitted to request capability '{}'",
                        caller.id().unwrap_or("unknown"),
                        capability_id
                    ),
                };
            }
        }

        // Step 6: Explicitly permitted
        PolicyDecision::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_deny_when_no_grants() {
        let engine = PolicyEngine::new_mvp(PathBuf::from("/tmp/demo"));
        let caller = CallerIdentity::principal("user-1");

        // Known capability, valid params, but caller has no grant -> DENY
        let decision = engine.evaluate(&caller, "sys.cpu.read", &serde_json::json!({}));
        assert!(decision.is_denied());
        assert!(decision.reason().unwrap().contains("is not permitted"));
    }

    #[test]
    fn test_allow_when_explicitly_granted() {
        let mut engine = PolicyEngine::new_mvp(PathBuf::from("/tmp/demo"));
        let caller = CallerIdentity::principal("user-1");
        engine.grant(caller.clone(), "sys.cpu.read");

        let decision = engine.evaluate(&caller, "sys.cpu.read", &serde_json::json!({}));
        assert!(decision.is_allowed());
        assert_eq!(decision, PolicyDecision::Allow);
    }

    #[test]
    fn test_deny_anonymous_caller() {
        let mut engine = PolicyEngine::new_mvp(PathBuf::from("/tmp/demo"));
        let anon = CallerIdentity::anonymous();
        // Even if attempted to grant, anonymous is always denied
        engine.grant(anon.clone(), "sys.cpu.read");

        let decision = engine.evaluate(&anon, "sys.cpu.read", &serde_json::json!({}));
        assert!(decision.is_denied());
        assert!(decision.reason().unwrap().contains("unauthenticated"));
    }

    #[test]
    fn test_deny_unknown_capability() {
        let mut engine = PolicyEngine::new_mvp(PathBuf::from("/tmp/demo"));
        let caller = CallerIdentity::principal("user-1");
        engine.grant(caller.clone(), "fake.unknown.tool");

        let decision = engine.evaluate(&caller, "fake.unknown.tool", &serde_json::json!({}));
        assert!(decision.is_denied());
        assert!(decision.reason().unwrap().contains("Unknown or unregistered"));
    }

    #[test]
    fn test_deny_malformed_capability_name() {
        let engine = PolicyEngine::new_mvp(PathBuf::from("/tmp/demo"));
        let caller = CallerIdentity::principal("user-1");

        let decision = engine.evaluate(&caller, "invalid_name_without_dots", &serde_json::json!({}));
        assert!(decision.is_denied());
        assert!(decision.reason().unwrap().contains("Malformed capability name"));
    }

    #[test]
    fn test_determinism_same_input_same_decision() {
        let mut engine = PolicyEngine::new_mvp(PathBuf::from("/tmp/demo"));
        let caller = CallerIdentity::principal("user-1");
        engine.grant(caller.clone(), "sys.cpu.read");

        let first = engine.evaluate(&caller, "sys.cpu.read", &serde_json::json!({}));
        for _ in 0..100 {
            let next = engine.evaluate(&caller, "sys.cpu.read", &serde_json::json!({}));
            assert_eq!(first, next);
        }
    }
}
