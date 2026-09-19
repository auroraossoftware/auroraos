//! Capability dispatcher mediating between the deterministic policy engine and providers.
//!
//! Pursuant to ADR-001 and ADR-002:
//! - Capability requests (or worker proposals) MUST pass through policy authorization first.
//! - A capability provider is invoked ONLY IF the policy evaluation yields `PolicyDecision::Allow`.
//! - Denied requests return immediately with `PERMISSION_DENIED` and NEVER invoke providers.
//! - Provider execution failures are distinguished from authorization denials.

use std::path::PathBuf;
use std::sync::Arc;

use crate::identity::CallerIdentity;
use crate::policy::{PolicyDecision, PolicyEngine};
use crate::provider::{CpuProvider, LinuxProcStatCpuProvider};
use aurora_protocol::{
    CapabilityError, CapabilityOutcome, CapabilityResult, CURRENT_PROTOCOL_VERSION,
    ProposeCapability,
};

/// Coordinates capability authorization and execution.
pub struct CapabilityDispatcher {
    policy_engine: PolicyEngine,
    cpu_provider: Arc<dyn CpuProvider>,
}

impl CapabilityDispatcher {
    /// Creates a new dispatcher with the provided policy engine and CPU provider.
    pub fn new(policy_engine: PolicyEngine, cpu_provider: Arc<dyn CpuProvider>) -> Self {
        Self {
            policy_engine,
            cpu_provider,
        }
    }

    /// Creates a default dispatcher with MVP policy configuration and Linux `/proc/stat` CPU provider.
    pub fn new_default(sandbox_root: PathBuf) -> Self {
        Self::new(
            PolicyEngine::new_mvp(sandbox_root),
            Arc::new(LinuxProcStatCpuProvider::new()),
        )
    }

    /// Access the underlying policy engine.
    pub fn policy_engine(&self) -> &PolicyEngine {
        &self.policy_engine
    }

    /// Access mutable underlying policy engine (e.g. to configure grants).
    pub fn policy_engine_mut(&mut self) -> &mut PolicyEngine {
        &mut self.policy_engine
    }

    /// Access the CPU provider.
    pub fn cpu_provider(&self) -> &Arc<dyn CpuProvider> {
        &self.cpu_provider
    }

    /// Evaluates a proposal against policy without executing the capability.
    pub fn evaluate(
        &self,
        caller: &CallerIdentity,
        proposal: &ProposeCapability,
    ) -> PolicyDecision {
        self.policy_engine
            .evaluate(caller, &proposal.capability_name, &proposal.parameters)
    }

    /// Executes an untrusted capability proposal through the deterministic policy boundary.
    ///
    /// # Security Invariants
    /// 1. Proposal schema and structural correctness are checked.
    /// 2. Policy engine evaluates caller identity and capability parameters.
    /// 3. If policy denies the request, a failure result is returned immediately.
    ///    **The capability provider is NEVER invoked.**
    /// 4. If policy allows the request, the corresponding provider is executed.
    /// 5. Provider execution errors (e.g. IO error) are returned with their distinct error codes,
    ///    never converted to authorization failures.
    pub fn execute_proposal(
        &self,
        caller: &CallerIdentity,
        proposal: &ProposeCapability,
    ) -> CapabilityResult {
        // Step 1: Validate proposal structural validity
        if let Err(val_err) = proposal.validate() {
            return CapabilityResult {
                protocol_version: CURRENT_PROTOCOL_VERSION,
                turn_id: proposal.turn_id.clone(),
                call_id: proposal.call_id.clone(),
                outcome: CapabilityOutcome::Failure {
                    error: CapabilityError {
                        code: "INVALID_ARGUMENT".to_string(),
                        message: val_err.to_string(),
                    },
                },
            };
        }

        // Step 2: Deterministic policy authorization
        let decision = self.policy_engine.evaluate(
            caller,
            &proposal.capability_name,
            &proposal.parameters,
        );

        // Step 3: Enforce policy decision (fail-closed)
        match decision {
            PolicyDecision::Deny { reason } => CapabilityResult {
                protocol_version: CURRENT_PROTOCOL_VERSION,
                turn_id: proposal.turn_id.clone(),
                call_id: proposal.call_id.clone(),
                outcome: CapabilityOutcome::Failure {
                    error: CapabilityError {
                        code: "PERMISSION_DENIED".to_string(),
                        message: reason,
                    },
                },
            },
            PolicyDecision::Allow => {
                // Step 4: Execute capability provider
                match proposal.capability_name.as_str() {
                    "sys.cpu.read" => match self.cpu_provider.read_cpu() {
                        Ok(data) => CapabilityResult {
                            protocol_version: CURRENT_PROTOCOL_VERSION,
                            turn_id: proposal.turn_id.clone(),
                            call_id: proposal.call_id.clone(),
                            outcome: CapabilityOutcome::Success { data },
                        },
                        Err(err) => CapabilityResult {
                            protocol_version: CURRENT_PROTOCOL_VERSION,
                            turn_id: proposal.turn_id.clone(),
                            call_id: proposal.call_id.clone(),
                            outcome: CapabilityOutcome::Failure {
                                error: CapabilityError {
                                    code: err.code,
                                    message: err.message,
                                },
                            },
                        },
                    },
                    unimplemented => CapabilityResult {
                        protocol_version: CURRENT_PROTOCOL_VERSION,
                        turn_id: proposal.turn_id.clone(),
                        call_id: proposal.call_id.clone(),
                        outcome: CapabilityOutcome::Failure {
                            error: CapabilityError {
                                code: "NOT_IMPLEMENTED".to_string(),
                                message: format!(
                                    "Capability '{unimplemented}' is not implemented in Milestone 4"
                                ),
                            },
                        },
                    },
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{CapabilityExecutionError, MockCpuProvider};

    fn make_proposal(name: &str, params: serde_json::Value) -> ProposeCapability {
        ProposeCapability {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            turn_id: "turn-100".to_string(),
            call_id: "call-200".to_string(),
            capability_name: name.to_string(),
            parameters: params,
        }
    }

    #[test]
    fn test_authorized_proposal_executes_provider() {
        let caller = CallerIdentity::principal("user-test");
        let mut policy = PolicyEngine::new_mvp(PathBuf::from("/demo"));
        policy.grant(caller.clone(), "sys.cpu.read");

        let mock_provider = Arc::new(MockCpuProvider::with_success(serde_json::json!({
            "user_percent": 15.2,
            "idle_percent": 80.1,
        })));
        let dispatcher = CapabilityDispatcher::new(policy, mock_provider.clone());

        let proposal = make_proposal("sys.cpu.read", serde_json::json!({}));
        let result = dispatcher.execute_proposal(&caller, &proposal);

        assert_eq!(mock_provider.invocation_count(), 1);
        match result.outcome {
            CapabilityOutcome::Success { data } => {
                assert_eq!(data["user_percent"], 15.2);
                assert_eq!(data["idle_percent"], 80.1);
            }
            CapabilityOutcome::Failure { error } => {
                panic!("Expected Success, got error: {error:?}");
            }
        }
    }

    #[test]
    fn test_unauthorized_proposal_never_invokes_provider() {
        let caller = CallerIdentity::principal("user-unauthorized");
        let policy = PolicyEngine::new_mvp(PathBuf::from("/demo")); // no grants

        let mock_provider = Arc::new(MockCpuProvider::with_success(serde_json::json!({})));
        let dispatcher = CapabilityDispatcher::new(policy, mock_provider.clone());

        let proposal = make_proposal("sys.cpu.read", serde_json::json!({}));
        let result = dispatcher.execute_proposal(&caller, &proposal);

        // Security Invariant: provider must NEVER be called
        assert_eq!(
            mock_provider.invocation_count(),
            0,
            "Provider was invoked on unauthorized request!"
        );

        match result.outcome {
            CapabilityOutcome::Failure { error } => {
                assert_eq!(error.code, "PERMISSION_DENIED");
                assert!(error.message.contains("not permitted"));
            }
            CapabilityOutcome::Success { .. } => {
                panic!("Expected Failure, got Success!");
            }
        }
    }

    #[test]
    fn test_anonymous_caller_never_invokes_provider() {
        let anon = CallerIdentity::anonymous();
        let policy = PolicyEngine::new_mvp(PathBuf::from("/demo"));

        let mock_provider = Arc::new(MockCpuProvider::with_success(serde_json::json!({})));
        let dispatcher = CapabilityDispatcher::new(policy, mock_provider.clone());

        let proposal = make_proposal("sys.cpu.read", serde_json::json!({}));
        let result = dispatcher.execute_proposal(&anon, &proposal);

        assert_eq!(mock_provider.invocation_count(), 0);
        match result.outcome {
            CapabilityOutcome::Failure { error } => {
                assert_eq!(error.code, "PERMISSION_DENIED");
                assert!(error.message.contains("unauthenticated"));
            }
            CapabilityOutcome::Success { .. } => panic!("Expected Failure"),
        }
    }

    #[test]
    fn test_unknown_capability_never_invokes_provider() {
        let caller = CallerIdentity::principal("user-1");
        let mut policy = PolicyEngine::new_mvp(PathBuf::from("/demo"));
        policy.grant(caller.clone(), "fake.unknown.cap");

        let mock_provider = Arc::new(MockCpuProvider::with_success(serde_json::json!({})));
        let dispatcher = CapabilityDispatcher::new(policy, mock_provider.clone());

        let proposal = make_proposal("fake.unknown.cap", serde_json::json!({}));
        let result = dispatcher.execute_proposal(&caller, &proposal);

        assert_eq!(mock_provider.invocation_count(), 0);
        match result.outcome {
            CapabilityOutcome::Failure { error } => {
                assert_eq!(error.code, "PERMISSION_DENIED");
                assert!(error.message.contains("Unknown or unregistered"));
            }
            CapabilityOutcome::Success { .. } => panic!("Expected Failure"),
        }
    }

    #[test]
    fn test_invalid_parameters_never_invokes_provider() {
        let caller = CallerIdentity::principal("user-1");
        let mut policy = PolicyEngine::new_mvp(PathBuf::from("/demo"));
        policy.grant(caller.clone(), "sys.cpu.read");

        let mock_provider = Arc::new(MockCpuProvider::with_success(serde_json::json!({})));
        let dispatcher = CapabilityDispatcher::new(policy, mock_provider.clone());

        // sys.cpu.read does not accept extra arguments
        let proposal = make_proposal("sys.cpu.read", serde_json::json!({"unexpected_key": 123}));
        let result = dispatcher.execute_proposal(&caller, &proposal);

        assert_eq!(mock_provider.invocation_count(), 0);
        match result.outcome {
            CapabilityOutcome::Failure { error } => {
                assert_eq!(error.code, "PERMISSION_DENIED");
                assert!(error.message.contains("Parameter or scope validation"));
            }
            CapabilityOutcome::Success { .. } => panic!("Expected Failure"),
        }
    }

    #[test]
    fn test_provider_execution_error_distinguished_from_permission_denied() {
        let caller = CallerIdentity::principal("user-1");
        let mut policy = PolicyEngine::new_mvp(PathBuf::from("/demo"));
        policy.grant(caller.clone(), "sys.cpu.read");

        let mock_provider = Arc::new(MockCpuProvider::with_failure(
            CapabilityExecutionError::new("IO_ERROR", "Failed to open /proc/stat"),
        ));
        let dispatcher = CapabilityDispatcher::new(policy, mock_provider.clone());

        let proposal = make_proposal("sys.cpu.read", serde_json::json!({}));
        let result = dispatcher.execute_proposal(&caller, &proposal);

        // Provider WAS invoked because caller was authorized
        assert_eq!(mock_provider.invocation_count(), 1);

        match result.outcome {
            CapabilityOutcome::Failure { error } => {
                // Must be IO_ERROR, NOT PERMISSION_DENIED
                assert_eq!(error.code, "IO_ERROR");
                assert_ne!(error.code, "PERMISSION_DENIED");
                assert!(error.message.contains("/proc/stat"));
            }
            CapabilityOutcome::Success { .. } => panic!("Expected Failure"),
        }
    }
}
