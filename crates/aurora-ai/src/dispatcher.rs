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
use crate::provider::{
    CapabilityExecutionError, CpuProvider, FileProvider, LinuxProcFsProcessProvider,
    LinuxProcMeminfoMemoryProvider, LinuxProcStatCpuProvider, MemoryProvider, MockFileProvider,
    ProcessProvider, SandboxedLocalFileProvider,
};
use aurora_protocol::{
    CapabilityError, CapabilityOutcome, CapabilityResult, CURRENT_PROTOCOL_VERSION,
    ProposeCapability,
};

/// Coordinates capability authorization and execution.
pub struct CapabilityDispatcher {
    policy_engine: PolicyEngine,
    cpu_provider: Arc<dyn CpuProvider>,
    memory_provider: Arc<dyn MemoryProvider>,
    process_provider: Arc<dyn ProcessProvider>,
    file_provider: Arc<dyn FileProvider>,
}

impl CapabilityDispatcher {
    /// Creates a new dispatcher with the provided policy engine and CPU provider.
    pub fn new(policy_engine: PolicyEngine, cpu_provider: Arc<dyn CpuProvider>) -> Self {
        let sandbox_root = policy_engine.registry().sandbox_root().to_path_buf();
        let file_provider: Arc<dyn FileProvider> =
            match SandboxedLocalFileProvider::new(&sandbox_root) {
                Ok(p) => Arc::new(p),
                Err(_) => Arc::new(MockFileProvider::with_error(CapabilityExecutionError::new(
                    "IO_ERROR",
                    "Failed to open sandbox root",
                ))),
            };

        Self {
            policy_engine,
            cpu_provider,
            memory_provider: Arc::new(LinuxProcMeminfoMemoryProvider::new()),
            process_provider: Arc::new(LinuxProcFsProcessProvider::new()),
            file_provider,
        }
    }

    /// Attaches a custom memory provider (useful for testing with mock providers).
    pub fn with_memory_provider(mut self, memory_provider: Arc<dyn MemoryProvider>) -> Self {
        self.memory_provider = memory_provider;
        self
    }

    /// Attaches a custom process provider (useful for testing with mock providers).
    pub fn with_process_provider(mut self, process_provider: Arc<dyn ProcessProvider>) -> Self {
        self.process_provider = process_provider;
        self
    }

    /// Attaches a custom file provider (useful for testing with mock providers).
    pub fn with_file_provider(mut self, file_provider: Arc<dyn FileProvider>) -> Self {
        self.file_provider = file_provider;
        self
    }

    /// Creates a dispatcher with explicit policy engine, CPU provider, and memory provider.
    pub fn new_with_providers(
        policy_engine: PolicyEngine,
        cpu_provider: Arc<dyn CpuProvider>,
        memory_provider: Arc<dyn MemoryProvider>,
    ) -> Self {
        let sandbox_root = policy_engine.registry().sandbox_root().to_path_buf();
        let file_provider: Arc<dyn FileProvider> =
            match SandboxedLocalFileProvider::new(&sandbox_root) {
                Ok(p) => Arc::new(p),
                Err(_) => Arc::new(MockFileProvider::with_error(CapabilityExecutionError::new(
                    "IO_ERROR",
                    "Failed to open sandbox root",
                ))),
            };

        Self {
            policy_engine,
            cpu_provider,
            memory_provider,
            process_provider: Arc::new(LinuxProcFsProcessProvider::new()),
            file_provider,
        }
    }

    /// Creates a dispatcher with explicit policy engine, CPU provider, memory provider, and process provider.
    pub fn new_with_all_providers(
        policy_engine: PolicyEngine,
        cpu_provider: Arc<dyn CpuProvider>,
        memory_provider: Arc<dyn MemoryProvider>,
        process_provider: Arc<dyn ProcessProvider>,
    ) -> Self {
        let sandbox_root = policy_engine.registry().sandbox_root().to_path_buf();
        let file_provider: Arc<dyn FileProvider> =
            match SandboxedLocalFileProvider::new(&sandbox_root) {
                Ok(p) => Arc::new(p),
                Err(_) => Arc::new(MockFileProvider::with_error(CapabilityExecutionError::new(
                    "IO_ERROR",
                    "Failed to open sandbox root",
                ))),
            };

        Self {
            policy_engine,
            cpu_provider,
            memory_provider,
            process_provider,
            file_provider,
        }
    }

    /// Creates a dispatcher with explicit policy engine and all four capability providers.
    pub fn new_with_all_capability_providers(
        policy_engine: PolicyEngine,
        cpu_provider: Arc<dyn CpuProvider>,
        memory_provider: Arc<dyn MemoryProvider>,
        process_provider: Arc<dyn ProcessProvider>,
        file_provider: Arc<dyn FileProvider>,
    ) -> Self {
        Self {
            policy_engine,
            cpu_provider,
            memory_provider,
            process_provider,
            file_provider,
        }
    }

    /// Creates a default dispatcher with MVP policy configuration and Linux telemetry providers.
    pub fn new_default(sandbox_root: PathBuf) -> Self {
        let file_provider: Arc<dyn FileProvider> =
            match SandboxedLocalFileProvider::new(&sandbox_root) {
                Ok(p) => Arc::new(p),
                Err(_) => Arc::new(MockFileProvider::with_error(CapabilityExecutionError::new(
                    "IO_ERROR",
                    "Failed to open sandbox root",
                ))),
            };

        Self::new_with_all_capability_providers(
            PolicyEngine::new_mvp(sandbox_root),
            Arc::new(LinuxProcStatCpuProvider::new()),
            Arc::new(LinuxProcMeminfoMemoryProvider::new()),
            Arc::new(LinuxProcFsProcessProvider::new()),
            file_provider,
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

    /// Access the memory provider.
    pub fn memory_provider(&self) -> &Arc<dyn MemoryProvider> {
        &self.memory_provider
    }

    /// Access the process provider.
    pub fn process_provider(&self) -> &Arc<dyn ProcessProvider> {
        &self.process_provider
    }

    /// Access the file provider.
    pub fn file_provider(&self) -> &Arc<dyn FileProvider> {
        &self.file_provider
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
                    "sys.memory.read" => match self.memory_provider.read_memory() {
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
                    "proc.list" => {
                        let limit: usize = match &proposal.parameters {
                            serde_json::Value::Object(map) => match map.get("limit") {
                                Some(val) => match val.as_i64() {
                                    Some(l) if (1..=50).contains(&l) => l as usize,
                                    _ => {
                                        return CapabilityResult {
                                            protocol_version: CURRENT_PROTOCOL_VERSION,
                                            turn_id: proposal.turn_id.clone(),
                                            call_id: proposal.call_id.clone(),
                                            outcome: CapabilityOutcome::Failure {
                                                error: CapabilityError {
                                                    code: "INVALID_ARGUMENT".to_string(),
                                                    message: "Invalid or malformed 'limit' parameter".to_string(),
                                                },
                                            },
                                        };
                                    }
                                },
                                None => 10,
                            },
                            serde_json::Value::Null => 10,
                            _ => {
                                return CapabilityResult {
                                    protocol_version: CURRENT_PROTOCOL_VERSION,
                                    turn_id: proposal.turn_id.clone(),
                                    call_id: proposal.call_id.clone(),
                                    outcome: CapabilityOutcome::Failure {
                                        error: CapabilityError {
                                            code: "INVALID_ARGUMENT".to_string(),
                                            message: "Expected JSON object or null for proc.list parameters".to_string(),
                                        },
                                    },
                                };
                            }
                        };

                        match self.process_provider.list_processes(limit) {
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
                        }
                    },
                    "fs.file.read" => {
                        let path = match &proposal.parameters {
                            serde_json::Value::Object(map) => match map.get("path") {
                                Some(serde_json::Value::String(p)) => p.as_str(),
                                _ => {
                                    return CapabilityResult {
                                        protocol_version: CURRENT_PROTOCOL_VERSION,
                                        turn_id: proposal.turn_id.clone(),
                                        call_id: proposal.call_id.clone(),
                                        outcome: CapabilityOutcome::Failure {
                                            error: CapabilityError {
                                                code: "INVALID_ARGUMENT".to_string(),
                                                message: "Expected 'path' string parameter"
                                                    .to_string(),
                                            },
                                        },
                                    };
                                }
                            },
                            _ => {
                                return CapabilityResult {
                                    protocol_version: CURRENT_PROTOCOL_VERSION,
                                    turn_id: proposal.turn_id.clone(),
                                    call_id: proposal.call_id.clone(),
                                    outcome: CapabilityOutcome::Failure {
                                        error: CapabilityError {
                                            code: "INVALID_ARGUMENT".to_string(),
                                            message: "Expected JSON object with 'path' parameter"
                                                .to_string(),
                                        },
                                    },
                                };
                            }
                        };

                        match self.file_provider.read_file(path) {
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
                        }
                    }
                    unimplemented => CapabilityResult {
                        protocol_version: CURRENT_PROTOCOL_VERSION,
                        turn_id: proposal.turn_id.clone(),
                        call_id: proposal.call_id.clone(),
                        outcome: CapabilityOutcome::Failure {
                            error: CapabilityError {
                                code: "NOT_IMPLEMENTED".to_string(),
                                message: format!(
                                    "Capability '{unimplemented}' is not implemented"
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
