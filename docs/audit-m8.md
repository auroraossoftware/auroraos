# Aurora OS Milestone 8 — Comprehensive System Audit Report

* **Status:** Complete (Milestone 8 Deliverable)
* **Date:** 2026-10-27
* **Authoritative Context:** [ADR-001](decisions/0001-core-daemon-and-worker-runtime-architecture.md), [ADR-002](decisions/0002-capability-and-permission-architecture.md), [Vertical Slice Prototype Design](vertical-slice-prototype-design.md)
* **Reference Artifacts:** [`docs/performance-baselines-m8.md`](performance-baselines-m8.md), [`docs/decisions/0003-socketpair-ipc-transport.md`](decisions/0003-socketpair-ipc-transport.md)

---

## 1. Overview & Audit Objectives

Milestone 8 performs an authoritative systems and architectural audit of the Aurora OS vertical slice prototype, evaluating the codebase against the requirements of ADR-001, ADR-002, and the prototype specification.

The audit evaluates:
1. **End-to-End Request Pipeline & Authorization Invariants:** Verification of mediation, policy enforcement, parameter validation semantics, and provider execution across all four implemented capabilities (`sys.cpu.read`, `sys.memory.read`, `proc.list`, `fs.file.read`).
2. **IPC Protocol Integrity & Failure Modes:** Directional framing, version negotiation, timeout handling, and proposal flood containment.
3. **Filesystem Confinement & Kernel Boundaries:** Strict verification of `openat2` resolution flags, regular file checks, 64 KiB read bounds, and documented limitations (hard links and worker ambient authority).
4. **Process Lifecycle, Signal Handling & Resource Cleanup:** Child process supervision, file-descriptor leak verification, and stale-socket handling.
5. **Architectural Reconciliation:** Honest accounting of discrepancies between ADR documentation and current implementation (worker recovery and fixed-path signal handling).

---

## 2. End-to-End Request Pipeline & Authorization Invariants

### 2.1 Request Lifecycle Architecture

The request flow traverses eight distinct pipeline stages:

```mermaid
sequenceDiagram
    autonumber
    actor Caller as Caller (CLI / Principal)
    participant Daemon as aurora-ai Core Daemon
    participant Sup as WorkerSupervisor
    participant Worker as Python AI Worker
    participant Dispatcher as CapabilityDispatcher
    participant Policy as PolicyEngine
    participant Provider as CapabilityProvider

    Caller->>Daemon: Submit User Prompt (RequestTurn)
    Daemon->>Sup: execute_turn_with_id(turn_id, prompt)
    Sup->>Worker: Send RequestTurn(turn_id, prompt)
    Worker->>Sup: Send ProposeCapability(turn_id, call_id, capability, params)
    Note over Sup: Increment Turn Proposal Counter (Pre-Dispatch Gate)
    Sup->>Dispatcher: dispatch(caller, turn_id, proposal)
    Dispatcher->>Policy: evaluate(caller, capability, params)
    alt Policy Denies (or Invalid Parameters)
        Policy-->>Dispatcher: PolicyDecision::Deny(reason)
        Dispatcher-->>Sup: CapabilityResult(call_id, Failure(PERMISSION_DENIED))
    else Policy Allows
        Policy-->>Dispatcher: PolicyDecision::Allow
        Dispatcher->>Provider: execute(capability, params)
        Provider-->>Dispatcher: Provider Outcome (Success / Error)
        Dispatcher-->>Sup: CapabilityResult(call_id, Outcome)
    end
    Sup->>Worker: Send CapabilityResult(call_id, outcome)
    Worker->>Sup: Send CompleteTurn(turn_id, synthesis)
    Sup-->>Daemon: TurnSummary { turn_id, final_response, capabilities_executed }
    Daemon-->>Caller: Final Response & Execution Summary
```

### 2.2 Capability Invariants & Policy Enforcement Matrix

All capabilities must be registered in `CapabilityRegistry` and granted to the authenticated caller identity. Anonymous callers are rejected unconditionally.

| Capability | Parameters Checked | Execution Provider | Policy Check Mechanism | Failure Outcome |
| :--- | :--- | :--- | :--- | :--- |
| **`sys.cpu.read`** | None (empty object `{}`) | `ProcCpuProvider` (reads `/proc/stat`) | `PolicyEngine::evaluate` checks explicit caller grant. | `PERMISSION_DENIED` |
| **`sys.memory.read`** | None (empty object `{}`) | `ProcMemoryProvider` (reads `/proc/meminfo`) | `PolicyEngine::evaluate` checks explicit caller grant. | `PERMISSION_DENIED` |
| **`proc.list`** | `limit`: Integer in $[1, 1000]$ (default: 100). | `ProcListProvider` (scans `/proc/[0-9]+/stat`) | `PolicyEngine::evaluate` validates `limit` range and caller grant. | `PERMISSION_DENIED` |
| **`fs.file.read`** | `path`: Relative or absolute path.<br>`offset`: Unsigned integer $\ge 0$.<br>`length`: Integer in $[1, 65536]$. | `FsFileReadProvider` (`openat2` + `pread`) | `PolicyEngine::evaluate` validates component containment within sandbox root and caller grant. | `PERMISSION_DENIED` |

---

### 2.3 Parameter Validation Error Semantics: ADR-002 Alignment & Redundant Code

An essential architectural question investigated during M8 is whether parameter validation failures should return `PERMISSION_DENIED` or `INVALID_ARGUMENT`.

#### 1. Architectural Compliance with ADR-002
* **ADR-002 Section 3.4 & Section 3.10:** Explicitly state:
  > "Default-Deny: Any capability request not explicitly permitted by configured policy is denied with PERMISSION_DENIED."
  > "Parameter Scope Validation: Policy rules may restrict capability parameters (e.g., allowed filesystem subtrees, maximum execution timeouts). Requests exceeding parameter scope fail policy evaluation."
* In the current implementation, `CapabilityDispatcher::dispatch` routes all incoming capability proposals directly through `PolicyEngine::evaluate`.
* `PolicyEngine::evaluate` validates both capability permissions and parameter constraints (e.g., verifying that a path falls strictly within the sandbox or that an integer limit is within range).
* When a parameter violates schema constraints or sandbox scope, `PolicyEngine::evaluate` returns `PolicyDecision::Deny(DenialReason::InvalidParameterScope(...))`.
* Because the policy decision is a denial, the dispatcher immediately generates a `CapabilityOutcome::Failure { code: "PERMISSION_DENIED", ... }`.
* **Conclusion:** Returning `PERMISSION_DENIED` for parameter and scope violations is **strictly compliant** with the approved ADR-002 architectural contract.

#### 2. Code Observation: Redundant Dispatcher Fallback Branches
* In `crates/aurora-ai/src/dispatcher.rs`, following the policy authorization check, the dispatcher executes `match capability.as_str()` blocks that deserialize parameters into typed structs:
  ```rust
  let limit = match parse_limit(params) {
      Ok(l) => l,
      Err(e) => return CapabilityOutcome::Failure { code: "INVALID_ARGUMENT", ... }
  };
  ```
* Because `PolicyEngine::evaluate` has already validated parameter syntax and bounds upstream, these `parse_*` routines in the dispatcher will never encounter an invalid parameter in normal operation.
* These `INVALID_ARGUMENT` branches are currently **dead code** (unreachable in practice).
* **Recommendation:** Retain these branches as defense-in-depth fallbacks, but document that `PolicyEngine` remains the authoritative parameter validator under ADR-002.

---

## 3. IPC Protocol Integrity, Reliability & Failure Containment

### 3.1 Directional Message Framing
* The IPC protocol (`crates/aurora-protocol/src/lib.rs`) enforces strict directional framing:
  * Daemon-to-worker stream carries only `Handshake`, `RequestTurn`, and `CapabilityResult`.
  * Worker-to-daemon stream carries only `HandshakeResponse`, `ProposeCapability`, and `CompleteTurn`.
* A compromised worker attempting to send a `DaemonToWorkerMessage` (such as forging a `RequestTurn`) fails deserialization with `UnknownWorkerMessage` and terminates the connection.

### 3.2 Handshake & Version Negotiation
* On startup, the daemon supervisor sends `Handshake { protocol_version: "0.1.0", ... }`.
* The worker must respond with `HandshakeResponse { accepted: true, protocol_version: "0.1.0" }`.
* Protocol version mismatches or worker rejections result in immediate termination of the worker child process and return `SupervisorError::HandshakeFailed`.

### 3.3 Proposal Flooding Protection (M8 Implementation)
* **The Vulnerability:** Prior to M8, an untrusted or hallucinating worker could emit thousands of `ProposeCapability` messages in a tight loop within a single turn, exhausting CPU and memory in the supervisor.
* **The M8 Implementation:**
  * Introduced `max_proposals_per_turn: usize` in `SupervisorConfig` (defaulting to **20**).
  * In `WorkerSupervisor::execute_turn_with_id`, an atomic proposal counter is incremented **immediately upon receipt of each proposal**, prior to deserialization, parameter extraction, policy evaluation, or provider dispatch.
  * If a 21st proposal is received (`count > max_proposals_per_turn`), the supervisor:
    1. Rejects the turn immediately with `SupervisorError::TurnProposalLimitExceeded { count: 21, limit: 20 }`.
    2. Drops both the socket reader and writer (`self.reader = None; self.writer = None`), invalidating the IPC session.
    3. Guarantees that the excess proposal **never reaches the dispatcher or capability provider**.
* **Test Verification:** Verified by `test_turn_proposal_flood_rejection_at_limit` and `test_turn_proposal_flood_rejection_counts_pre_dispatch` in `crates/aurora-ai/tests/m8_audit_verification_tests.rs`. Both tests pass reliably.

### 3.4 Worker Recovery Discrepancy & M9 Deferral
* **ADR-001 Section 4 Rationale:**
  > "Process Boundary over In-Process FFI: Python crashes, GIL bottlenecks, or memory fragmentation cannot destabilize the aurora-ai daemon. Unhealthy workers can be terminated and restarted by the daemon supervisor."
* **Current Implementation Behavior:**
  * `WorkerSupervisor` detects child process crashes, timeouts, and framing errors. Upon detecting an error, it drops IPC channels and returns a `SupervisorError` (fail-closed behavior).
  * However, `WorkerSupervisor` does **not** currently implement an automatic worker restart loop. Once a worker session fails, subsequent `execute_turn` calls fail with `SupervisorError::SessionNotInitialized`.
* **Architectural Status:**
  * This represents an unresolved architectural discrepancy between ADR-001's design vision and the M1–M7 vertical slice implementation.
  * **Approved Decision:** Defer automatic worker restart logic to **Milestone 9**, where it can be designed natively alongside the transition to anonymous `socketpair` IPC (ADR-003). Automatic restart over filesystem-path-based Unix sockets is prone to file-locking races and stale socket cleanup issues.

---

## 4. Filesystem Confinement & Kernel Security Boundaries

### 4.1 Sandboxed File Reading Implementation (`fs.file.read`)
The `FsFileReadProvider` implements kernel-enforced sandboxing using the modern Linux `openat2` syscall:

```rust
// crates/aurora-ai/src/providers/fs.rs
let mut how = openat2::OpenHow::new();
how.flags(openat2::OFlag::O_RDONLY | openat2::OFlag::O_CLOEXEC);
how.resolve(
    openat2::ResolveFlag::RESOLVE_BENEATH
        | openat2::ResolveFlag::RESOLVE_NO_SYMLINKS
        | openat2::ResolveFlag::RESOLVE_NO_MAGICLINKS
        | openat2::ResolveFlag::RESOLVE_NO_XDEV,
);
```

#### Kernel Invariants Enforced:
1. `RESOLVE_BENEATH`: Prevents any path component from escaping the designated sandbox directory (rejects `../` directory traversals).
2. `RESOLVE_NO_SYMLINKS`: Forbids traversing symbolic links within the path, preventing symlink redirection outside the boundary.
3. `RESOLVE_NO_MAGICLINKS`: Forbids traversing procfs "magic links" (such as `/proc/self/fd/0`), preventing descriptor reuse escapes.
4. `RESOLVE_NO_XDEV`: Forbids crossing mount points (VFS filesystem boundaries).
5. **Regular File Invariant:** Following file descriptor acquisition, `fstat` verifies that `file_type.is_file()` is true. Directory descriptors, device nodes (`/dev/zero`), sockets, and FIFOs are rejected immediately.
6. **Bounded Read:** File contents are read using `pread` up to a maximum buffer limit of **64 KiB** ($65,536$ bytes).

---

### 4.2 Documented Filesystem Confinement Limitations

The audit confirms that while `openat2` provides robust VFS boundary enforcement, two structural security boundaries remain:

#### Limitation 1: Pre-Existing External Hard Links
* In Unix filesystems, a hard link is a directory entry referencing an existing inode.
* If a file within the sandbox root is created as a hard link to a file outside the sandbox (e.g., `/sandbox/secret_link` -> `/etc/shadow`), both entries share the exact same inode.
* Because `openat2` operates on VFS path resolution and does not track external link count origins, resolving `/sandbox/secret_link` with `RESOLVE_BENEATH` succeeds if the link itself is beneath the root directory.
* **Mitigation / Reality:** The sandbox root must be maintained by an administrator without pre-existing hard links from external sensitive locations.

#### Limitation 2: Worker Ambient Authority (No OS Sandboxing)
* The Python AI worker currently executes as a standard child process sharing the daemon's User ID (`UID`) without operating-system-level sandboxing (no user namespaces, no seccomp-bpf, no Landlock LSM).
* While capability proposals are strictly mediated by the daemon's dispatcher, the worker process retains the ambient operating-system authority of its executing UID.
* A compromised worker process could bypass the IPC channel entirely and directly call `open("/etc/passwd")` using standard Linux libc calls.
* **Conclusion:** Full filesystem confinement is not achieved until OS-level process sandboxing (Landlock / namespaces) is implemented in future milestones.

---

## 5. Process Lifecycle, Signal Handling & Resource Hygiene

### 5.1 File Descriptor Leak Verification
File descriptor hygiene was validated across two complementary integration test suites in `crates/aurora-ai/tests/m8_audit_verification_tests.rs`:

1. **In-Process Stream Transport (`test_descriptor_leakage_under_sustained_turns`):**
   * Validates the daemon supervisor's descriptor table (`/proc/self/fd`) under 500 sustained turns using `WorkerSupervisor::from_stream` and a thread-based mock worker.
   * Transient `/proc/self/fd` directory handles are filtered out.
   * Result: Verified daemon descriptor invariance $\Delta \mathcal{S}_{\text{daemon\_fd}} = \emptyset$.

2. **Live External Python Worker Subprocess (`test_external_python_worker_and_daemon_descriptor_leakage_under_sustained_turns`):**
   * Exercises the Rust supervisor directly within the integration-test process (`/proc/self/fd`), while launching the Python worker as a separate unprivileged child process (`/proc/<worker_pid>/fd`) via `WorkerSupervisor::start()`.
   * Captures the live child worker PID and inspects `/proc/<worker_pid>/fd` and `/proc/self/fd` in a quiescent state post-startup.
   * Executes 500 consecutive capability turns cycling across all four approved capabilities (`sys.cpu.read`, `sys.memory.read`, `proc.list`, and sandboxed `fs.file.read` via a controlled temporary sandbox fixture) using the real worker process, waiting for each turn to complete synchronously.
   * Re-evaluates quiescent descriptor snapshots after workload completion for both the live Python worker child process and the daemon/test process.
   * Compares persistent descriptor counts and link target identities, accounting for transient handles.
   * Results:
     * Live Python Worker (Child PID): Baseline 7 descriptors (stdio, socket stream, makefile reader/writer handles). Final snapshot: 7 identical descriptors. Leaked: $\emptyset$, Unexpectedly Closed: $\emptyset$ ($\Delta \mathcal{S}_{\text{worker\_fd}} = \emptyset$).
     * Daemon Supervisor (Test Process): Identical descriptor set before and after 500 turns ($\Delta \mathcal{S}_{\text{daemon\_fd}} = \emptyset$).
   * Process & Socket Cleanup: Verifies child process termination, child process reaping, and clean socket file removal on test completion.

### 5.2 Stale Socket Path Analysis & Signal Handling Deferral

#### Socket Path Computation
In `crates/aurora-ai/src/config.rs`:
```rust
pub fn socket_path(&self) -> PathBuf {
    self.socket_path.clone().unwrap_or_else(|| {
        std::env::temp_dir().join(format!("aurora-ai-{}.sock", std::process::id()))
    })
}
```

#### Behavior Under Abrupt Termination:
1. **Default Mode (PID-based path):**
   * The default socket path includes the current process ID (`/tmp/aurora-ai-{PID}.sock`).
   * If the daemon terminates abruptly (via `SIGKILL`, `SIGINT`, or unhandled `SIGTERM`), the socket file remains as an orphaned inode in `/tmp`.
   * However, because the next invocation of the daemon runs under a new process ID, **the orphaned socket does not block subsequent ordinary startups**.
2. **Fixed Mode (`--socket-path` CLI override):**
   * When an operator provides an explicit fixed path (e.g., `--socket-path /run/aurora/ai.sock`), abrupt process termination leaves the socket file on disk.
   * On subsequent startup, `UnixListener::bind` fails with `EADDRINUSE` (Address already in use), blocking startup until manual administrative intervention.
3. **Approved Decision (M9 Deferral):**
   * Signal-driven cleanup (`signal-hook` / async signal handlers) for fixed paths is **deferred to Milestone 9**.
   * The long-term architectural resolution is the transition to anonymous `socketpair` IPC (ADR-003), which completely eliminates filesystem socket paths and their associated stale-inode failure modes.

---

## 6. Comprehensive Verification Summary

| Verification Category | Test Suite / Target | Invariant Verified | Outcome |
| :--- | :--- | :--- | :---: |
| **Multi-Step Capability Chaining** | `m8_audit_verification_tests.rs` | Sequential execution of multiple capabilities (`sys.cpu.read`, `sys.memory.read`) within a single turn. | **PASSED** |
| **Proposal Flood Rejection** | `m8_audit_verification_tests.rs` | 21st proposal triggers immediate turn rejection and session invalidation; 0 excess executions. | **PASSED** |
| **Pre-Dispatch Counter Accounting** | `m8_audit_verification_tests.rs` | Unauthorized proposals count toward proposal limit; limit reached with 0 provider calls. | **PASSED** |
| **In-Process Descriptor Invariance** | `m8_audit_verification_tests.rs` | $\Delta \mathcal{S}_{\text{FD}} = \emptyset$ across 500 sustained turns (in-process stream). | **PASSED** |
| **Live External Worker FD Invariance** | `m8_audit_verification_tests.rs` | $\Delta \mathcal{S}_{\text{FD}} = \emptyset$ across 500 sustained turns on `/proc/<worker_pid>/fd` (real Python child). | **PASSED** |
| **Sustained Memory Trajectory** | `m8_audit_verification_tests.rs` | Bounded memory consumption across 1,000 sustained turns without monotonic leakage. | **PASSED** |
| **Performance Baselines** | `benches/m8_baselines.rs` | Empirical latency distributions ($p_{50}, p_{90}, p_{99}$) and throughput across 8 scenarios over 3 runs. | **PASSED** |
| **Core Daemon Test Suite** | `crates/aurora-ai` (all targets) | 188 integration and unit tests passing. | **PASSED** |
| **Python Worker Tests** | `worker/` (pytest) | 23 protocol, lifecycle, and handler tests passing. | **PASSED** |

---

## 7. Conclusions & M9 Action Items

1. **Architecture Integrity:**
   * The Aurora OS vertical slice prototype operates with high reliability, minimal IPC overhead (~61 µs median turn latency), and strict fail-closed capability mediation.
   * Parameter validation returning `PERMISSION_DENIED` is fully aligned with ADR-002.
2. **Action Items Deferred to Milestone 9:**
   * **ADR-003 Adoption:** Implement anonymous `socketpair(AF_UNIX, SOCK_STREAM, 0)` IPC transport, deprecating filesystem socket paths for internal worker communication.
   * **Worker Supervision & Restart:** Implement automatic worker restart capability conforming to ADR-001 Section 4 over the new socketpair channel.
   * **Signal-Driven Cleanup:** Implement signal handling for fixed daemon listeners or complete transition to systemd socket activation.
