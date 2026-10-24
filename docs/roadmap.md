# Aurora OS Implementation Roadmap

* **Status:** Living Document
* **Authoritative Architecture Context:** [ADR-001](decisions/0001-core-daemon-and-worker-runtime-architecture.md), [ADR-002](decisions/0002-capability-and-permission-architecture.md), and [Vertical Slice Prototype Design](vertical-slice-prototype-design.md)
* **Current Progress:** Milestones 1–5 Complete; Milestone 6 In Progress (M6a & M6b complete; M6c next)

---

## 1. Important Scope Qualifications & Boundary Notes

The milestones documented below track prototype implementation progress against the Aurora OS vertical slice architecture. The following qualifications apply to the current state:

1. **Deterministic Worker Stub (No Neural Models):** The AI worker process is a deterministic Python stub simulating reasoning and intent formulation; no real LLM, model runtime (PyTorch/llama.cpp), embeddings, or inference engine has been introduced.
2. **IPC & Caller Authentication:** Public D-Bus IPC, system bus interfaces, and production caller authentication (e.g., Polkit integration, bus credentials) are deliberately deferred. In M1–M5, callers are represented via internal principal abstractions and direct CLI flags.
3. **Worker Sandboxing:** Production-grade sandboxing (e.g., custom seccomp-bpf filters, Landlock, cgroups, user namespaces) has not yet been established. The worker currently executes as a standard unprivileged child process communicating over a private Unix domain socket.
4. **Test Reporting:** All reported passing tests are implementation-reported automated test suite results verifying internal structural contracts, fail-closed boundaries, and execution paths; they do not represent independent third-party security certification.

---

## 2. Milestone Overview & Status

| Milestone | Title | Status | Primary Focus |
| :--- | :--- | :--- | :--- |
| **M1** | Repository Skeleton & IPC Protocol Contracts | **Complete** | Workspace crates, Python worker skeleton, language-agnostic protocol schemas. |
| **M2** | Core Daemon Lifecycle & Worker Supervision | **Complete** | Child process supervision, private Unix socket handshake, health monitoring. |
| **M3** | Minimal Policy Engine & Capability Registry | **Complete** | Deterministic in-memory policy engine, default-deny evaluator, component-aware path checks. |
| **M4** | First Capability (`sys.cpu.read`) Integrated | **Complete** | Provider abstraction, CapabilityDispatcher mediation, policy pre-authorization enforcement. |
| **M5** | Complete End-to-End Request Flow | **Complete** | Full vertical slice: caller -> daemon -> worker -> proposal -> policy -> provider -> outcome -> worker synthesis -> caller response. |
| **M6** | Remaining MVP Capabilities | **In Progress** (M6a & M6b complete; M6c next) | Implement `sys.memory.read` (M6a complete), `proc.list` (M6b complete), and component-contained `fs.file.read` (M6c next). |
| **M7** | Security, Rejection & Fault Containment Tests | Planned | Comprehensive adversarial test harness (traversal, prefix attacks, malformed frames). |
| **M8** | Verification & Architecture Documentation Review | Planned | End-to-end audit, performance baselines, and architectural findings review. |

---

## 3. Completed Milestones

### Milestone 1: Repository Skeleton & Shared IPC Protocol Contracts
* **Status:** Complete
* **Purpose:** Establish the workspace layout, decoupled crate structure, isolated Python worker package, and the shared, language-agnostic private IPC protocol contract governing communication between the core daemon and the isolated worker process.
* **Main Deliverables:**
  * Cargo workspace structure with `crates/aurora-protocol` (protocol contract crate) and `crates/aurora-ai` (core daemon crate).
  * Python worker package `worker/` with typed protocol models in `worker/protocol.py`.
  * Typed protocol messages: `DaemonToWorkerMessage` (`Handshake`, `RequestTurn`, `CapabilityResult`), `WorkerToDaemonMessage` (`HandshakeResponse`, `ProposeCapability`, `CompleteTurn`), and `CapabilityOutcome`.
  * Protocol contract specification: [docs/internal-worker-protocol.md](internal-worker-protocol.md).
* **Verification Performed:**
  * Rust unit tests in `crates/aurora-protocol/src/lib.rs` (11 tests): JSON serialization round-trips, unsupported version rejection, invalid capability name rejection, rejection of unknown messages, and enforcement of directional message framing (worker cannot forge daemon messages).
  * Python unit tests in `worker/test_protocol.py` (7 tests): serialization round-trips, capability name validation, version validation, and JSON decoding matching Rust definitions.
* **Relevant Documents & Code:**
  * Specification: [docs/internal-worker-protocol.md](internal-worker-protocol.md)
  * Rust Contracts: `crates/aurora-protocol/src/lib.rs`
  * Python Contracts: `worker/protocol.py`
  * Tests: `crates/aurora-protocol/src/lib.rs`, `worker/test_protocol.py`

---

### Milestone 2: Core Daemon Lifecycle & Worker Supervision
* **Status:** Complete
* **Purpose:** Implement child process lifecycle supervision, private point-to-point IPC hosting, and protocol version handshake negotiation in the core daemon (`aurora-ai`), along with the connection skeleton in the Python worker stub.
* **Main Deliverables:**
  * `WorkerSupervisor` in `crates/aurora-ai/src/supervisor.rs`: manages isolated child process spawn, private Unix domain socket listener binding, connection timeout handling, handshake exchange, process health polling, and clean socket unlinking on shutdown.
  * Worker runtime in `worker/main.py`: connects to private socket, performs handshake verification, returns `HandshakeResponse`, and maintains connection loop.
  * Transport utilities in `crates/aurora-ai/src/ipc.rs`: newline-delimited JSON (NDJSON) streaming and framing.
  * Configuration in `crates/aurora-ai/src/config.rs`: configurable socket paths, worker commands, and handshake timeouts.
* **Verification Performed:**
  * Supervisor lifecycle tests in `crates/aurora-ai/tests/supervisor_tests.rs` (5 tests): successful process spawn, connection and handshake; rejection of incompatible protocol versions; detection of premature worker exit without daemon crash; and clean resource cleanup on termination.
  * Worker lifecycle tests in `worker/test_worker.py`: socket connection, handshake acknowledge, version mismatch handling.
* **Relevant Documents & Code:**
  * Decision Record: [ADR-001](decisions/0001-core-daemon-and-worker-runtime-architecture.md)
  * Design: [Vertical Slice Prototype Design (Section 3 & 8)](vertical-slice-prototype-design.md)
  * Code: `crates/aurora-ai/src/supervisor.rs`, `crates/aurora-ai/src/ipc.rs`, `worker/main.py`
  * Tests: `crates/aurora-ai/tests/supervisor_tests.rs`, `worker/test_worker.py`

---

### Milestone 3: Minimal Deterministic Policy Engine & Capability Registry
* **Status:** Complete
* **Purpose:** Implement an in-memory, deterministic policy engine enforcing default-deny access control, caller identity checking, capability whitelisting, and parameter validation, decoupled from the untrusted worker.
* **Main Deliverables:**
  * `CallerIdentity` in `crates/aurora-ai/src/identity.rs`: distinguishes authenticated principals from unauthenticated/anonymous callers.
  * `CapabilityRegistry` in `crates/aurora-ai/src/capability.rs`: declarative definitions for the 4 MVP capabilities (`sys.cpu.read`, `sys.memory.read`, `proc.list`, `fs.file.read`) with parameter schema validation.
  * Component-aware path confinement (`is_component_contained`, `normalize_path`): strictly verifies file paths within sandbox hierarchies using path components rather than naive string prefixes (preventing sibling bypasses like `/demo` vs `/demo-secret`).
  * `PolicyEngine` in `crates/aurora-ai/src/policy.rs`: deterministic evaluation pipeline enforcing: (1) caller authentication, (2) capability name syntax, (3) registry whitelist, (4) parameter scope constraints, (5) explicit caller permission grants.
* **Verification Performed:**
  * Policy integration tests in `crates/aurora-ai/tests/policy_tests.rs` (15 tests): default-deny when ungranted, allow on explicit grant, anonymous caller denial, unknown capability rejection, malformed name rejection, determinism validation (100 identical iterations yielding identical decisions), parameter scope checks, and component-aware path containment vs sibling directory traversal.
  * Registry unit tests in `crates/aurora-ai/src/capability.rs`: component-aware containment and parameter validation.
* **Relevant Documents & Code:**
  * Decision Record: [ADR-002](decisions/0002-capability-and-permission-architecture.md)
  * Design: [Vertical Slice Prototype Design (Section 5 & 6)](vertical-slice-prototype-design.md)
  * Code: `crates/aurora-ai/src/policy.rs`, `crates/aurora-ai/src/capability.rs`, `crates/aurora-ai/src/identity.rs`
  * Tests: `crates/aurora-ai/tests/policy_tests.rs`

---

### Milestone 4: First Capability (`sys.cpu.read`) Integrated Through Policy Boundary
* **Status:** Complete
* **Purpose:** Implement and integrate the first concrete capability provider (`sys.cpu.read`) through the policy engine and capability dispatcher, proving that capability execution strictly occurs after authorization and never on denial.
* **Main Deliverables:**
  * `CpuProvider` trait and implementations in `crates/aurora-ai/src/provider.rs`: `LinuxProcStatCpuProvider` (parses real Linux `/proc/stat`) and `MockCpuProvider` (invocation tracking and simulated errors).
  * `CapabilityDispatcher` in `crates/aurora-ai/src/dispatcher.rs`: mediates between untrusted capability proposals, the policy gate, and concrete providers.
  * Clean error categorization: differentiates execution failures (`IO_ERROR`) from authorization denials (`PERMISSION_DENIED`).
* **Verification Performed:**
  * Integration tests in `crates/aurora-ai/tests/m4_cpu_capability_tests.rs` (9 tests) & dispatcher unit tests: authorized caller succeeds with structured telemetry, unauthorized caller denied with `PERMISSION_DENIED` and provider invocation count remains 0, anonymous caller denied with count 0, invalid parameters rejected with count 0, provider execution error cleanly distinguished from authorization denial, and real Linux `/proc/stat` parsing against the host system.
* **Relevant Documents & Code:**
  * Design: [Vertical Slice Prototype Design (Section 5 & 11)](vertical-slice-prototype-design.md)
  * Code: `crates/aurora-ai/src/dispatcher.rs`, `crates/aurora-ai/src/provider.rs`
  * Tests: `crates/aurora-ai/tests/m4_cpu_capability_tests.rs`

---

### Milestone 5: Complete End-to-End Request Flow (Vertical Slice)
* **Status:** Complete
* **Purpose:** Prove the first full vertical slice: client/CLI -> daemon -> worker -> proposal -> policy engine -> capability provider -> outcome -> worker synthesis -> client response.
* **Main Deliverables:**
  * End-to-end turn coordination in `WorkerSupervisor`: implemented `execute_turn` and `execute_turn_with_id` coordinating `RequestTurn`, receiving `ProposeCapability`, delegating to `CapabilityDispatcher`, returning `CapabilityResult`, and receiving `CompleteTurn`.
  * Turn execution loop in Python worker `worker/main.py`: implemented `handle_request_turn` to deterministically propose `sys.cpu.read`, receive observation outcome, format synthesis text, and return `CompleteTurn`.
  * Deterministic test seams in worker: handles `simulate_crash`, `invalid_proposal_name`, `invalid_params`, `unknown_capability`, and `noop`.
  * Minimal CLI integration in `crates/aurora-ai/src/main.rs`: `--request`, `--caller`, `--unauthorized`, and `--anonymous` flags to exercise the full vertical slice from the command line.
* **Verification Performed:**
  * Integration tests in `crates/aurora-ai/tests/m5_end_to_end_flow_tests.rs` (12 tests):
    1. Authorized request nominal flow + multi-turn execution.
    2. **Critical Security Property Proven:** Untrusted worker proposal -> policy DENY -> provider invocation count == 0.
    3. Anonymous caller proposal denied with provider invocation count 0.
    4. Invalid capability name syntax rejected before provider execution.
    5. Invalid parameter scope rejected before provider execution.
    6. Unknown capability proposal rejected before provider execution.
    7. Worker crash during turn (code 137) handled safely without daemon crash.
    8. Provider execution failure (`IO_ERROR`) propagates as execution error, not masked as permission error.
    9. Malformed wire message fails deserialization with provider invocation count 0.
    10. Forged message direction rejected with provider invocation count 0.
    11. Prevention of authorization bypass.
    12. Real Linux host telemetry execution end-to-end.
  * CLI execution verification: successfully tested `--request "check cpu"` and `--request "check cpu" --unauthorized`.
  * Python integration tests in `worker/test_worker.py`: turn flow, denial handling, and multi-turn execution.
  * Workspace test suite: 72 Rust tests + 12 Python tests passing cleanly.
* **Relevant Documents & Code:**
  * Protocol: [docs/internal-worker-protocol.md](internal-worker-protocol.md)
  * Design: [Vertical Slice Prototype Design (Section 2 & 11)](vertical-slice-prototype-design.md)
  * Code: `crates/aurora-ai/src/supervisor.rs`, `crates/aurora-ai/src/main.rs`, `worker/main.py`
  * Tests: `crates/aurora-ai/tests/m5_end_to_end_flow_tests.rs`, `worker/test_worker.py`

---

## 4. Milestone 6: Remaining MVP Capabilities (In Progress)

* **Status:** In Progress (Sub-milestone M6a complete and verified; M6b next)
* **Target:** Remaining MVP Capabilities (`sys.memory.read`, `proc.list`, `fs.file.read`)
* **Execution Strategy:** Divided into three strictly isolated sequential sub-milestones (M6a, M6b, M6c).

---

### Sub-milestone M6a: Host Memory Metrics (`sys.memory.read`)
* **Status:** Complete
* **Purpose:** Implement and integrate the second concrete capability provider (`sys.memory.read`) through the existing policy engine, capability dispatcher, and untrusted worker request flow.
* **Main Deliverables:**
  * `MemoryProvider` trait in `crates/aurora-ai/src/provider.rs`: abstraction for memory metric queries with mock implementation (`MockMemoryProvider`) for deterministic test assertions.
  * `LinuxProcMeminfoMemoryProvider`: prototype provider parsing `/proc/meminfo` lines (`MemTotal`, `MemFree`, `MemAvailable`), computing metrics in binary MiB (`total_mb`, `used_mb`, `free_mb`, `available_mb`, retaining `_mb` field names for protocol compatibility). Explicitly validates against duplicate fields, unexpected units, malformed values, and zero totals. Documented fallback logic when `MemAvailable` is absent (kernels < 3.14) as a lower-bound approximation, and `used_mb` as an estimate (`total - available`).
  * Dispatcher integration in `crates/aurora-ai/src/dispatcher.rs`: wired `sys.memory.read` through `PolicyEngine` pre-authorization check; denied proposals never execute the provider.
  * Worker stub integration in `worker/main.py`: handles prompts requesting memory metrics ("memory", "ram"), formats structured response upon success.
  * CLI flag support in `crates/aurora-ai/src/main.rs`: permits `--request "check memory"` for authorized runs.
  * Architectural & Isolation Boundary Qualification: Operating-system-level confinement of the worker (e.g. seccomp, namespaces, Landlock) is not yet active; the worker process is an ordinary unprivileged child process and can read world-readable `/proc` files at the OS level. Isolation and policy enforcement for capability execution are strictly mediated at the application/protocol level by the daemon.
* **Verification Performed:**
  * Unit tests in `crates/aurora-ai/src/provider.rs`: proc meminfo parsing, unit conversion (kB to MiB), duplicate field rejection, malformed value rejection, unexpected unit rejection, missing field validation, and mock invocation counting.
  * Integration tests in `crates/aurora-ai/tests/m6a_memory_capability_tests.rs` (10 tests):
    1. Authorized proposal succeeds with structured telemetry.
    2. Unauthorized proposal denied with `PERMISSION_DENIED` and provider count 0.
    3. Anonymous caller proposal denied with provider count 0.
    4. Invalid parameters rejected before provider execution.
    5. Provider failure (`IO_ERROR`) cleanly distinguished from authorization denial.
    6. Real Linux `/proc/meminfo` provider integration test on host.
    7. Supervisor turn integration enforces authorization before execution.
    8. Authorized end-to-end flow with worker synthesis.
    9. Unauthorized end-to-end flow denied with provider invocation count 0.
    10. Real host telemetry end-to-end execution.
  * Python unit & integration tests in `worker/test_worker.py`: memory prompt synthesis and response validation.
  * Full regression run: 94 Rust tests + 13 Python tests passing.
* **Relevant Code:**
  * Provider: `crates/aurora-ai/src/provider.rs`
  * Dispatcher: `crates/aurora-ai/src/dispatcher.rs`
  * Tests: `crates/aurora-ai/tests/m6a_memory_capability_tests.rs`, `worker/test_worker.py`

---

### Sub-milestone M6b: Process Listing (`proc.list`)
* **Status:** Complete
* **Purpose:** Implement and integrate the third concrete capability provider (`proc.list`) through the existing policy engine, capability dispatcher, and untrusted worker request flow.
* **Main Deliverables:**
  * `ProcessProvider` trait in `crates/aurora-ai/src/provider.rs`: abstraction for process enumeration with mock implementation (`MockProcessProvider`) tracking invocation count and limit bounds.
  * `LinuxProcFsProcessProvider`: prototype provider inspecting `/proc` directly via Rust standard library filesystem APIs without spawning subshells or executing external utilities (`ps`, `pgrep`, `top`).
  * Minimal & Confined Metadata: Discovers numeric PIDs, extracts executable basename from `/proc/<pid>/comm`, and resident memory from `/proc/<pid>/status` (`VmRSS:` in binary MiB). Prohibits reading command-line arguments (`cmdline`), environment variables (`environ`), or file descriptors.
  * Resilient Enumeration: Ephemeral processes that exit or have permission restrictions during directory traversal are skipped gracefully without failing the request; systemic `/proc` unmount/permission failures return an explicit `IO_ERROR`.
  * Deterministic Sorting & Bounding: Results are sorted deterministically in ascending order by PID and truncated to the validated limit ($1 \le \text{limit} \le 50$, default 10).
  * Omission of `cpu_percent`: Documented technical rationale that a single snapshot provides cumulative clock ticks rather than an instantaneous percentage, omitting it to prevent misleading telemetry in a stateless observation capability.
  * Parameter Enforcement: Registry strictly validates `limit` ($1 \le \text{limit} \le 50$), rejecting non-integers, out-of-range values, unexpected fields, and unsupported types before provider invocation.
  * Dispatcher integration in `crates/aurora-ai/src/dispatcher.rs`: extracts validated limit (or default 10) without silent clamping; gated behind `PolicyDecision::Allow`.
  * Worker stub integration in `worker/main.py`: handles process queries ("process", "ps", "task"), proposes `proc.list`, and synthesizes summary upon success.
  * CLI flag support in `crates/aurora-ai/src/main.rs`: permits `--request "list processes"` on authorized runs.
* **Verification Performed:**
  * Unit tests in `crates/aurora-ai/src/provider.rs`: synthetic `/proc` tree parsing, comm extraction, VmRSS conversion, PID ascending sort, limit truncation, inaccessible directory `IO_ERROR`, and mock counting.
  * Parameter tests in `crates/aurora-ai/src/capability.rs`: rejection of `limit = 0`, `limit = -5`, `limit = 51`, `"ten"`, floats, unexpected fields, and non-object inputs.
  * Integration tests in `crates/aurora-ai/tests/m6b_process_capability_tests.rs` (13 tests):
    1. Authorized proposal succeeds with bounded results and PID ascending sort.
    2. Default limit of 10 applied when parameter is omitted or empty.
    3. Unauthorized proposal denied with `PERMISSION_DENIED` and provider count 0.
    4. Anonymous caller proposal denied with provider count 0.
    5. Invalid limit rejected before provider execution with count 0.
    6. Unexpected parameter rejected before provider execution with count 0.
    7. Unsupported parameter types rejected before provider execution with count 0.
    8. Provider failure (`IO_ERROR`) cleanly distinguished from authorization denial.
    9. Supervisor turn integration enforces authorization before execution.
    10. Real Linux `/proc` provider integration test on host.
    11. Authorized end-to-end flow with worker synthesis.
    12. Unauthorized end-to-end flow denied with provider invocation count 0.
    13. Real host telemetry end-to-end execution.
  * Python unit & integration tests in `worker/test_worker.py`: process prompt synthesis, regex word boundary intent matching, and response validation.
  * Full regression run: 111 Rust tests + 16 Python tests passing.
* **Relevant Code:**
  * Provider: `crates/aurora-ai/src/provider.rs`
  * Registry: `crates/aurora-ai/src/capability.rs`
  * Dispatcher: `crates/aurora-ai/src/dispatcher.rs`
  * Tests: `crates/aurora-ai/tests/m6b_process_capability_tests.rs`, `worker/test_worker.py`

---

### Sub-milestone M6c: Sandboxed File Reading (`fs.file.read`)
* **Status:** Planned (Follows M6b)
* **Scope:**
  * Scoped read-only filesystem capability strictly confined within a demonstration sandbox directory hierarchy.
  * Rigorous defense against `..` traversal, sibling-prefix confusion, symbolic links, and race conditions.
  * Fail-closed rejection and bounded read limits.
