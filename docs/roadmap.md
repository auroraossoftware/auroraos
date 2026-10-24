# Aurora OS Implementation Roadmap

* **Status:** Living Document
* **Authoritative Architecture Context:** [ADR-001](decisions/0001-core-daemon-and-worker-runtime-architecture.md), [ADR-002](decisions/0002-capability-and-permission-architecture.md), and [Vertical Slice Prototype Design](vertical-slice-prototype-design.md)
* **Current Progress:** Milestones 1–7 Complete (Milestone 8 next)

---

## 1. Important Scope Qualifications & Boundary Notes

The milestones documented below track prototype implementation progress against the Aurora OS vertical slice architecture. The following qualifications apply to the current state:

1. **Deterministic Worker Stub (No Neural Models):** The AI worker process is a deterministic Python stub simulating reasoning and intent formulation; no real LLM, model runtime (PyTorch/llama.cpp), embeddings, or inference engine has been introduced.
2. **IPC & Caller Authentication:** Public D-Bus IPC, system bus interfaces, and production caller authentication (e.g., Polkit integration, bus credentials) are deliberately deferred. In M1–M5, callers are represented via internal principal abstractions and direct CLI flags.
3. **Worker Sandboxing & Ambient Authority:** Operating-system-level confinement (e.g., custom seccomp-bpf filters, Landlock, cgroups, user/mount namespaces) has not yet been established. The worker currently executes as a standard unprivileged child process sharing the daemon's UID. While capability permissions and policy gates are strictly enforced at the daemon's dispatcher boundary, the worker process retains the ambient OS authority of its executing UID (including direct filesystem access to world-readable files and shared same-UID directories). True zero-ambient-authority confinement requires dedicated OS sandboxing.
4. **Test Reporting:** All reported passing tests are implementation-reported automated test suite results verifying internal structural contracts, fail-closed boundaries, and execution paths; they do not represent independent third-party security certification.
5. **Filesystem Socket Lifecycle & Threat-Model Boundaries:** Path-based Unix domain socket IPC in shared filesystem directories has inherent Linux VFS boundaries:
   * *Cross-UID Isolation vs. Same-UID Boundaries:* The current implementation defaults to `std::env::temp_dir()` (typically `/tmp`) and does not create or validate parent directory permissions. Deploying the socket in an external private directory with mode `0700` owned by the daemon user is an operational deployment recommendation that isolates the socket from other unprivileged UIDs, but it is not enforced by code and does **not** protect against a malicious or compromised process sharing the daemon's own UID.
   * *Two Distinct Socket Lifecycle Races on Shared Paths:*
     1. *Post-Bind Ownership-Capture Race:* Between `UnixListener::bind(&path)` returning and `symlink_metadata(&path)` reading the host inode, a concurrent same-UID process could unlink the socket and substitute another entry, causing the daemon to record the replacement's inode.
     2. *Shutdown Check-Then-Unlink Race:* Between `symlink_metadata(&path)` checking the entry on shutdown and `std::fs::remove_file(&path)` executing `unlink()`, a concurrent same-UID process could swap the socket with another file, causing the daemon to unlink the replacement. Linux provides no atomic `unlink_if_matches` syscall, and `fstat` on a socket descriptor queries `sockfs` (which diverges from the host filesystem's inode), preventing descriptor-based path validation.
   * *Socket-Pair IPC Scope:* Transitioning to anonymous `socketpair` IPC in a future ADR removes all filesystem-path races for that channel, but process-level isolation, memory safety, and file-descriptor inheritance remain separate security concerns.

---

## 2. Milestone Overview & Status

| Milestone | Title | Status | Primary Focus |
| :--- | :--- | :--- | :--- |
| **M1** | Repository Skeleton & IPC Protocol Contracts | **Complete** | Workspace crates, Python worker skeleton, language-agnostic protocol schemas. |
| **M2** | Core Daemon Lifecycle & Worker Supervision | **Complete** | Child process supervision, private Unix socket handshake, health monitoring. |
| **M3** | Minimal Policy Engine & Capability Registry | **Complete** | Deterministic in-memory policy engine, default-deny evaluator, component-aware path checks. |
| **M4** | First Capability (`sys.cpu.read`) Integrated | **Complete** | Provider abstraction, CapabilityDispatcher mediation, policy pre-authorization enforcement. |
| **M5** | Complete End-to-End Request Flow | **Complete** | Full vertical slice: caller -> daemon -> worker -> proposal -> policy -> provider -> outcome -> worker synthesis -> caller response. |
| **M6** | Remaining MVP Capabilities | **Complete** | Implemented `sys.memory.read` (M6a), `proc.list` (M6b), and kernel-contained `fs.file.read` (M6c). |
| **M7** | Security, Rejection & Fault Containment Tests | **Complete** (Reconciled Prototype Scope) | Adversarial test harness, non-destructive socket pre-checking, fail-closed invalidation, and documented threat-model boundaries. |
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

## 4. Milestone 6: Remaining MVP Capabilities
* **Status:** Complete (Sub-milestones M6a, M6b, and M6c complete)
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
* **Status:** Complete
* **Purpose:** Implement and integrate the fourth concrete capability provider (`fs.file.read`) with kernel-enforced path containment, strict pre-normalization path validation, bounded 64 KiB reads, and safe 512 KiB byte-bounded IPC framing across Rust and Python.
* **Main Deliverables:**
  * **Byte-Bounded 512 KiB IPC Framing:**
    * Shared `MAX_IPC_FRAME_SIZE = 524_288` bytes (512 KiB inclusive of trailing `\n`) enforced in raw bytes across Rust (`read_bounded_line` in `crates/aurora-ai/src/ipc.rs`) and Python (`BoundedSocketFile` in `worker/main.py`).
    * Worst-case control-character expansion analysis: 64 KiB of control characters expands to ~393 KiB in JSON string escaping, fitting safely within the 512 KiB per-frame buffering limit with ~128 KiB headroom.
    * Immediate fail-closed socket closure on oversized frames or unterminated frames at EOF to prevent message desynchronization or fragment misparsing.
    * Protocol specification updated in `docs/internal-worker-protocol.md` (Section 5.1).
  * **Kernel-Enforced Path Containment (`openat2`):**
    * `FileProvider` trait and `SandboxedLocalFileProvider` in `crates/aurora-ai/src/provider.rs` backed by `rustix::fs::openat2`.
    * Retained trusted sandbox root directory descriptor (`dirfd`) opened with `O_PATH | O_DIRECTORY | O_CLOEXEC`.
    * Enforces `ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_XDEV`.
    * Rejects leaf and intermediate symlinks (`SYMLINK_REJECTED`), mount crossings, and directory escapes.
    * Concurrently safe against TOCTOU path-replacement races (verified via parallel stress test).
  * **Strict Pre-Normalization Syntactic Validation:**
    * `validate_fs_path` in `crates/aurora-ai/src/capability.rs` inspects raw path segments before any path parser or normalization runs.
    * Strictly rejects relative traversal (`..`), explicit dot components (`.`, e.g. `dir/./file.txt`), empty segments / consecutive slashes (`//`), absolute paths (`/`), tildes (`~`), null bytes (`\0`), control characters, and lengths exceeding 255 bytes.
    * Any syntactic or policy denial guarantees provider invocation count remains exactly 0.
  * **Bounded & Regular File Safety:**
    * Bounded read via `take(MAX_FILE_SIZE_BYTES + 1)` (65,537 bytes) enforcing the 64 KiB (65,536 bytes) limit. Files exceeding this are rejected (`FILE_TOO_LARGE`).
    * Metadata inspection via `rustix::fs::fstat` verifying regular file status; directories (`IS_A_DIRECTORY`) and FIFOs/devices/sockets (`NOT_REGULAR_FILE`) are rejected immediately without blocking.
    * Strict UTF-8 verification; binary files fail cleanly (`INVALID_ENCODING`) without returning partial contents.
    * Explicit syscall error mapping (`NOT_FOUND`, `TEMPORARILY_UNAVAILABLE` on `EAGAIN`, `UNSUPPORTED_PLATFORM` on `ENOSYS`). Never falls back to userspace canonicalize-then-open.
  * **Honest Security Boundary & Documentation:**
    * Explicit documentation of hard-link threats (hard links can point outside sandbox if created in advance by a writer) and same-UID access caveats.
    * Architectural boundary qualification: Python worker is not yet OS-sandboxed (e.g. seccomp, Landlock); containment is enforced at the daemon's capability provider level.
  * **Worker & Supervisor Integration:**
    * Worker stub in `worker/main.py` parses file requests ("read <path>"), proposes `fs.file.read`, and formats responses (`File content (<size> bytes): <preview>`).
    * `WorkerSupervisor` advertises `fs.file.read` in handshake schema; `CapabilityDispatcher` dispatches authorized requests to `FileProvider`.
* **Verification Performed:**
  * IPC Framing Unit Tests in `crates/aurora-ai/src/ipc.rs` (10 tests): clean EOF, valid frame, exact boundary (524,288 bytes), oversized frame (+1 byte), unterminated frame at EOF, worst-case control character payload (~393 KiB), byte vs character counting for multibyte UTF-8, and connection teardown on framing error.
  * Python Framing & Worker Tests in `worker/test_worker.py` (8 framing/file tests, 21 total suite tests): `BoundedSocketFile` exact limit, oversized rejection, unterminated EOF rejection, multibyte UTF-8 byte counting, worst-case control-character expansion roundtrip, socket closure on framing error, file read proposal, and turn synthesis.
  * Capability & Path Validation Tests in `crates/aurora-ai/src/capability.rs`: rejection of `.`, `..`, empty segments, absolute paths, null bytes, control characters, oversized paths, and unexpected parameter fields.
  * Direct Provider Unit Tests in `crates/aurora-ai/src/provider.rs`: nominal file reads, subpaths, 64 KiB exact, 64 KiB + 1 byte rejection, non-UTF8 rejection, directory rejection, and simulated syscall errors.
  * Integration Tests in `crates/aurora-ai/tests/m6c_file_capability_tests.rs` (29 tests):
    1. Unauthorized caller denied with provider count 0.
    2. Anonymous caller denied with provider count 0.
    3. Missing path parameter denied with provider count 0.
    4. Non-string path parameter denied with provider count 0.
    5. Unexpected parameter fields denied with provider count 0.
    6. Control characters denied with provider count 0.
    7. Empty and whitespace path denied with provider count 0.
    8. Null byte path denied with provider count 0.
    9. Path length exceeded (>255) denied with provider count 0.
    10. Explicit dot component (`dir/./file.txt`, `./file.txt`, `.`) denied with provider count 0.
    11. Traversal dot-dot (`../secret.txt`, `sub/../../etc/passwd`) denied with provider count 0.
    12. Absolute path (`/etc/passwd`, `/sandbox/file.txt`) denied with provider count 0.
    13. Direct provider sibling directory containment rejection.
    14. Authorized nominal file read.
    15. Nested subpath file read.
    16. Leaf symlink rejected without leaking outside content.
    17. Intermediate directory symlink rejected without leaking outside content.
    18. FIFO rejected without blocking indefinitely.
    19. Directory path rejected (`IS_A_DIRECTORY`).
    20. File size exactly 64 KiB succeeds.
    21. File size 64 KiB + 1 byte rejected (`FILE_TOO_LARGE`).
    22. Non-UTF8 binary rejected (`INVALID_ENCODING`) without partial content.
    23. Missing file returns `NOT_FOUND`.
    24. Simulated `EAGAIN` returns `TEMPORARILY_UNAVAILABLE` safely.
    25. Unsupported `ENOSYS` fails closed (`UNSUPPORTED_PLATFORM`).
    26. Concurrent path-replacement race stress test (verifying outside sentinel data never leaks under parallel swap/read contention).
    27. Authorized end-to-end file read turn with live Python worker.
    28. Unauthorized end-to-end file read turn denied with `PERMISSION_DENIED`.
    29. Escape end-to-end turn denied with `PERMISSION_DENIED`.
  * Verification Summary:
    - Functional & Integration Tests: PASSED (153 Rust tests across 10 test suites + 21 Python worker tests, 100% pass rate).
    - Linter / Clippy: PASSED (`cargo clippy --workspace --all-targets --all-features -- -D warnings` clean with 0 warnings, 0 errors).
    - Whitespace & Diff Check: PASSED (`git diff --check` clean with 0 errors).
    - Targeted M6c Code Formatting: PASSED (M6c newly added and modified code verified compliant with `rustfmt`).
    - Workspace-Wide Formatting Check: FAILED (`cargo fmt --all -- --check` fails with exit code 1 due to pre-existing legacy formatting variances in files from Milestones 1–6b; repository-wide reformatting was deliberately not applied to prevent unrelated diff churn across prior milestones).
* **Relevant Code:**
  * IPC: `crates/aurora-ai/src/ipc.rs`, `worker/main.py`
  * Provider: `crates/aurora-ai/src/provider.rs`
  * Path Validation: `crates/aurora-ai/src/capability.rs`
  * Dispatcher: `crates/aurora-ai/src/dispatcher.rs`
  * Specification: `docs/internal-worker-protocol.md`
  * Tests: `crates/aurora-ai/tests/m6c_file_capability_tests.rs`, `worker/test_worker.py`

---

## 5. Milestone 7: Security, Rejection & Fault Containment Tests

* **Status:** Complete (Reconciled Prototype Scope)
* **Purpose:** Construct a comprehensive adversarial test harness and harden core supervisor lifecycle and protocol handling against hostile worker inputs, connection state desynchronization, socket path collisions, malformed frames, and path boundary attacks.
* **Acceptance Criteria Reconciliation & Scope Boundary:**
  * **Criteria Genuinely Met:**
    * Comprehensive adversarial test suite covering all planned categories (29 Rust tests + 2 Python tests, 100% pass rate).
    * Non-destructive startup refusal: all pre-existing filesystem entries (active listeners, dead sockets, regular files, dangling symlinks) are detected and refused without modification or deletion.
    * Drop safety: dropping a failed supervisor instance never deletes pre-existing entries (`owns_socket` initialized to `false`).
    * Post-bind internal failure cleanup: freshly bound sockets are cleaned up on spawn or handshake failure.
    * Passive path replacement detection on shutdown: replacement regular files, directories, symlinks, or non-matching sockets are preserved.
    * Fail-closed protocol invalidation on both inbound violations and outbound write transmission failures.
    * Policy-before-provider execution invariant enforced across all 4 capabilities with 0 provider invocations on denial.
  * **Reconciled Threat-Model Boundary:**
    * If the milestone requirement for socket ownership is interpreted as *guaranteeing immunity against a hostile, concurrent same-UID process racing filesystem path entries in a shared directory*, this requirement cannot be met by path-based IPC under Linux POSIX semantics (due to `sockfs` inode divergence and the lack of atomic `unlink_if_matches`).
    * Under the approved prototype scope (protecting against stale entries, uncoordinated instances, accidental conflicts, worker crashes, and cross-UID boundaries), Milestone 7 meets all acceptance criteria. Protection against malicious same-UID path manipulation is formally deferred to the proposed Socket-Pair IPC architecture.
* **Main Deliverables & Hardening:**
  * **Strict Socket Ownership & Non-Destructive Lifecycle Cleanup:**
    * Hardened `WorkerSupervisor` in `crates/aurora-ai/src/supervisor.rs` with explicit socket ownership tracking (`owns_socket: bool`) and bound inode recording (`bound_socket_dev_ino: Option<(u64, u64)>`).
    * Startup Pre-Check: checks `symlink_metadata(&self.socket_path)` without following symlinks. Refuses startup (`SupervisorError::SocketAlreadyExists(path)`) if any entry exists (active listener, dead socket, regular file, or dangling symlink) without modifying or deleting it.
    * Drop & Shutdown Safety: `shutdown()` and `Drop::drop()` only unlink the socket path if `self.owns_socket` is true. If `start()` was refused or failed before bind (or if created via `from_stream`), `owns_socket` remains false, guaranteeing pre-existing entries are never deleted on drop or shutdown.
    * Socket-Path Replacement Safeguard: `shutdown()` verifies that the entry at `self.socket_path` is still a socket (`FileTypeExt::is_socket()`) and matches the originally bound `(dev, ino)` before unlinking. Replacement entries (regular files, symlinks, or foreign sockets) are preserved untouched.
    * Post-Bind Failure Cleanup: failures occurring after successful bind (spawn failure, accept timeout, handshake failure) cleanly invoke `shutdown()`, removing the bound socket and preventing avoidable stale entries.
    * Configurable socket timeout builder `SupervisorConfig::with_socket_timeout(timeout)` in `crates/aurora-ai/src/config.rs`.
  * **Detailed Documentation of Socket Lifecycle Races & Linux Semantics:**
    * *Linux Kernel Semantics (`sockfs` vs. Host VFS):* In Linux, `fstat()` on a `UnixListener` descriptor returns the inode inside the kernel's internal `sockfs` pseudo-filesystem (`st_dev` of `sockfs`), whereas `lstat()` on the filesystem pathname returns the inode allocated by the host filesystem (e.g., `ext4`, `tmpfs`). Because these identifiers reside in distinct filesystems and never match, descriptor metadata cannot establish ownership of the pathname's filesystem entry.
    * *Post-Bind Ownership-Capture Race:* Between `UnixListener::bind(&path)` returning and `symlink_metadata(&path)` reading the host inode, a concurrent same-UID process with write access to the directory could unlink the socket and substitute another entry. The subsequent `symlink_metadata` call would read and record the replacement entry's `(dev, ino)`, causing the supervisor to adopt ownership of an entry it did not create.
    * *Shutdown Check-Then-Unlink Race:* Between `symlink_metadata(&path)` checking the entry on shutdown and `std::fs::remove_file(&path)` executing `unlink()`, a concurrent same-UID process could swap the socket with another file. Because Linux provides no atomic `unlink_if_matches` syscall, the daemon would unlink the replacement entry.
    * *Guarantees Provided by Current Implementation:*
      * Guaranteed protection against accidental startup collisions with dead/stale sockets, active listeners, and regular files.
      * Guaranteed preservation of pre-existing entries when a failed supervisor instance is dropped.
      * Guaranteed cleanup of freshly bound sockets if spawn or handshake fails internally.
      * Guaranteed preservation of non-socket replacement files on shutdown.
    * *Deployment Assumptions & Guarantees NOT Provided:*
      * Aurora does **not** create or validate parent directory permissions or ownership; cross-UID protection is an environmental assumption requiring deployment in an externally managed `0700` directory.
      * Even when deployed in an external `0700` directory, directory permissions do **not** isolate the daemon from a malicious or compromised process sharing the daemon's own UID.
      * Path-based Unix sockets cannot provide atomic race immunity against concurrent same-UID filesystem manipulation in a shared directory.
  * **Future Architecture Proposal: Socket-Pair IPC (Proposed ADR-0003):**
    * *Proposal:* Transition the supervisor-worker IPC transport from a filesystem path rendezvous (`--socket-path`) to a connected anonymous Unix stream socket pair (`socketpair(AF_UNIX, SOCK_STREAM, 0)`) passed via file-descriptor inheritance.
    * *Worker Startup:* Spawns the worker child with an inherited file descriptor (e.g. `--fd <N>` or inherited standard input), instantiated in Python via `socket.fromfd()`.
    * *Descriptor Inheritance & Security:* Explicitly marks all other daemon descriptors `O_CLOEXEC` to prevent descriptor leakage to child processes.
    * *Lifecycle Management:* Completely eliminates filesystem path creation, directory permissions, bind collisions, stale socket files, unlink races, and TOCTOU vulnerabilities; kernel automatically reaps descriptors and `sockfs` inodes upon process termination.
    * *Protocol Compatibility:* 100% compliant with Internal Worker Protocol v1 (NDJSON framing up to 512 KiB and identical message schemas).
    * *Testing:* Simplifies unit and integration testing by using `UnixStream::pair()` directly without temporary directory management.
    * *Scope Clarification:* Socket-pair IPC removes filesystem-path races for that specific IPC channel, but process-level isolation, memory safety, and descriptor security remain separate concerns requiring dedicated OS sandboxing.
  * **Fail-Closed Protocol Invalidation & Write-Failure Protection:**
    * Cleanly distinguishes ordinary capability authorization denials (which return `CapabilityOutcome::Failure`, preserve the connection, and maintain provider invocation count == 0) from protocol-state violations.
    * In `WorkerSupervisor::execute_turn_with_id()`: drops reader and writer channels (`self.reader = None; self.writer = None`) upon detecting:
      * Inbound turn ID mismatches in `ProposeCapability` or `CompleteTurn`.
      * Incompatible protocol versions (`IncompatibleProtocolVersion`).
      * Protocol sequence violations (e.g., `HandshakeResponse` received during an active turn).
      * `CompleteTurn` validation errors.
      * Framing or deserialization errors.
      * **Write-side transmission failures:** write failures during `RequestTurn` or `CapabilityResult` immediately invalidate channels before returning `SupervisorError::Ipc(e)`.
    * Subsequent turns on a compromised, failed, or desynchronized connection fail closed immediately with `SupervisorError::ConnectionClosed`.
  * **Adversarial Security Test Suite (`m7_adversarial_security_tests.rs`):**
    * 29 comprehensive Rust integration tests across 7 distinct categories:
      * **Authorization & Scoping (AUTH):**
        * `AUTH-01`: Cross-caller context isolation in shared sessions (`test_cross_caller_turn_context_isolation`).
        * `AUTH-02`: Parameter type confusion across all 4 MVP capabilities (`test_parameter_type_confusion_across_all_capabilities`).
      * **Path & Filesystem Containment (PATH):**
        * `PATH-01`: Exact 255-byte path boundary (`test_path_length_exact_255_byte_boundary`).
        * `PATH-02`: Deeply nested directories (`test_deeply_nested_directory_containment`).
        * `PATH-03`: Cyclic symlink loop containment (`test_cyclic_symlink_loop_safe_rejection`).
        * `PATH-04`: Hard link outside sandbox known limitation assertion (`test_hard_link_known_limitation_demonstration`).
        * `PATH-05`: Non-regular special files fail-closed (`test_special_non_regular_file_fail_closed_rejection`).
      * **IPC Transport & Malformed Input (IPC):**
        * `IPC-01`: Truncated frame mid-stream EOF (`test_truncated_frame_mid_stream_eof`).
        * `IPC-02`: Fragment misparsing prevention after JSON syntax error (`test_fragment_misparsing_prevention_after_json_syntax_error`).
        * `IPC-03`: Deeply nested JSON recursion bomb (`test_deeply_nested_json_recursion_bomb`).
        * `IPC-04`: Whitespace and newline flooding (`test_whitespace_and_empty_newline_flooding`).
        * `IPC-05`: Protocol version type invariance across message types (`test_numeric_protocol_version_invariance_across_messages`).
      * **Message Integrity & Sequencing (MSG):**
        * `MSG-01`: Turn ID mismatch in `ProposeCapability` invalidates connection (`test_turn_id_mismatch_in_proposal_terminates_connection`).
        * `MSG-02`: Turn ID mismatch in `CompleteTurn` invalidates connection (`test_turn_id_mismatch_in_complete_turn_terminates_connection`).
        * `MSG-03`: Unexpected `HandshakeResponse` during active turn terminates connection (`test_unexpected_handshake_response_during_turn_terminates_connection`).
        * `MSG-04`: Unsolicited `ProposeCapability` before turn rejected (`test_unsolicited_capability_proposal_before_request_turn`).
        * `MSG-05`: Empty and whitespace correlation IDs rejected (`test_empty_or_whitespace_correlation_ids_rejected`).
      * **Worker Fault Containment (FLT):**
        * `FLT-01`: Worker crash during result delivery handled safely and invalidates connection (`test_worker_crash_during_result_delivery_handled_safely`).
        * `FLT-01b`: Worker disconnect during RequestTurn transmission invalidates connection (`test_write_failure_during_request_turn_invalidates_connection`).
        * `FLT-02`: Turn socket read timeout handled safely (`test_turn_socket_read_timeout_and_cleanup`).
        * `FLT-03`: Handshake connection timeout and child reap (`test_handshake_connection_timeout_and_child_reap`).
        * `FLT-04a`: Stale dead socket collision refuses startup without deletion, verified post-drop (`test_stale_socket_entry_refuses_startup_without_deletion`).
        * `FLT-04b`: Active listener socket collision refuses startup without deletion, verified post-drop and undisrupted (`test_active_listener_socket_refuses_startup_without_deletion`).
        * `FLT-04c`: Conflicting regular file refuses startup without deletion, verified post-drop (`test_conflicting_regular_file_refuses_startup_without_deletion`).
        * `FLT-04d`: Dangling symlink socket path refuses startup without deletion, verified post-drop (`test_dangling_symlink_refuses_startup_without_deletion`).
        * `FLT-04e`: Socket path replacement safeguard preserves replacement file on shutdown (`test_socket_path_replacement_safeguard`).
      * **Provider Failure Handling (PROV):**
        * `PROV-01`: Corrupted telemetry fixtures parsed without panics (`test_corrupted_telemetry_source_handling_via_fixtures`).
        * `PROV-02`: Unreadable file EACCES cleanly distinguished from policy denial (`test_unreadable_file_eacces_vs_policy_denial`).
      * **Regression Protection (REG):**
        * `REG-01`: Unified policy-before-provider execution matrix across all 4 MVP capabilities (`sys.cpu.read`, `sys.memory.read`, `proc.list`, `fs.file.read`) under anonymous, ungranted, invalid parameters, and unknown capabilities (`test_unified_policy_before_provider_matrix`).
  * **Python Worker Adversarial Tests (`worker/test_adversarial.py`):**
    * `PY-01`: Daemon framing error (> 512 KiB) causes worker to exit cleanly and close socket (`test_worker_terminates_and_closes_socket_on_daemon_framing_error`).
    * `PY-02`: Malformed JSON from daemon rejected gracefully during turn handling (`test_worker_rejects_malformed_daemon_json_during_turn`).
  * **Architectural Boundaries & Security Invariants Explicitly Maintained:**
    * *No OS-Level Worker Sandboxing Yet:* Acknowledged that Python worker remains an unprivileged child process without seccomp or Landlock filters; capability containment is enforced at the daemon's dispatcher and provider boundaries. The worker retains ambient OS authority of its UID.
    * *Hard-Link Invariant:* Re-verified that `openat2` prevents directory traversal but cannot prevent opening pre-existing hard links targeting external files; documented as an approved filesystem boundary constraint.
    * *Socket Ownership Trade-Offs & TOCTOU:* Safe non-destructive refusal preserves external listeners and prevents drop-deletion; residual TOCTOU replacement window and post-bind capture race acknowledged.
* **Verification Performed:**
  * Rust Test Suite: 182 tests passing (48 unit tests, 9 M4, 12 M5, 10 M6a, 13 M6b, 29 M6c, 29 M7, 15 policy, 6 supervisor, 11 protocol).
  * Python Test Suite: 23 tests passing (2 test_adversarial, 7 test_protocol, 14 test_worker).
  * Total Automated Tests: 205 passed across the workspace (100% pass rate).
  * Linter / Clippy: Clean run with `cargo clippy --workspace --all-targets --all-features -- -D warnings` (0 warnings, 0 errors).
  * Formatting & Style: Clean run with `rustfmt --check crates/aurora-ai/tests/m7_adversarial_security_tests.rs crates/aurora-ai/src/config.rs crates/aurora-ai/src/supervisor.rs` and `git diff --check`.
  * Workspace-Wide Formatting State: Fails on pre-existing legacy files from M1–M6b (`cargo fmt --all -- --check`), while all M7 files pass targeted checks.
* **Relevant Code:**
  * Supervisor: `crates/aurora-ai/src/supervisor.rs`
  * Configuration: `crates/aurora-ai/src/config.rs`
  * Rust Tests: `crates/aurora-ai/tests/m7_adversarial_security_tests.rs`
  * Python Tests: `worker/test_adversarial.py`
