# Vertical Slice Prototype Design: Core Daemon, Worker Boundary, and Capability Model

* **Status:** Proposed Architecture Proposal
* **Date:** 2026-09-19
* **Author:** Antigravity (AI Systems Architecture)
* **Target:** Minimum Viable Prototype validating [ADR-001](decisions/0001-core-daemon-and-worker-runtime-architecture.md) and [ADR-002](decisions/0002-capability-and-permission-architecture.md)

---

## 1. Goal and Purpose

This document designs the smallest possible end-to-end vertical slice for Aurora OS to prove that the architectural decisions made in **ADR-001** (Core Daemon, Worker Runtime, Two-Tier IPC) and **ADR-002** (Deterministic Capability & Permission Architecture) work together in a realistic execution environment.

The prototype proves:
1. A client can submit an intent to the `aurora-ai` daemon over public desktop IPC (**D-Bus**).
2. The core daemon (**Rust**) can supervise and communicate with an isolated worker (**Python stub**) over private IPC (**Unix domain socket**).
3. The untrusted worker can propose capability invocations without possessing ambient execution authority over protected resources.
4. The core daemon deterministically authorizes or denies capability requests based on caller identity, policy rules, and parameter scopes.
5. The core daemon executes authorized capability providers and injects observation results back into the worker.
6. The system fails closed when requests are unauthorized, malformed, or when the worker process crashes.

> **Crucial Simplification:** The prototype uses a **deterministic Python stub worker** rather than a live neural model. The goal is to validate systems engineering, IPC boundaries, policy enforcement, and fault containment without premature hardware or model runtime dependencies.

---

## 2. End-to-End Request Flow

The diagram below traces a single complete interaction lifecycle, highlighting the strict separation between AI reasoning proposals and deterministic system enforcement.

```text
CLI Client (User)          aurora-ai Daemon (Rust)             Python Stub Worker             Capability Provider
       │                              │                                │                               │
       │ 1. D-Bus Method Call         │                                │                               │
       ├─────────────────────────────>│ [D-Bus Ingress]                │                               │
       │                              │  * Authenticate caller identity│                               │
       │                              │    via IPC/OS credentials      │                               │
       │                              │                                │                               │
       │                              │ 2. Forward Prompt              │                               │
       │                              ├───────────────────────────────>│ [Simulated AI Reasoning]      │
       │                              │    (Unix Domain Socket)        │  * Determines intent          │
       │                              │                                │  * Selects capability         │
       │                              │                                │  * Formulates arguments       │
       │                              │ 3. Propose Capability          │                               │
       │                              │<───────────────────────────────┤                               │
       │                              │                                                                │
       │                              │ 4. [Deterministic Policy Gate]                                 │
       │                              │    a. Validate message schema & types                          │
       │                              │    b. Check caller identity                                    │
       │                              │    c. Check capability registry                                │
       │                              │    d. Enforce parameter scope (e.g. sandbox path)               │
       │                              │    e. Evaluate ALLOW / DENY rule                               │
       │                              │                                                                │
       │                              │ [If ALLOWED]                                                   │
       │                              │ 5. Execute Capability                                          │
       │                              ├───────────────────────────────────────────────────────────────>│
       │                              │                                                                │ (Executes provider;
       │                              │ 6. Return Observation Result                                   │  e.g., reads system
       │                              │<───────────────────────────────────────────────────────────────┤  metrics or file)
       │                              │                                                                │
       │                              │ 7. Inject Observation Context  │                               │
       │                              ├───────────────────────────────>│ [Simulated Synthesis]        │
       │                              │                                │  * Formulates final answer    │
       │                              │ 8. Final Formatted Response    │                               │
       │                              │<───────────────────────────────┤                               │
       │                              │                                                                │
       │ 9. D-Bus Reply               │                                                                │
       │<─────────────────────────────┤                                                                │
```

### Trace Narrative:
1. **Invocation:** The CLI test client sends a natural-language or structured query (e.g., `"check cpu"`) to `aurora-ai` over the D-Bus session bus.
2. **Caller Authentication:** The daemon establishes the identity of the calling principal using identity information available through the IPC mechanism and operating system (such as connection credentials provided by the message bus).
3. **Dispatch to Worker:** The daemon creates a request envelope containing the prompt and available capability schemas and sends it to the Python stub worker across the private Unix domain socket.
4. **Intent Formulation (Untrusted):** The Python stub worker maps the input to a simulated plan, proposing a capability execution: `RequestCapability { name: "sys.cpu.read", args: {} }`.
5. **Deterministic Policy Evaluation (Enforcement Point):** The daemon intercepts the proposal before any system action occurs. It validates the capability name against its registry, confirms the caller is permitted to request CPU metrics, and issues an `ALLOW` decision.
6. **Capability Execution:** The daemon's capability provider executes the requested observation. *(Note: in the prototype, this is implemented via direct reads of Linux telemetry files, but this is a prototype implementation choice rather than a permanent architectural commitment).*
7. **Observation Delivery:** The daemon packages the sanitized telemetry into an observation payload and sends it back to the worker over the socket.
8. **Synthesis:** The stub worker receives the observation and formats a human-readable response (e.g., `"CPU utilization is 12%"`).
9. **Reply:** The daemon delivers the finalized response to the CLI client over D-Bus.

---

## 3. Minimal Components

To avoid accidental bloat, the vertical slice consists of exactly three runtime components:

```text
┌────────────────────────────────────────────────────────┐
│ 1. CLI Test Client (CLI executable)                    │
└───────────────────────────┬────────────────────────────┘
                            │ Public D-Bus IPC
                            ▼
┌────────────────────────────────────────────────────────┐
│ 2. aurora-ai Core Daemon (Rust executable)             │
│    ├── D-Bus Ingress Adapter                           │
│    ├── Worker Lifecycle Supervisor & Private IPC Host  │
│    ├── Deterministic Policy Engine                     │
│    └── Capability Dispatcher & Providers               │
└───────────────────────────┬────────────────────────────┘
                            │ Private Unix Domain Socket
                            ▼
┌────────────────────────────────────────────────────────┐
│ 3. AI Worker Stub (Python script)                      │
│    ├── Private IPC Client                              │
│    └── Deterministic Rule/Intent Engine                │
└────────────────────────────────────────────────────────┘
```

### Component Details:

| Component | Responsibility & Why It Exists | What It Communicates With | What Authority It Possesses | What It Explicitly Does NOT Have Authority To Do |
| :--- | :--- | :--- | :--- | :--- |
| **CLI Test Client** | Minimal user-facing tool to issue queries, inspect responses, and test error codes. | `aurora-ai` over D-Bus. | Ambient permissions of the invoking user. | Cannot bypass `aurora-ai` or directly trigger capability providers. |
| **`aurora-ai` Core Daemon (Rust)** | Central orchestrator, supervisor, and policy enforcement point for AI-mediated capabilities. | CLI (via D-Bus), Worker (via Unix socket), Linux system resources. | Host daemon authority to query telemetry and read designated demo sandbox filesystem paths. | Does NOT have authority to execute arbitrary user commands or grant un-sandboxed root access. |
| **AI Worker Stub (Python)** | Simulates model reasoning by mapping prompts to capability proposals and observations to replies. | `aurora-ai` daemon over private Unix domain socket only. | **Unprivileged and isolated.** Possesses only the ordinary process resources required to execute, communicate with the daemon over its private socket, and perform its own computation. | Has **no ambient authority** to access Aurora-protected resources, invoke capability providers, communicate with desktop apps, or modify policy tables. |

---

## 4. Stub Worker Protocol and Behavior

The stub worker behaves architecturally as an **untrusted AI system**. It communicates with the daemon using a minimal, message-oriented protocol over the private Unix domain socket.

### Protocol Message Lifecycle:
```text
Daemon                                  Worker Stub
  │                                          │
  │─── RequestTurn(id, prompt) ─────────────>│
  │                                          │ [Simulate intent parsing]
  │<── ProposeCapability(id, call_id, name, args) ───│
  │                                          │
  │ [Policy Check & Execution]               │
  │─── CapabilityResult(id, call_id, data) ──>│
  │                                          │ [Simulate response synthesis]
  │<── CompleteTurn(id, text_response) ──────│
```

### Untrusted Worker Guardrails:
1. **No Direct Execution:** The worker cannot execute capabilities. It only emits `ProposeCapability`.
2. **No Policy Ingestion:** The worker cannot emit policy directives or alter permissions.
3. **Turn Correlation:** Every proposal must reference an active `id` (turn ID) tracked by the daemon. Unsolicited or out-of-order capability proposals are rejected.
4. **Deterministic Simulation Rules:** The stub worker maps test inputs deterministically:
   * `"cpu"` $\longrightarrow$ proposes `sys.cpu.read`
   * `"memory"` $\longrightarrow$ proposes `sys.memory.read`
   * `"processes"` $\longrightarrow$ proposes `proc.list` with limit 10
   * `"read test.txt"` $\longrightarrow$ proposes `fs.file.read` with `path="test.txt"`
   * `"escape"` $\longrightarrow$ proposes `fs.file.read` with `path="/etc/passwd"` (for security rejection testing)
   * `"prefix_mismatch"` $\longrightarrow$ proposes `fs.file.read` with `path="../demo-secret/secret.txt"` (for component containment testing)
   * `"fake"` $\longrightarrow$ proposes `fake.admin.tool` (for unknown capability testing)
   * `"malformed"` $\longrightarrow$ sends invalid syntax (for parser error testing)

---

## 5. Capability Execution Specifications

> **Note on Implementation Mechanisms vs. Architecture:** The telemetry sources mentioned below (such as querying `/proc/stat` for CPU, `/proc/meminfo` for memory, or scanning `/proc` for processes) represent lightweight prototype implementation choices suitable for a local Linux development environment. They do not constitute permanent architectural commitments for how Aurora OS will retrieve system metrics in future production releases.

The vertical slice implements exactly four narrow, general primitives:

### 1. `sys.cpu.read`
* **Input Schema:** None (empty object `{}`).
* **Output Schema:** `{ "user_percent": float, "system_percent": float, "idle_percent": float }`
* **Scope:** Host system-wide CPU metrics.
* **Side Effects:** None (pure read-only observation).
* **Sensitivity:** Low (Tier 0 observation).
* **Authorization Requirements:** Permitted for authenticated local user sessions.

### 2. `sys.memory.read`
* **Input Schema:** None (empty object `{}`).
* **Output Schema:** `{ "total_mb": integer, "used_mb": integer, "free_mb": integer, "available_mb": integer }`
* **Scope:** Host system-wide memory metrics.
* **Side Effects:** None (pure read-only observation).
* **Sensitivity:** Low (Tier 0 observation).
* **Authorization Requirements:** Permitted for authenticated local user sessions.

### 3. `proc.list`
* **Input Schema:** `{ "limit": integer }` (optional, default 10, maximum 50).
* **Output Schema:** `[ { "pid": integer, "name": string, "cpu_percent": float, "memory_mb": integer } ]`
* **Scope:** Current running processes in host namespace.
* **Side Effects:** None (pure read-only observation).
* **Sensitivity:** Medium (exposes process names and PIDs).
* **Authorization Requirements:** Permitted for authenticated local user sessions; enforced parameter limit $\le 50$.

### 4. `fs.file.read`
* **Input Schema:** `{ "path": string }`
* **Output Schema:** `{ "content": string, "size_bytes": integer }`
* **Scope:** Strictly confined to a dedicated demonstration directory (e.g. `<workspace>/demo_sandbox/`).
* **Side Effects:** None (read-only).
* **Sensitivity:** High (file content retrieval).
* **Authorization Requirements:**
  * Path must be strictly non-empty.
  * **Component-Aware Containment:** Filesystem containment must be path-component aware and must **not** rely on naive textual string prefix matching. For example, a sandbox rooted at `/demo` must never treat `/demo-secret` or `/demo/../demo-secret` as being inside the sandbox. Path validation must resolve path components cleanly and verify that the target canonically resides strictly inside the designated directory hierarchy.
  * Any traversal attempts (`..`), symlinks escaping the sandbox, or absolute paths outside the sandbox are strictly denied.
  * *(Architectural Note: This prototype containment is a simplified demonstration boundary. Production-grade filesystem delegation—such as user-selected file grants, file descriptor passing, or XDG desktop portals—is explicitly deferred and left open).*

---

## 6. Minimal Deterministic Policy Model

For this vertical slice, the policy engine is a lightweight, deterministic in-memory evaluator embedded within the Rust daemon.

### Policy Structure:
```text
Input Tuple: (CallerIdentity, CapabilityName, Arguments)
                     │
                     ▼
          1. Validate Parameter Types
                     │
                     ▼
          2. Check Capability Whitelist
                     │
                     ▼
          3. Evaluate Scope Predicates (Component-Aware Path Confinement)
                     │
                     ▼
             Decision: ALLOW or DENY
```

1. **Caller Identity:** The daemon must establish the identity of the calling principal using identity information available through the IPC mechanism and operating system. For the prototype, standard unprivileged user sessions matching the daemon's user are recognized as authenticated.
2. **Capability Whitelist:** Static registry in code recognizing only the four defined capabilities:
   * `sys.cpu.read` $\rightarrow$ `ALLOW`
   * `sys.memory.read` $\rightarrow$ `ALLOW`
   * `proc.list` $\rightarrow$ `ALLOW` if `limit <= 50` else `DENY`
   * `fs.file.read` $\rightarrow$ `ALLOW` if `is_component_sandboxed(path)` else `DENY`
3. **Scope Checking (Component-Aware Path Confinement):**
   Naive string prefix comparison (e.g., `path.starts_with("/demo")`) is strictly forbidden because `/demo-secret` shares the string prefix `/demo` without being inside the directory component.
   
   *(Illustrative prototype implementation note in Rust; not an architectural mandate for production policy enforcement):*
   ```rust
   // Prototype implementation note:
   let canonical_sandbox = std::fs::canonicalize(&sandbox_root)?;
   let target_path = sandbox_root.join(args.path);
   let canonical_target = std::fs::canonicalize(&target_path)?;
   
   // Verify that canonical_target has canonical_sandbox as a strict path prefix
   // using path components, not raw string prefixes:
   if !canonical_target.starts_with(&canonical_sandbox) {
       return Decision::Deny("Path escapes demo sandbox");
   }
   ```
4. **Default-Deny Rule:** Any capability not in the whitelist or any parameter failing scope checks returns `DENY`.
5. **Fail-Closed Behavior:** Any IO error during path canonicalization (e.g. missing file or broken link) immediately results in `DENY`.

---

## 7. Security Boundaries

```text
[ User Session Boundary ]
       CLI Client
           │
===========│=== Public IPC Boundary (D-Bus Session Bus) =========================
           │   * Authenticate caller identity via IPC/OS credentials
           v
+-------------------------------------------------------------------------------+
| aurora-ai Daemon (Rust)                                                       |
|                                                                               |
|   [ Ingress ] ──> [ Orchestrator ] ──> [ Deterministic Policy Engine ]        |
|                          │                     │                              |
|                          │ Propose Capability  │ Checks Whitelist, Scopes     |
|                          │ Intent              │ (Default-Deny)               |
|                          v                     │                              |
|                   [ Socket Bridge ]            │                              |
|                          │                     v                              |
+==========================│============== [ Capability Dispatcher ] ===========+
  Private IPC Boundary     │                     │
  (Unix Domain Socket)     │                     │ System Operations
                           v                     v
                +--------------------+   +------------------------------------+
                | AI Worker Stub     |   | Capability Providers               |
                | (Python)           |   |                                    |
                |                    |   | Prototype providers:               |
                | * Unprivileged     |   | * System telemetry                 |
                |   & isolated       |   | * Process metrics                  |
                | * Untrusted inputs |   | * Sandboxed VFS read               |
                +--------------------+   +------------------------------------+
                                                           │
                                                           v
                                                 Linux Kernel Primitives
```

### Boundary Guarantees:
1. **CLI $\rightarrow$ Daemon:** The daemon establishes the identity of the calling principal using identity information available through the IPC mechanism and operating system.
2. **Daemon $\rightarrow$ Worker:** Point-to-point private stream socket. The worker process has no socket connection to D-Bus and cannot communicate with desktop applications directly.
3. **Untrusted Input Boundary:** All bytes received from the worker socket are treated as untrusted data. Deserialization errors or unexpected fields immediately trigger turn termination.
4. **Enforcement Separation:** Capability execution code resides inside or is mediated by the daemon. While the worker process may execute ordinary user-space instructions and system calls necessary for its own execution, it possesses **no ambient authority** to access Aurora-protected system resources, inspect arbitrary files, or execute privileged operations directly.

---

## 8. Failure and Safety Matrix

| Failure Event | Trigger Condition | System Behavior & Failure Handling | Security Outcome |
| :--- | :--- | :--- | :--- |
| **Worker Process Crash** | Python worker killed (`SIGKILL` or uncaught exception). | Daemon detects EOF / socket hangup; drops pending turns; returns `ServiceUnavailable` to CLI client; logs incident. | **Safe:** OS and daemon remain running; no leaked state. |
| **Malformed Worker Message** | Worker sends invalid JSON or bad binary frame. | Daemon parser fails during schema deserialization; turn is rejected immediately; error returned to CLI. | **Safe:** No memory corruption or unexpected state. |
| **Unknown Capability** | Worker proposes `"fake.admin.tool"`. | Daemon policy engine checks capability registry; name not found; returns `PermissionDenied` to worker. | **Fail-Closed:** Action blocked. |
| **Invalid Parameters** | Worker proposes `proc.list` with `limit = -5` or `limit = 9999`. | Parameter validation fails schema constraints; returns `InvalidParameters`. | **Fail-Closed:** Action blocked. |
| **Path Traversal Escape** | Worker proposes `fs.file.read` with `../../etc/shadow`. | Canonicalization check fails component containment; returns `PermissionDenied`. | **Fail-Closed:** Arbitrary file read prevented. |
| **Path Prefix Mismatch** | Worker proposes `fs.file.read` with `../demo-secret/test.txt`. | Component-aware check detects path component divergence; returns `PermissionDenied`. | **Fail-Closed:** Sibling directory access prevented. |
| **Provider IO Failure** | Target file does not exist in demo sandbox. | Capability provider returns `NotFound`; error packaged into observation context for worker. | **Safe:** Error handled gracefully. |
| **Policy Engine Error** | Missing configuration or evaluation fault. | Any evaluation anomaly defaults to `Decision::Deny`. | **Fail-Closed:** No default allow. |
| **Client Disconnect** | CLI killed during execution. | Daemon catches D-Bus client disconnect; cancels active turn; resets worker context. | **Safe:** No orphaned background tasks. |

---

## 9. Test Scenarios

The vertical slice is validated by an automated test suite exercising both nominal and adversarial execution paths:

```text
[ Test Suite: Vertical Slice Validation ]
  ├── 1. Positive Tests (Nominal Execution)
  │    ├── Test 1.1: Query "cpu"       ──> sys.cpu.read       ──> ALLOWED (Returns CPU %)
  │    ├── Test 1.2: Query "memory"    ──> sys.memory.read    ──> ALLOWED (Returns Mem MB)
  │    ├── Test 1.3: Query "processes" ──> proc.list          ──> ALLOWED (Returns top PIDs)
  │    └── Test 1.4: Query "sandbox"   ──> fs.file.read(ok)   ──> ALLOWED (Returns file content)
  │
  └── 2. Negative & Security Tests (Fail-Closed Enforcement)
       ├── Test 2.1: Query "escape"    ──> fs.file.read(/etc) ──> DENIED (Path traversal outside sandbox)
       ├── Test 2.2: Query "prefix"    ──> fs.file.read(sibling) ──> DENIED (Component mismatch e.g. /demo-secret)
       ├── Test 2.3: Query "fake"      ──> fake.admin.tool    ──> DENIED (Unknown capability)
       ├── Test 2.4: Query "malformed" ──> Garbage syntax     ──> REJECTED (Deserialization failure)
       ├── Test 2.5: Self-Grant Attack ──> Worker grants perm ──> REJECTED (Unrecognized protocol message)
       └── Test 2.6: Worker Crash      ──> SIGKILL worker     ──> RECOVERED (Daemon survives, reports error)
```

### What Each Test Proves:
* **Test 1.1–1.3:** Proves capability registration, worker proposal formulation, policy pass, provider execution, and observation round-trip for system telemetry.
* **Test 1.4:** Proves scoped read-only filesystem capability execution inside a controlled directory.
* **Test 2.1:** Proves deterministic path confinement and protection against directory traversal attacks (`../`).
* **Test 2.2:** Proves that filesystem containment is component-aware and does not rely on naive string prefix matching.
* **Test 2.3:** Proves default-deny capability registry enforcement.
* **Test 2.4:** Proves daemon robustness against malformed or hostile worker output.
* **Test 2.5:** Proves the worker has no mechanism to alter policy or grant permissions.
* **Test 2.6:** Proves process boundary fault isolation (ADR-001 Invariant: worker failure does not kill daemon or desktop).

---

## 10. Deliberately Deferred (Out of Scope for this Slice)

To ensure this prototype remains small and executable, the following capabilities and mechanisms are **explicitly out of scope**:

1. **Real Model Inference:** No PyTorch, llama.cpp, Transformers, or GPU acceleration.
2. **Production Sandboxing Technologies:** No custom seccomp-bpf filters, user namespaces, or Landlock integration yet (the stub runs as a standard child process).
3. **Polkit & Administrative Privileges:** No elevated system administration tasks.
4. **Desktop GUI Consent Modals:** No Wayland layer-shell dialogs or XDG Desktop Portal dialogues.
5. **Persistent Policy Storage:** No `/etc/aurora/policy.d/` parser; policy is defined in in-memory structures.
6. **Multi-Step Plan Batching:** No complex multi-action transactions or plan rollbacks.
7. **Advanced Filesystem Delegation:** No file descriptor passing or document portals.
8. **Autonomous Daemon Agents:** No timers, background cron tasks, or unsupervised actions.

---

## 11. Implementation Milestones

Development is structured into 8 sequential milestones organized to **prove the security boundary as early as possible** before broadening the capability set:

```text
M1: Repository Skeleton & IPC Protocol Contracts
    └── Define workspace layout, Python stub location, and shared protocol message schemas.

M2: Core Daemon Lifecycle & Worker Startup
    └── Core daemon starts, spawns Python stub worker as child process, establishes private socket handshake.

M3: Minimal Policy Engine
    └── Implement in-memory default-deny evaluator, capability registry, and caller identity extraction.

M4: One Capability Integrated Through the Policy Boundary
    └── Implement single primitive (`sys.cpu.read`); verify policy checks, authorizes, and executes it in isolation.

M5: Complete End-to-End Request Flow
    └── Connect full lifecycle for one capability: CLI -> D-Bus -> daemon -> worker proposal -> policy authorization -> execution -> worker synthesis -> CLI reply.

M6: Remaining MVP Capabilities
    └── Implement sys.memory.read, proc.list, and component-aware sandboxed fs.file.read.

M7: Security, Rejection, and Fault Containment Tests
    └── Execute adversarial test suite: directory traversal, prefix mismatch (/demo-secret), unknown capability, malformed frames, worker crash.

M8: Verification and Documentation Review
    └── Run automated test harness, verify all test scenarios pass, and document architectural findings.
```

> **Key Milestone Principle:** Prove one complete `capability -> authorization -> execution` path (M4 & M5) before implementing the entire capability set (M6).

---

## 12. Architectural Risks and Guardrails

| Risk Area | Specific Threat to Aurora OS Architecture | Architectural Guardrail in this Slice |
| :--- | :--- | :--- |
| **Monolithic Super-Daemon** | `aurora-ai` expands into an unwieldy system service doing custom device control and reimplementing OS features. | **Strict Provider Separation:** Capability providers are modeled as small, modular functions that invoke standard Linux userspace APIs, keeping the daemon core minimal. |
| **Python / Framework Lock-In** | The internal IPC protocol accidentally bakes in Python pickle, Python object semantics, or specific ML library data structures. | **Language-Agnostic Protocol:** Communication over the private Unix domain socket uses neutral JSON/binary framing. The worker can later be replaced with C++ or Rust without daemon changes. |
| **Model Runtime Coupling** | Designing the worker protocol around specific LLM prompt formats or vendor APIs. | **Abstract Intent Protocol:** The protocol exchanges generic intent proposals (`ProposeCapability`) and observations, completely decoupled from model prompt templates. |
| **Worker Ambient Privilege Creep** | Granting the worker process direct filesystem or network access during testing for convenience. | **Unprivileged Isolation:** The worker is unprivileged and isolated, with no ambient authority to access Aurora-protected resources or perform privileged system operations. |
| **Overly Broad Capabilities** | Creating dangerous "catch-all" capabilities such as `sys.shell.execute` or `fs.write_raw`. | **Narrow Primitives Only:** Primitives are strictly typed, bounded, and composable (e.g., `proc.list` rather than `proc.inspect_everything`). |
| **Reinventing Linux Security** | Building a massive custom authorization framework instead of integrating with Linux primitives. | **Pragmatic In-Memory Policy:** The prototype uses standard identity checks, preparing for future integration with Polkit and portals rather than inventing a redundant permissions language. |
