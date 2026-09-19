# Aurora OS Internal Daemon ↔ Worker Protocol Specification (v1)

* **Status:** Draft / Specification
* **Target:** Milestone 1 (M1) Protocol Contract
* **Applies To:** `aurora-ai` Core Daemon (Rust) and AI Worker Process (Python)
* **Authoritative Context:** [ADR-001](decisions/0001-core-daemon-and-worker-runtime-architecture.md), [ADR-002](decisions/0002-capability-and-permission-architecture.md), and [Vertical Slice Prototype Design](vertical-slice-prototype-design.md)

---

## 1. Overview and Purpose

This specification defines the language-agnostic protocol contract governing communication between the **`aurora-ai` core daemon** and the **isolated AI worker process** across their private inter-process communication (IPC) channel.

Pursuant to **ADR-001**, the AI worker runs in an isolated child process decoupled behind a point-to-point private IPC boundary. This ensures that memory fragmentation, inference hangs, or model runtime crashes cannot destabilize the core system service.

Pursuant to **ADR-002**, the AI worker is treated as **untrusted software**. It possesses no ambient authority over protected operating system resources. It cannot execute system calls to manipulate host files or services directly, nor can it authorize capability usage. The protocol is strictly structured to allow the worker to propose capability invocations, which the deterministic daemon authorizes and executes.

---

## 2. Core Protocol Lifecycle

### 2.1 Connection and Handshake Phase (Milestone 2)
Upon launching the isolated worker process and establishing the private IPC stream connection, the daemon and worker perform an explicit protocol handshake to verify version compatibility and readiness before any requests are exchanged:

```text
aurora-ai Daemon                                           AI Worker Process
      │                                                           │
      │ 1. Handshake(protocol_version, daemon_version)            │
      ├──────────────────────────────────────────────────────────>│
      │                                                           │ [Validate protocol version]
      │ 2. HandshakeResponse(protocol_version, worker_version,    │
      │                       status: "ready" | "incompatible")   │
      │<──────────────────────────────────────────────────────────┤
      │                                                           │
```

If the protocol version does not match, or the worker reports `"incompatible_version"`, the daemon immediately rejects the connection, tears down the worker process, and unlinks the IPC socket.

### 2.2 Turn Execution Lifecycle
Once the handshake is confirmed, reasoning turns follow a deterministic four-phase message exchange:

```text
aurora-ai Daemon                                           AI Worker Process
      │                                                           │
      │ 1. RequestTurn(turn_id, prompt, capabilities)             │
      ├──────────────────────────────────────────────────────────>│
      │                                                           │
      │                                                           │ [Reasoning / Planning]
      │                                                           │ (Untrusted)
      │                                                           │
      │ 2. ProposeCapability(turn_id, call_id, name, parameters)  │
      │<──────────────────────────────────────────────────────────┤
      │                                                           │
[Deterministic Policy Evaluation                                  │
 & Capability Execution]                                          │
      │                                                           │
      │ 3. CapabilityResult(turn_id, call_id, outcome)            │
      ├──────────────────────────────────────────────────────────>│
      │                                                           │
      │                                                           │ [Observation Synthesis]
      │                                                           │ (Untrusted)
      │                                                           │
      │ 4. CompleteTurn(turn_id, status, response_text)           │
      │<──────────────────────────────────────────────────────────┤
      │                                                           │
```

### Phase Definitions:
1. **`Handshake` / `HandshakeResponse` (Connection Setup):** Daemon sends daemon version and protocol version; worker acknowledges and asserts readiness or incompatibility.
2. **`RequestTurn` (Daemon $\rightarrow$ Worker):** The daemon initiates a turn by passing the caller's request along with declarative schemas of the capabilities that the caller is potentially eligible to use.
3. **`ProposeCapability` (Worker $\rightarrow$ Daemon):** The worker evaluates the input and emits an intent proposal requesting execution of a specific, narrow capability with structured arguments.
4. **`CapabilityResult` (Daemon $\rightarrow$ Worker):** The daemon deterministically evaluates policy, executes the authorized capability (or records a policy denial/error), and delivers the sanitized observation back to the worker.
5. **`CompleteTurn` (Worker $\rightarrow$ Daemon):** The worker synthesizes the observation into a finalized natural language or structured completion for the calling application.

---

## 3. Message Type Definitions

### 3.1 `Handshake` (Daemon $\rightarrow$ Worker)
Initiated by the daemon immediately upon connecting to the private Unix domain socket.

| Field | Type | Description |
| :--- | :--- | :--- |
| `type` | String (`"handshake"`) | Discriminator tag. |
| `protocol_version` | Unsigned Integer (e.g. `1`) | Protocol contract version offered by daemon. |
| `daemon_version` | String | Daemon service version (e.g. `"0.1.0"`). |

### 3.2 `HandshakeResponse` (Worker $\rightarrow$ Daemon)
Returned by the worker to confirm protocol compatibility and readiness.

| Field | Type | Description |
| :--- | :--- | :--- |
| `type` | String (`"handshake_response"`) | Discriminator tag. |
| `protocol_version` | Unsigned Integer (e.g. `1`) | Protocol contract version acknowledged by worker. |
| `worker_version` | String | Worker runtime version (e.g. `"0.1.0"`). |
| `status` | String (`"ready"` \| `"incompatible_version"`) | Handshake outcome status. |

### 3.3 `RequestTurn` (Daemon $\rightarrow$ Worker)
Initiates an inference and reasoning cycle.

| Field | Type | Description |
| :--- | :--- | :--- |
| `type` | String (`"request_turn"`) | Discriminator tag. |
| `protocol_version` | Unsigned Integer (e.g. `1`) | Protocol contract version. |
| `turn_id` | String (Non-empty) | Unique identifier for this turn. |
| `prompt` | String | User or calling application request string. |
| `available_capabilities` | Array of `CapabilitySchema` | List of capabilities available for proposal during this turn. |

Each `CapabilitySchema` contains:
* `name`: Canonical capability identifier (e.g. `sys.cpu.read`, `fs.file.read`).
* `description`: Human-readable purpose description.
* `parameters_schema`: Structured schema defining accepted arguments.

### 3.4 `ProposeCapability` (Worker $\rightarrow$ Daemon)
Proposes that a capability be invoked to advance the reasoning plan.

| Field | Type | Description |
| :--- | :--- | :--- |
| `type` | String (`"propose_capability"`) | Discriminator tag. |
| `protocol_version` | Unsigned Integer (`1`) | Protocol contract version. |
| `turn_id` | String (Non-empty) | Correlated turn identifier. |
| `call_id` | String (Non-empty) | Unique correlation identifier for this capability proposal. |
| `capability_name` | String (Canonical) | Name of capability requested (e.g., `sys.cpu.read`). |
| `parameters` | Structured Object (Key-Value Map) | Validated parameters for the capability. |

### 3.5 `CapabilityResult` (Daemon $\rightarrow$ Worker)
Delivers observation data or a failure descriptor back to the worker.

| Field | Type | Description |
| :--- | :--- | :--- |
| `type` | String (`"capability_result"`) | Discriminator tag. |
| `protocol_version` | Unsigned Integer (`1`) | Protocol contract version. |
| `turn_id` | String (Non-empty) | Correlated turn identifier. |
| `call_id` | String (Non-empty) | Correlated call identifier matching the proposal. |
| `outcome` | `CapabilityOutcome` | Result status and data/error. |

`CapabilityOutcome` is a tagged union:
* **Success:** `{ "status": "success", "data": <Structured Observation> }`
* **Failure:** `{ "status": "failure", "error": { "code": "<CODE>", "message": "<TEXT>" } }`

### 3.6 `CompleteTurn` (Worker $\rightarrow$ Daemon)
Signals completion of turn synthesis.

| Field | Type | Description |
| :--- | :--- | :--- |
| `type` | String (`"complete_turn"`) | Discriminator tag. |
| `protocol_version` | Unsigned Integer (`1`) | Protocol contract version. |
| `turn_id` | String (Non-empty) | Correlated turn identifier. |
| `status` | String (`"success"` \| `"error"`) | Turn outcome status. |
| `response_text` | String | Final formatted completion. |

---

## 4. Security Principles and Guardrails

1. **Untrusted Worker Input:**
   * All bytes received from the worker socket are treated as completely untrusted data.
   * Deserialization errors, unexpected message types, or schema violations cause immediate turn termination without execution.
2. **Structural Inability to Authorize:**
   * The worker-to-daemon protocol grammar contains **zero messages for policy modification or privilege escalation**.
   * The worker cannot emit grant tokens, alter ACLs, or bypass the policy engine.
3. **Strict Directionality:**
   * Incoming messages on the worker-to-daemon stream are restricted strictly to `WorkerToDaemonMessage` (`HandshakeResponse`, `ProposeCapability`, and `CompleteTurn`).
   * If a worker transmits a `Handshake`, `RequestTurn`, or `CapabilityResult` message, deserialization immediately fails.
4. **Explicit Capability Identification:**
   * Capability names must conform to canonical naming rules: lower-case alphanumeric characters with segmenting dots (e.g., `sys.cpu.read`).
   * Wildcards, arbitrary command strings, shell invocations, or empty capability names are rejected at deserialization.
5. **Correlation Integrity:**
   * Every capability proposal and completion must reference an active, daemon-tracked `turn_id`. Unsolicited proposals are discarded.
6. **Protocol Versioning:**
   * Every message includes `protocol_version`. Discrepancies between daemon and worker protocol versions are detected and rejected at handshake.

---

## 5. Serialization and Replaceability

* **Language Agnosticism:** The protocol contract is conceptually independent of programming languages and wire encodings.
* **Provisional Serialization:** For **Milestones 1 and 2**, message structures are validated using newline-delimited JSON (NDJSON) encoding over private stream channels. This allows rapid verification across Rust and Python without third-party binary serialization dependencies.
* **Worker Replaceability:** Pursuant to ADR-001 Section 3.4, the Python worker process can be replaced in future releases by a native Rust or C++ inference engine (e.g., ONNX, Candle, or llama.cpp) by adhering to this identical protocol contract. The daemon requires no architectural changes or client-facing alterations when the worker runtime changes.
