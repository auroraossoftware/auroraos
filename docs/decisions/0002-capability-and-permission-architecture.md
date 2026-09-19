# ADR-002: Capability and Permission Architecture

* **Status:** Proposed
* **Date:** 2026-09-19
* **Deciders:** Aurora OS Architecture Team

---

## 1. Problem
Aurora OS integrates artificial intelligence as a first-class system service. However, probabilistic AI models cannot be trusted with ambient operating-system authority. If an AI worker process or calling application were able to invoke system operations directly, the system would be vulnerable to prompt injection attacks, confused-deputy privilege escalation, model hallucinations, and application abuse.

Aurora OS must establish:
1. The architectural boundary separating AI reasoning from deterministic system authority.
2. The role of `aurora-ai` in mediating capabilities without superseding the Linux security model.
3. The definition and structure of system capabilities.
4. The authorization model governing capability invocation.
5. The boundaries of AI-assisted orchestration.
6. The failure containment principles ensuring OS resilience.
7. The minimal capability boundary required for the MVP.

## 2. Context
As established in [`docs/architecture-variants/architecture-v1`](../architecture-variants/architecture-v1) and [ADR-001](0001-core-daemon-and-worker-runtime-architecture.md):
* **Linux First (Principle 3.1):** Aurora builds upon standard Linux. System security mechanisms provided by the Linux kernel and userspace should be leveraged rather than reinvented.
* **AI Is a Service, Not the OS (Principle 3.2):** Operating system functionality must not depend on the availability or correctness of the AI subsystem. AI failure must never cause operating system failure.
* **Worker Process Isolation (ADR-001 & Section 11):** The model inference worker is isolated from the core system daemon across an IPC process boundary.
* **Separation of Suggestion and Action (Section 12):** Generating a suggestion must be architecturally separated from performing an action.
* **Untrusted Content & Prompt Injection (Section 20 & 33):** Model outputs and external content must be treated as untrusted data. AI output is never equivalent to authorization.

## 3. Decision

### 3.1 Core Security Boundary & Untrusted Worker
The AI subsystem strictly separates three distinct concerns:
1. **AI Reasoning & Orchestration:** Evaluating user intent, planning potential steps, and proposing actions.
2. **Authorization:** Deterministically deciding whether a proposed action is permitted.
3. **Capability Execution:** Carrying out the authorized action against system resources.

The AI worker is treated as **untrusted software**. It may reason about requests and propose capability invocations, but it must possess **zero ambient authority** over the operating system.

The architectural rule governing this boundary is:

> **AI can reason about what it wants to do; deterministic system software decides what it is actually allowed to do.**

This does not imply that the worker process is physically incapable of invoking Linux system calls. Rather, the architectural requirement is that the AI worker runs in an unprivileged, isolated environment such that its system calls do not grant it meaningful authority over protected system resources. It cannot access host devices, user files, or privileged services directly.

### 3.2 Role of `aurora-ai`
`aurora-ai` is **not** the universal or sole security authority of Aurora OS.

Instead, `aurora-ai` is defined as:

> **The policy enforcement point for AI-mediated capabilities.**

Aurora OS continues to rely on Linux's existing security model (kernel discretionary/mandatory access controls, user privileges, systemd sandboxing, desktop portals, Polkit) where appropriate. `aurora-ai` coordinates AI-mediated operations and enforces policy for requests routed through the AI service; it does not replace or bypass the broader operating system security architecture.

### 3.3 Capability Model
Capabilities in Aurora OS are **narrow, typed, declarative abilities** that the AI subsystem may request. 

Capabilities must:
* **Be narrow:** Represent single, well-defined operations rather than sweeping access.
* **Have typed parameters:** Accept structured, validated arguments rather than arbitrary shell strings or unbounded payloads.
* **Have explicit scope:** Target specified resources or constraints.
* **Distinguish observation from mutation:** Separate read-only telemetry gathering from state-modifying or destructive operations.
* **Avoid unrestricted authority:** Deny ambient or unbounded wildcards.
* **Be composable:** Allow the AI orchestrator to combine orthogonal capabilities to achieve complex outcomes.

Aurora prefers **general system primitives** over specialized, hard-coded AI features. For instance, the system provides composable observation primitives (such as inspecting CPU statistics or process listings) rather than a monolithic capability like `diagnose_slow_computer`. The AI subsystem reasons over general primitives to diagnose issues, while the system retains small, auditable capability surfaces.

Conceptual examples include:
* `sys.cpu.read`
* `sys.memory.read`
* `proc.list`
* `fs.file.read`
* `app.launch`

### 3.4 Deterministic Authorization Pipeline
The AI worker cannot grant itself capabilities or modify policy rules. Every capability request emitted by the AI subsystem must pass through deterministic authorization before execution.

The conceptual authorization flow is:

$$\text{Caller Identity} \longrightarrow \text{Capability Requested} \longrightarrow \text{Parameters / Scope} \longrightarrow \text{Applicable Policy} \longrightarrow \text{Authorization Decision} \longrightarrow \text{Capability Execution}$$

* **Default Deny:** All capability requests are denied unless explicitly permitted by policy.
* **Deterministic Evaluation:** The authorization decision is computed strictly by deterministic logic in the system service; the model's self-reported confidence, prompt framing, or perceived urgency has zero influence on the decision.
* **Mechanism Agnostic:** The exact policy syntax, configuration paths, IPC formats, and enforcement system calls are deferred to implementation specifications.

### 3.5 AI-Assisted Orchestration
Aurora OS intentionally incorporates AI reasoning within its orchestration layer. 

The AI subsystem may assist with:
* Interpreting natural-language intent.
* Selecting relevant context from available inputs.
* Identifying which capabilities may be useful to fulfill a request.
* Constructing parameters for capability requests.
* Proposing multi-step operational plans.
* Synthesizing execution results into meaningful responses.

However, all AI outputs—including structured capability requests—must be treated as **untrusted input**. AI reasoning informs *what to ask for*, but never bypasses deterministic authorization or executes operations directly.

### 3.6 Caller Authority and AI Subsystem Authority
The architecture does not permanently restrict AI authority to the rule that *"AI can only do whatever the calling application could natively do."* While that heuristic prevents confused-deputy attacks in common cases, adopting it as a permanent rule would unnecessarily constrain future Aurora-native capabilities (such as system-level troubleshooting or desktop-wide assistance requested through a lightweight client).

Instead, the architecture establishes:
1. The identity and authorization of the caller always matter and form part of the policy evaluation.
2. AI-mediated operations require explicit capability authorization regardless of caller context.
3. Aurora OS may eventually define controlled, purpose-specific authority for the AI subsystem itself.
4. Any such AI subsystem authority must remain strictly bounded by deterministic policy, constrained scopes, least privilege, and user consent where appropriate.

The final AI authority model will be designed as the platform evolves.

### 3.7 Scoped Filesystem Access Strategy
File access exposes high-value user data and significant security risks.
* **For the MVP:** Filesystem capability access will be restricted to a deliberately constrained demonstration area (e.g., an isolated sandbox directory).
* **Future Direction:** Path-prefix string matching is recognized as insufficient for long-term desktop security due to symlinks, path traversal, and race conditions. Future designs will evaluate safer delegation mechanisms such as user-selected file grants, file descriptor passing, desktop portals, or equivalent scoped resource handles. The final mechanism is not selected in this decision.

### 3.8 Risk and User Consent
The system does not lock Aurora into a fixed, rigid tier hierarchy at this stage. Instead, authorization requirements and user consent gates depend on a combination of risk factors:
* **Sensitivity** of the data involved.
* **Scope** of the requested operation.
* **Side effects** on the system or environment.
* **Reversibility** of the operation.
* **Destructive potential** (e.g., file deletion, process termination).
* **Repetition** (single invocation vs. continuous polling).
* **User intent** (whether the action was explicitly commanded by the user or autonomously inferred).
* **Nature of access** (observational telemetry vs. mutating action).

For the MVP, authorization will use a simple deterministic policy with explicit handling for sensitive actions. The comprehensive user consent UX and interactive challenge architecture will be designed in a future decision.

### 3.9 Multi-Step Plans
The AI orchestrator may propose multi-step plans to resolve complex user requests (e.g., inspect CPU $\rightarrow$ inspect memory $\rightarrow$ list processes).

For this architecture:
* **Authorization occurs at capability execution time:** Each capability invocation within a plan is evaluated when it is ready to be executed.
* **No Premature Plan-Wide Authorization:** The MVP will not introduce complex plan-wide transactional leases or pre-execution guarantees.
* **Future Evolution:** Future iterations may explore grouping or batching operations when they share equivalent risk profiles and scopes, but execution-time authorization remains the baseline guarantee.

### 3.10 Failure Containment and System Invariance
The capability and permission subsystem must **fail closed**:
* **Denied Capability:** Returns a deterministic permission error to the orchestrator; the AI may communicate the denial or alter its plan, but cannot retry around the block.
* **Invalid Request or Malformed Parameters:** Rejected immediately before reaching execution providers.
* **Unavailable Capability Provider:** Fails gracefully with a standard provider error.
* **AI Worker Crash / Hang:** Trapped by the core daemon supervisor; pending client requests receive a service error, and the desktop remains unaffected.
* **Policy Evaluation Failure:** Defaults strictly to `DENY`.
* **User Denial:** Halts the proposed action immediately.
* **Timeout:** Cancels capability execution if execution thresholds are exceeded.

**Fundamental Invariant:** The desktop shell, system services, and conventional Linux applications must continue running normally if the AI worker, orchestrator, or capability subsystem fails. AI failure must never degrade baseline OS operations.

### 3.11 Minimum Viable Product (MVP) Boundary
To validate the architecture with minimal complexity, the capability registry for the initial MVP is restricted to four narrow primitives:
1. `sys.cpu.read` — Read basic CPU usage statistics.
2. `sys.memory.read` — Read system memory utilization statistics.
3. `proc.list` — Read a list of running processes with basic resource metrics.
4. `fs.file.read` — Read file contents strictly confined to a designated demonstration directory.

No further capabilities will be introduced for the MVP. Advanced actions (writing files, modifying settings, terminating processes, executing commands) are deferred until this foundation is proven.

### 3.12 Deferral of Implementation Mechanisms
This ADR establishes the architectural boundaries and guarantees. It deliberately avoids premature commitments regarding:
* Exact D-Bus interface names, method signatures, and wire formats.
* Exact internal Unix domain socket protocols (JSON-RPC, Protobuf, etc.).
* Specific Linux sandboxing technologies for worker isolation (cgroups, user namespaces, seccomp filters, landlock).
* Exact filesystem storage paths or schemas for policy files.
* Concrete desktop Polkit or Portal integrations.
* Model inference runtimes or GPU acceleration frameworks.

These details will be decided in implementation-oriented specifications following the acceptance of this architecture.

## 4. Rationale
* **Untrusted Worker Principle:** Treat the AI worker as untrusted software ensures that bugs, model drift, or prompt injection cannot result in unauthorized system modification.
* **General Primitives:** Small, orthogonal capabilities can be audited thoroughly, tested independently, and recombined by the AI orchestrator to answer unanticipated queries.
* **Fail-Closed Design:** A default-deny stance guarantees that unexpected inputs, protocol deserialization errors, or policy parsing faults never default to executing an action.
* **Separation of Policy Enforcement from OS Authority:** Situating `aurora-ai` as a policy enforcement point for AI capabilities prevents it from becoming an unwieldy substitute for existing Linux security features.

## 5. Alternatives Considered
* **Ambiently Privileged In-Process AI:** Embedding model inference directly into the core daemon with ambient daemon privileges. *Rejected:* A crash in inference kills the daemon, and prompt injection would yield full daemon authority over the host.
* **Direct Application Capability Access (Bypassing `aurora-ai`):** Requiring applications to execute all system capabilities directly and feed raw data to `aurora-ai`. *Rejected:* Duplicates capability execution code in every application, prevents shared system-level intelligence, and precludes centralized policy oversight.
* **Dynamic / Self-Authorizing AI Agent:** Allowing the model to request and approve its own capability escalations based on reasoning. *Rejected:* Violates core security principles; probabilistic systems cannot act as their own security boundaries.
* **Large Monolithic Capability Set for MVP:** Defining dozens of broad system administration capabilities immediately. *Rejected:* Introduces substantial security attack surface and implementation overhead before core plumbing and isolation boundaries are validated.

## 6. Consequences & Trade-offs
### Positive
* Robust security boundary: Prompt injection and worker vulnerabilities cannot automatically compromise the system.
* High maintainability: Small capability surface makes verification and testing straightforward.
* Extensible architecture: New capabilities can be registered and subjected to the same deterministic authorization pipeline.
* Fault isolation: AI subsystem crashes do not impact the host desktop.

### Negative & Trade-offs
* IPC overhead: Multi-step orchestration requires message passing across process boundaries.
* Orchestration latency: The model must perform round-trips to propose capabilities and receive observations.
* Policy maintenance: System administrators and developers must define explicit rules for capability access.

## 7. Relationship with ADR-001
This decision directly builds upon [ADR-001](0001-core-daemon-and-worker-runtime-architecture.md):
* **ADR-001** established the process and language boundaries: a memory-safe core daemon in Rust acting as supervisor and policy manager, communicating with an unprivileged inference worker in Python over a private Unix domain socket.
* **ADR-002** defines how that architecture safely mediates capability requests, enforces deterministic authorization, and isolates system resources from AI reasoning.
* No contradictions exist between ADR-001 and ADR-002. ADR-001 remains unchanged.

## 8. Open Questions
The following architectural and design questions are deliberately left open for subsequent decisions:
1. **GUI User Consent Implementation:** How should interactive consent challenges be presented to the user (e.g., via an XDG Desktop Portal, a dedicated Aurora Shell interface, or Polkit agents)?
2. **Safe Resource Delegation:** Which specific mechanism (file descriptors, portals, capability tokens) should replace path-based scoping for user-selected files and resources?
3. **AI Subsystem Authority Model:** What specific, controlled authority should be granted to the AI subsystem when acting on system-level tasks independent of an application context?
4. **Multi-Step Plan Authorization:** Under what conditions, if any, can multi-step plans with homogeneous risk profiles be authorized as a batch rather than step-by-step?
5. **Worker Sandboxing Primitives:** Which specific combination of Linux primitives (namespaces, seccomp-bpf, cgroups v2, landlock) should enforce the unprivileged worker's isolation?
6. **Capability Provider Organization:** Should capability providers be compiled directly into the `aurora-ai` daemon, executed in separate helper processes, or mediated via external system daemons over D-Bus?

## 9. Reconsideration Criteria
This decision will be reconsidered if:
1. IPC latency between the worker, orchestrator, and capability providers proves prohibitive for interactive desktop usage.
2. The separation of orchestration and capability execution prevents viable integration with emerging local model architectures.
3. Linux desktop portal standards provide a unified capability model that supersedes internal daemon policy enforcement.
