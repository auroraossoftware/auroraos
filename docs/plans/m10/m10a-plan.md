# Milestone 10a Plan: Threat Model and Security Requirements

* **Plan Status:** Approved
* **Execution Status:** Complete
* **Date:** 2026-11-20 / 2026-11-21
* **Authoritative Architecture Context:**
  - [ADR-001: Core Daemon Language, Initial Worker Runtime, and Process Boundary](../../decisions/0001-core-daemon-and-worker-runtime-architecture.md)
  - [ADR-002: Capability and Permission Architecture](../../decisions/0002-capability-and-permission-architecture.md)
  - [ADR-003: Anonymous Socketpair IPC Transport](../../decisions/0003-socketpair-ipc-transport.md)
  - [Aurora OS Implementation Roadmap](../../roadmap.md)
* **Primary Deliverables:**
  - [AI Worker Threat Model](../../security/worker-threat-model.md)
  - [Worker Security & Sandbox Requirements](../../security/worker-sandbox-requirements.md)

---

## 1. Milestone Overview & Security Objective

Aurora OS incorporates artificial intelligence as an unprivileged, decoupled system service. Under [ADR-001](../../decisions/0001-core-daemon-and-worker-runtime-architecture.md) and [ADR-002](../../decisions/0002-capability-and-permission-architecture.md), the AI worker process is treated as **untrusted software**: it may reason over inputs and propose operational steps via IPC, but it possesses zero ambient authority to invoke system capabilities directly.

In Milestones 1 through 9, capability proposals received over private anonymous socketpair IPC ([ADR-003](../../decisions/0003-socketpair-ipc-transport.md)) were strictly mediated by the daemon's deterministic policy engine and capability dispatcher. However, at the operating system layer, the worker process executed as a standard unconfined child process sharing the daemon's User ID (`UID`) and Group ID (`GID`), retaining ambient access to host files, processes, and network resources.

The agreed **Milestone 10 security objective** is:

> **"If the Python AI worker is completely compromised, it must not gain unrestricted access to the host system. It must operate within an explicitly defined, operating-system-enforced security boundary."**

Milestone 10 is executed across four sequential sub-milestones:
1. **M10a: Threat Model and Security Requirements** (This Plan — Approved and Complete).
2. **M10b: Sandbox Architecture and Design** (Planned).
3. **M10c: Sandbox Implementation** (Planned).
4. **M10d: Adversarial Testing and Security Audit** (Planned).

Sub-milestone 10a establishes the architectural foundation: formalizing the threat model, cataloging attack surfaces, establishing an explicit inherited file-descriptor allowlist, defining ten operating-system-enforced security requirements, and evaluating candidate Linux isolation primitives.

---

## 2. Planning Objectives

The objectives for Milestone 10a were:

1. **Architecture & Implementation Reconnaissance**: Inspect the M1–M9 implementation artifacts to document actual security boundaries, lifecycle mechanics, file-descriptor inheritance, and existing limitations.
2. **Threat Modeling for Fully Compromised Worker**: Formulate an authoritative threat model assuming complete Arbitrary Code Execution (ACE) within the worker address space, with no reliance on Python-level cooperative guardrails.
3. **Attack Surface Identification**: Catalog active attack vectors across host filesystem access, network exfiltration, process signaling/inspection, resource exhaustion (fork-bombs, memory pressure), and direct capability bypasses.
4. **Inherited Descriptor Policy**: Analyze file-descriptor leakage hazards (including the M9 `Stdio::inherit()` terminal injection vector and `SCM_RIGHTS` descriptor smuggling) and establish an explicit inherited-FD allowlist.
5. **Security Requirements Formulation**: Define ten verifiable, OS-enforced security requirements (SEC-REQ-01 through SEC-REQ-10).
6. **Isolation Mechanism Evaluation**: Evaluate Linux Landlock LSM, Seccomp-BPF, Linux Namespaces, Cgroups v2, POSIX resource limits, and a dedicated native trusted launcher.
7. **Empirical Platform Probing**: Probe the target Linux kernel directly to determine actual Landlock ABI support, LSM configuration, and cgroup availability.
8. **Roadmap & Milestone Tracking**: Update [`docs/roadmap.md`](../../roadmap.md) to record Milestone 10 and its four sub-milestones.

---

## 3. Scope and Explicit Non-Goals

### 3.1 In-Scope
* Architecture reconnaissance across `crates/aurora-ai`, `crates/aurora-protocol`, and `worker/`.
* Creation of [`docs/security/worker-threat-model.md`](../../security/worker-threat-model.md).
* Creation of [`docs/security/worker-sandbox-requirements.md`](../../security/worker-sandbox-requirements.md).
* Updating [`docs/roadmap.md`](../../roadmap.md) to reflect M10 sub-milestone execution.
* Direct kernel probing of Landlock ABI and security features on the development host.
* Preservation of this approved plan in `docs/plans/m10/m10a-plan.md`.

### 3.2 Explicit Non-Goals (Enforced Restrictions)
* **No Implementation Code**: No modifications to Rust daemon code, Python worker runtime, or test harnesses.
* **No Dependency Changes**: No additions to `Cargo.toml`, `Cargo.lock`, or Python packaging.
* **No Premature Milestones**: No commencement of M10b (Design), M10c (Implementation), or M10d (Audit).
* **No ADR Modification or Premature Creation**: Existing ADRs ([ADR-001](../../decisions/0001-core-daemon-and-worker-runtime-architecture.md), [ADR-002](../../decisions/0002-capability-and-permission-architecture.md), [ADR-003](../../decisions/0003-socketpair-ipc-transport.md)) remain unchanged. Proposed ADR-004 is deferred to Milestone 10b.
* **No Scope Broadening**: Maintaining focus strictly on internal AI worker confinement; public D-Bus interfaces and multi-user caller authentication remain out-of-scope until subsequent platform milestones.

---

## 4. Approved Threat-Modeling Approach

The approved threat model adheres to the following principles:

1. **Assumed Breach Posture**:
   * The threat actor is assumed to have achieved complete Arbitrary Code Execution (ACE) within the Python worker address space (e.g. via prompt injection driving code execution, memory corruption in native C/C++ neural acceleration runtimes, or supply-chain dependency tampering).
   * The attacker is not constrained by Python language abstractions or cooperative checks; they can issue raw Linux system calls (`syscall(2)`), manipulate descriptors, and spawn threads.
2. **Honest Accounting of Host Security Controls**:
   * The model accurately reflects that the worker runs as an unprivileged process under standard Linux Discretionary Access Control (DAC: UID/GID permissions `rwxr-xr-x`), POSIX ACLs, AppArmor, and Yama `ptrace_scope`.
   * The worker does not possess root privileges; the threat stems from possessing the **full ambient authority of the invoking desktop user**.
3. **Attack Surface Catalog**:
   * **VFS Access**: Direct reading of `~/.ssh`, `~/.bash_history`, browser profiles, and tokens; persistence via `~/.bashrc` or autostart.
   * **Network Access**: Outbound data exfiltration to remote C2 servers; local loopback service and socket probing.
   * **Process Interference**: Snooping on sibling processes via `/proc`; signaling or ptrace injection under shared UID.
   * **Resource Denial-of-Service**: Fork-bombing to exhaust user PID space; RAM allocation to induce system-wide OOM panics.
   * **Capability Bypass**: Bypassing daemon capability mediation by directly reading `/proc/stat`, `/proc/meminfo`, or host files.

---

## 5. Security Requirements Established

Milestone 10a establishes ten formal security requirements recorded in [`docs/security/worker-sandbox-requirements.md`](../../security/worker-sandbox-requirements.md):

* **SEC-REQ-01 (Pre-Execution Confinement & Trusted Launcher)**: Essential confinement must be established externally before untrusted Python code, imports, or native extensions execute. Rejects Python self-confinement as primary boundary.
* **SEC-REQ-02 (Filesystem Whitelisting & Partitioning)**: Default-deny host VFS; read-only whitelist on runtime libraries and worker code; write access restricted strictly to a dedicated, isolated scratch/cache directory with mount-level quota (`PYTHONDONTWRITEBYTECODE=1`).
* **SEC-REQ-03 (Inherited Descriptor Hygiene & Leak Prevention)**: Explicit inherited-FD allowlist: FD 0 (IPC socketpair), FD 1 (`/dev/null`), FD 2 (`/dev/null` or non-terminal logging pipe). Mandatory `close_range(3, ~0U, 0)`. FD 2 must NOT inherit an interactive terminal (`Stdio::inherit()`) to eliminate `TIOCSTI` injection. Unintended `SCM_RIGHTS` descriptor passing over IPC is strictly prohibited.
* **SEC-REQ-04 (Network Disconnection by Default)**: Network socket creation blocked; execution inside disconnected network namespace (`CLONE_NEWNET`) with loopback down, or Seccomp socket blocks.
* **SEC-REQ-05 (System Call Filtering via Seccomp-BPF)**: Restrict system calls to an explicit allowlist. Block `execve` (post-initialization), `ptrace`, `bpf`, `mount`. Enforce thread creation strictly via `CLONE_THREAD`, and require `SECCOMP_FILTER_FLAG_TSYNC`.
* **SEC-REQ-06 (Resource Limits & Cgroup v2 Control)**: Cgroup v2 preferred for per-worker `pids.max`, `memory.max`, and `cpu.max`. Avoids the POSIX `RLIMIT_NPROC` per-UID trap. Strict mode refuses startup if mandatory resource controls are unavailable. `RLIMIT_FSIZE` bounds individual files only.
* **SEC-REQ-07 (Process Isolation & Non-Interference)**: `PR_SET_DUMPABLE(0)` protects worker from being traced by others; Seccomp and Yama prevent worker from tracing others. PID namespace child-entry invariant: worker must enter as a subsequently created child and mount a private `procfs` instance.
* **SEC-REQ-08 (External Deterministic Sandbox Verification)**: Prohibits trusting worker-reported flags. Procfs `/proc/<pid>/status` sanity checks complemented by trusted launcher sync-pipe verification.
* **SEC-REQ-09 (IPC Protocol & Lifecycle Compatibility)**: Low-descriptor safety ($\ge 3$), `PR_SET_PDEATHSIG(SIGKILL)`, orderly shutdown escalation ladder, and 512 KiB framing preserved.
* **SEC-REQ-10 (Platform Compatibility & Safe Refusal Policy)**: Dynamic probing of Landlock ABI at runtime via `landlock_create_ruleset`. Configurable strict vs. permissive failure policy.

---

## 6. Repository Reconnaissance Activities

The reconnaissance phase inspected:
1. **Existing Architecture Decision Records**:
   - [ADR-001](../../decisions/0001-core-daemon-and-worker-runtime-architecture.md): Verified memory-safe Rust daemon supervising isolated Python worker.
   - [ADR-002](../../decisions/0002-capability-and-permission-architecture.md): Verified deterministic default-deny policy pipeline and untrusted worker suggestion model.
   - [ADR-003](../../decisions/0003-socketpair-ipc-transport.md): Verified anonymous stream socketpair IPC, `Stdio::from(OwnedFd)` on FD 0, and pre-exec parent-death containment.
2. **Current Daemon Implementation (`crates/aurora-ai`)**:
   - `WorkerSupervisor` in `src/supervisor.rs`: Thread pinning (`!Send`/`!Sync`), signalfd multiplexing, lazy replacement recovery, orderly shutdown ladder (EOF $\to$ SIGTERM $\to$ SIGKILL $\to$ `waitpid`).
   - `CapabilityDispatcher` and `PolicyEngine`: Policy-before-provider execution invariant across all 4 MVP capabilities.
   - Child stdio setup: Identified `cmd.stderr(Stdio::inherit())` as an ambient terminal hazard to be addressed in M10.
3. **Worker Runtime (`worker/main.py`)**:
   - `init_socket_from_fd`: Descriptor duplication and `/dev/null` redirection on FD 0.
   - `BoundedSocketFile`: Strict 512 KiB raw wire byte framing limit.
4. **Empirical Runtime Probes**:
   - Kernel version: `Linux 6.8.0-1070-azure` (Ubuntu 22.04 LTS).
   - **Landlock ABI Probe**: Probed via `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`, returning **`ABI v4`**.
   - LSM configuration: `lockdown,capability,landlock,yama,apparmor` active in `/sys/kernel/security/lsm`.
   - Cgroups: Cgroup v2 unified hierarchy mounted at `/sys/fs/cgroup`.
   - Namespaces: Unprivileged user namespaces enabled (`unprivileged_userns_clone = 1`).

---

## 7. Documentation Deliverables

Milestone 10a produced the following documentation artifacts:

| Document | Path | Description |
| :--- | :--- | :--- |
| **AI Worker Threat Model** | [`docs/security/worker-threat-model.md`](../../security/worker-threat-model.md) | Comprehensive threat model for a fully compromised worker process under Arbitrary Code Execution (ACE). |
| **Worker Sandbox Requirements** | [`docs/security/worker-sandbox-requirements.md`](../../security/worker-sandbox-requirements.md) | Ten formal security requirements (SEC-REQ-01 to SEC-REQ-10), mechanism evaluations, and operational path mappings. |
| **Implementation Roadmap Update** | [`docs/roadmap.md`](../../roadmap.md) | Updated Section 1, Section 2, and added Section 5 detailing M10a through M10d. |
| **Milestone 10a Approved Plan** | `docs/plans/m10/m10a-plan.md` | Standalone permanent record of the approved and executed M10a plan. |

---

## 8. Architectural Constraints and Principles

The requirements established in M10a enforce four core architectural principles:

1. **Confinement-Before-Execution**: Untrusted code must never execute in an unconfined environment. Sandbox boundaries must be sealed by the supervisor or a trusted native launcher *prior* to `execve("python3")`.
2. **Single-Threaded Landlock Baseline (ABI 4 Compatibility)**:
   - Upstream Linux 6.8 corresponds to Landlock ABI v4; ABI v5 was merged in Linux 6.10.
   - Landlock ABI 8 introduced `LANDLOCK_RESTRICT_SELF_TSYNC` (thread synchronization for rulesets) and is available starting in Linux 7.0.
   - Because ABI 8 TSYNC is unavailable on kernels providing ABI v1–v5 (including our Linux 6.8 target environment), applying Landlock within a **strictly single-threaded trusted launcher (`aurora-worker-launcher`) before `execve("python3")` and before secondary threads exist** is our baseline approach.
   - All subsequent threads spawned by Python inherit the restricted Landlock domain. On platforms where runtime probing confirms ABI $\ge 8$, TSYNC will be leveraged as an optional defense-in-depth capability.
3. **PID Namespace Child-Entry & Private Procfs Mounting**:
   - Calling `unshare(CLONE_NEWPID)` affects only *subsequently created children*. The worker must enter the new PID namespace as a subsequently created child.
   - The launcher must configure a private mount namespace (`CLONE_NEWNS`) and mount a fresh `procfs` instance to prevent inheriting the host PID table.
4. **Trusted-Launcher-Controlled Verification**:
   - The daemon must never trust self-reported worker status.
   - Verification relies on trusted-launcher execution, clean error reporting over a dedicated supervisor sync pipe, and secondary procfs sanity checks.

---

## 9. Acceptance Criteria

The acceptance criteria for Milestone 10a were defined and met as follows:

| Acceptance Criterion | Verification Method | Status |
| :--- | :--- | :---: |
| **Comprehensive Threat Model Delivered** | Peer-reviewed specification covering all attack surfaces, ACE profile, and inherited descriptor hazards. | **MET** |
| **Formal Security Requirements Defined** | 10 numbered requirements (SEC-REQ-01 to SEC-REQ-10) with explicit criteria. | **MET** |
| **Empirical Runtime Probes Recorded** | Actual syscall probing of Landlock ABI (returning ABI v4 on Linux 6.8) and LSM presence. | **MET** |
| **Landlock ABI 8 TSYNC Compatibility Strategy** | Single-threaded launcher baseline documented; TSYNC treated as optional capability on Linux $\ge 7.0$. | **MET** |
| **PID Namespace Child-Entry & Procfs Documented** | Child-entry invariant and private procfs mounting explicitly specified. | **MET** |
| **Inherited FD Policy & Terminal Safety Defined** | Stderr terminal hazard documented; `close_range` and `SCM_RIGHTS` prohibitions enforced. | **MET** |
| **Roadmap Updated with Sub-Milestones** | [`docs/roadmap.md`](../../roadmap.md) updated with M10a, M10b, M10c, M10d. | **MET** |
| **Strict Non-Regression & Scope Containment** | Zero code modified; existing test suite (25/25 Python tests) passing; `git diff --check` clean. | **MET** |

---

## 10. Dependencies and Prerequisites

* **Prerequisites**: Milestones 1 through 9 complete, tested, and accepted.
* **Runtime Platform**: Modern Linux kernel ($\ge 5.13$ for Landlock ABI v1; $\ge 6.5$ for ABI v4; $\ge 3.5$ for Seccomp-BPF).
* **Development Baseline**: Linux 6.8.0-1070-azure (Ubuntu 22.04 LTS), Landlock ABI v4, Cgroup v2 unified hierarchy, unprivileged user namespaces enabled.

---

## 11. Risks, Limitations, and Unresolved Questions Handed Over to M10b

The following technical decisions are explicitly handed over to **Milestone 10b: Sandbox Architecture and Design**:

1. **Trusted Launcher Implementation Language & Tooling**:
   - Determine whether `aurora-worker-launcher` should be implemented in minimal Rust (statically linked via `musl` to eliminate dynamic linker dependencies) or minimal C.
2. **Supervisor $\leftrightarrow$ Launcher Sync Pipe Protocol**:
   - Design the exact framing and error payload for the synchronization pipe between `WorkerSupervisor` and `aurora-worker-launcher`.
3. **Restricted Scratch Directory Mount Mechanics**:
   - Design the exact mount lifecycle: private in-memory `tmpfs` (with `MS_NODEV | MS_NOSUID | MS_NOEXEC` and `size=128M`) inside a mount namespace vs. daemon-managed `$XDG_RUNTIME_DIR` path restricted by Landlock.
4. **Cgroup v2 Delegation Mechanics**:
   - Design the delegation workflow: integration with `systemd-run --user --scope` vs. writing to pre-delegated user cgroup subtrees.
5. **Seccomp System Call Allowlist Specification**:
   - Construct the exact minimal BPF system call allowlist required for dynamic linking, Python runtime execution, signal handling, and socketpair IPC.

---

## 12. Relationship with Existing Architecture Records & Roadmap

* **[ADR-001](../../decisions/0001-core-daemon-and-worker-runtime-architecture.md)**: M10 enforces the process boundary established in ADR-001 at the kernel layer, ensuring that the worker process cannot break out of its child runtime.
* **[ADR-002](../../decisions/0002-capability-and-permission-architecture.md)**: M10 guarantees that capability mediation cannot be bypassed via direct VFS syscalls, upholding the untrusted worker principle.
* **[ADR-003](../../decisions/0003-socketpair-ipc-transport.md)**: M10 sandboxing operates strictly over the anonymous socketpair IPC channel on FD 0, preserving descriptor inheritance safety and parent-death containment (`PR_SET_PDEATHSIG`).
* **[Proposed ADR-004]**: Architectural design decisions for the trusted launcher and isolation subsystem will be formalized as ADR-004 during Milestone 10b.
