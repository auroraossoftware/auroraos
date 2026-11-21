# Aurora OS AI Worker Threat Model

* **Status:** Approved Architectural Specification (Milestone 10a)
* **Date:** 2026-11-20
* **Authoritative Architecture Context:** [ADR-001](../decisions/0001-core-daemon-and-worker-runtime-architecture.md), [ADR-002](../decisions/0002-capability-and-permission-architecture.md), [ADR-003](../decisions/0003-socketpair-ipc-transport.md), and [Milestone 8 System Audit](../audit-m8.md)
* **Companion Document:** [Worker Sandbox Requirements](worker-sandbox-requirements.md)

---

## 1. Executive Summary & Security Objectives

Aurora OS incorporates an artificial intelligence subsystem where model reasoning is decoupled from core operating system authority. Under [ADR-001](../decisions/0001-core-daemon-and-worker-runtime-architecture.md) and [ADR-002](../decisions/0002-capability-and-permission-architecture.md), the AI worker process is treated as **untrusted software**.

In Milestones 1 through 9, the capability dispatcher and policy engine in the core daemon (`aurora-ai`) enforced deterministic pre-authorization for all capability proposals transmitted over IPC. However, as documented in the Milestone 8 audit ([Tracked Item #1](../audit-m8.md#L304-L307)), the worker process itself has executed as an unconfined child process.

The agreed **Milestone 10 security objective** is:

> **"If the Python AI worker is completely compromised, it must not gain unrestricted access to the host system. It must operate within an explicitly defined, operating-system-enforced security boundary."**

This document establishes the threat model for a fully compromised AI worker process. It defines the trust boundaries, catalog of attack surfaces, attacker capabilities, inherited file descriptor risks, and residual platform boundaries.

---

## 2. System Context & Component Decomposition

The system consists of the following components and operational paths:

```
+---------------------------------------------------------------------------------+
|                               HOST LINUX SYSTEM                                 |
|                                                                                 |
|  +-----------------------------------+     +---------------------------------+  |
|  |       aurora-ai Core Daemon       |     |       AI Worker Runtime         |  |
|  |              (Rust)               |     |           (Python)              |  |
|  |                                   |     |                                 |  |
|  |  * WorkerSupervisor (owner thread)|     |  * Python 3 Interpreter         |  |
|  |  * CapabilityDispatcher           |     |  * Model Execution & Inference  |  |
|  |  * PolicyEngine (Default-Deny)    |     |  * Untrusted Reasoning Turn     |  |
|  |  * Capability Providers           |     |  * Protocol Framing (512 KiB)   |  |
|  +-----------------+-----------------+     +----------------+----------------+  |
|                    |                                        |                   |
|                    +================ socketpair ============+                   |
|                                (FD 0 Native Handoff)                            |
|                                                                                 |
|  [APPLICATION / PROTOCOL BOUNDARY]         [OPERATING SYSTEM BOUNDARY]          |
|  - Strictly mediated by daemon             - Governed by Kernel LSM & DAC       |
|  - Denied proposals: 0 executions          - Subject of M10 Confinement         |
+---------------------------------------------------------------------------------+
```

### 2.1 Component Roles
1. **Core System Daemon (`aurora-ai`)**:
   - Implemented in Rust as a memory-safe, long-running daemon.
   - Mediates access to host capabilities (`sys.cpu.read`, `sys.memory.read`, `proc.list`, `fs.file.read`).
   - Evaluates caller identity and policy grants deterministically prior to provider invocation.
   - Supervises the worker process lifecycle across anonymous socketpair IPC.
2. **AI Worker Process (`aurora-worker`)**:
   - Implemented in Python. Dedicated solely to model loading, prompt evaluation, planning, and response synthesis.
   - Communicates with the daemon over a private, kernel-allocated stream socket pair (`socketpair(AF_UNIX, SOCK_STREAM, 0)`).
   - In M1–M9, runs a deterministic stub; in future production milestones, executes complex neural runtimes (e.g., PyTorch, llama.cpp, ONNX Runtime).

### 2.2 Path Distinctions: Development vs. Deployment
To prevent environment coupling, security boundaries distinguish between development workspaces and deployment-independent runtime paths:

| Logical Role | Development Environment (Codespace) | Standard Production Linux Deployment |
| :--- | :--- | :--- |
| **Daemon Binary** | `target/debug/aurora-ai` | `/usr/libexec/aurora-ai` or `/usr/bin/aurora-ai` |
| **Worker Entrypoint** | `/workspaces/auroraos/worker/main.py` | `/usr/lib/aurora-ai/worker/main.py` |
| **Python Libraries** | `/opt/conda/...` or `/usr/lib/python3.x` | System `/usr/lib/python3.x`, `/usr/local/lib/python3.x` |
| **Worker Scratch/Cache** | `/tmp/aurora-worker-scratch-[id]` | `$XDG_RUNTIME_DIR/aurora-ai/worker-scratch` or private `tmpfs` |
| **Sandbox Demo Root** | `/tmp/aurora-sandbox-demo` | `/var/lib/aurora-ai/sandbox` |
| **Operator Policy Config** | In-memory / CLI flags | `/etc/aurora/policy.json` or `/etc/aurora-ai/` |

---

## 3. Trust Boundaries & Current Security Posture (M9 Baseline)

### 3.1 The Application / Protocol Boundary
Across the socketpair IPC channel, the core daemon strictly mediates capability execution:
* **Untrusted Wire Input**: Every message from the worker (`ProposeCapability`, `CompleteTurn`, `HandshakeResponse`) is validated against schema bounds, protocol version invariance, and turn ID correlation.
* **Pre-Dispatch Policy Gate**: Capability proposals are evaluated by `PolicyEngine::evaluate` before any provider executes. Denied proposals yield `PERMISSION_DENIED` with zero capability executions.
* **Proposal Flooding Defense**: Turns exceeding 20 proposals fail closed immediately with session invalidation.
* **Transport Hygiene**: Anonymous socketpair eliminates VFS pathname collision, capture, and unlinking races.

### 3.2 The Host Operating System Boundary (The M9 Reality)
The application-level protocol boundary assumes the worker only interacts with the system by sending messages over the socket. However, at the operating system layer:
* **Process Identity & Group**: The worker process runs under the **exact same User ID (`UID`) and Primary/Supplementary Group IDs (`GID`)** as the `aurora-ai` daemon (or the interactive desktop user invoking the CLI).
* **Ordinary Linux Security Controls Active**:
  - **Discretionary Access Control (DAC)**: The worker is bounded by standard Linux user permissions (`rwxr-xr-x`). It cannot access root-owned files (`/etc/shadow`, `/root`) unless read permissions are explicitly open.
  - **POSIX ACLs**: Standard filesystem access control lists apply to the worker's UID.
  - **Linux Security Modules (LSM)**: Host-level LSMs (such as AppArmor or SELinux) enforce standard system-wide confinement on the calling user.
  - **Yama ptrace Scope**: `/proc/sys/kernel/yama/ptrace_scope` restricts unprivileged process attachment across disparate process hierarchies.
* **The Ambient Authority Vulnerability**:
  Because no OS-level sandboxing (Landlock, Seccomp, namespaces) was applied in M1–M9, the worker process possesses the **full ambient authority of the invoking user**. A compromised worker can bypass the IPC socket entirely and make direct Linux system calls to read user files, access the network, or signal sibling processes.

---

## 4. Threat Actor Profile & Attacker Capabilities

### 4.1 Threat Actor Profile
* **Attacker Objective**: System compromise, persistent host access, private user data exfiltration, lateral network movement, denial of service, or unauthorized capability invocation.
* **Attack Vectors for Compromise**:
  1. *Prompt Injection*: Malicious user or external content manipulating future dynamic code-execution features or tool-use planning.
  2. *Native Runtime Vulnerabilities*: Memory corruption, buffer overflows, or arbitrary write primitives in underlying C/C++ neural runtimes (e.g., llama.cpp, PyTorch C++ bindings, BLAS libraries, tokenizers).
  3. *Supply-Chain Tampering*: Malicious or compromised third-party Python packages, models, or serialization artifacts (e.g., unsafe pickle/safetensors deserialization).
* **Attacker Position**: Complete Arbitrary Code Execution (ACE) within the Python worker address space.

### 4.2 Attacker Capabilities (Assumed Breach)
Once compromised, the attacker is **not constrained by Python language abstractions or cooperative runtime checks**:
* The attacker can execute raw shellcode, invoke arbitrary native Linux system calls via `syscall(2)` or inline assembly, and spawn threads.
* The attacker can manipulate, inspect, or duplicate any file descriptor held in the worker process's open file table.
* The attacker can attempt to send direct signals or ptrace commands to host processes.
* The attacker can ignore the IPC protocol entirely, refusing to send `ProposeCapability` and instead attempting direct execution against the kernel.

**Core Invariant**: The worker process cannot be trusted to self-report its security state, enforce its own isolation, or respect Python-level guards once arbitrary native execution is achieved.

---

## 5. Attack Surface & Threat Scenario Catalog

| Threat ID | Category | Attacker Scenario | Baseline Impact (M9) | M10 Security Target |
| :--- | :--- | :--- | :--- | :--- |
| **THR-FS-01** | **Host Filesystem Read** | Worker issues `openat()` to read `~/.ssh/id_rsa`, `~/.bash_history`, browser profiles, or auth tokens. | **High**: Full read access to all files accessible by the user's UID. | **Blocked**: VFS confinement denies access to user `$HOME`, `/root`, and sensitive host trees. |
| **THR-FS-02** | **Host Filesystem Write** | Worker writes a malicious backdoor to `~/.bashrc`, `~/.config/autostart`, or cron jobs to achieve persistence. | **Critical**: Permanent user account compromise and persistence across reboots. | **Blocked**: Entire host filesystem is mounted or restricted to read-only; zero write authority to host disk. |
| **THR-FS-03** | **Scratch/Cache Escape** | Worker attempts directory traversal (`../`) out of its designated writable cache directory into parent paths. | **High**: Escape from cache into user files. | **Blocked**: Kernel-enforced path resolution and Landlock rules strictly confine writes to the designated scratch boundary. |
| **THR-NET-01** | **Outbound Exfiltration** | Worker creates an `AF_INET` TCP socket and exfiltrates environment variables or data to a remote C2 server. | **High**: Unrestricted outbound network exfiltration. | **Blocked**: Default zero network access; socket creation denied or isolated network namespace with loopback down. |
| **THR-NET-02** | **Local Service Probing** | Worker connects to local loopback ports (`127.0.0.1`) or local Unix domain sockets (D-Bus session bus, Wayland, PipeWire). | **High**: Lateral movement to desktop services, keystroke snooping, or display capture. | **Blocked**: Network stack isolated; local domain socket creation and access restricted by Landlock and Seccomp. |
| **THR-PROC-01** | **Process Inspection** | Worker inspects `/proc/[pid]/cmdline`, `environ`, and memory maps of sibling user applications. | **Medium**: Information disclosure of arguments and secrets from running desktop apps. | **Blocked**: Isolated PID namespace or `/proc` mount hiding external processes. |
| **THR-PROC-02** | **Process Signaling & Ptrace** | Worker sends `SIGKILL` / `SIGSTOP` or attempts `PTRACE_ATTACH` against the `aurora-ai` daemon or desktop shell. | **High**: Denial of service, daemon shutdown, or process code injection under shared UID. | **Blocked**: Process isolation, Yama restrictions, Seccomp-BPF prohibition of `ptrace`, and `PR_SET_DUMPABLE(0)`. (Note: `PR_SET_DUMPABLE(0)` protects the worker from being traced by other same-UID processes; preventing the worker from tracing *others* is strictly enforced by Seccomp blocking `ptrace`/`process_vm_readv` and PID namespace isolation). |
| **THR-BYP-01** | **Direct Capability Bypass** | Worker directly reads `/proc/stat`, `/proc/meminfo`, or host sandbox files, bypassing policy mediation. | **Medium**: Circumvents capability audit logs and deterministic permission gates. | **Blocked**: Direct VFS access to system telemetry nodes and external files is blocked; delegation is mandatory. |
| **THR-RES-01** | **Process Fork Bomb** | Worker launches an unbounded loop of `fork()` calls, exhausting available PID table entries for the user. | **High**: Denial of service; freezes entire user graphical session. | **Blocked**: Cgroup v2 `pids.max` strictly caps total process and thread tree size. (Note: POSIX `RLIMIT_NPROC` cannot be used as an isolated per-worker limit because it restricts the entire real UID globally). |
| **THR-RES-02** | **Memory & Storage Exhaustion** | Worker allocates vast memory buffers or fills disk storage, triggering the kernel OOM killer or exhausting disk. | **High**: Random termination of critical user applications or host disk fill-up. | **Blocked**: Cgroup v2 `memory.max` contains memory exhaustion strictly within the worker cgroup. Aggregate scratch storage is bounded via private `tmpfs` quota (POSIX `RLIMIT_FSIZE` limits individual file size only, not aggregate storage). |
| **THR-IPC-01** | **Descriptor Stealing / Reuse** | Worker attempts to manipulate inherited file descriptors from the parent daemon to tamper with host resources. | **High**: Exploits leaked parent file handles (e.g. log files, directory handles, database descriptors). | **Blocked**: Strict inherited descriptor allowlist (`close_range`); only approved IPC handles remain open. |
| **THR-IPC-02** | **Protocol Desynchronization** | Worker transmits oversized frames (>512 KiB) or malformed NDJSON to cause buffer overflows or hangs in daemon. | **Low**: Trapped by M9 `read_bounded_line` and byte-bounded framing; session terminated. | **Maintained**: 512 KiB limit and immediate session drop remain active. |
| **THR-IPC-03** | **Ancillary FD Passing (`SCM_RIGHTS`)** | Worker attempts to smuggle or receive host file descriptors over the Unix domain socket via `sendmsg`/`recvmsg`. | **High**: Potential bypass of descriptor containment or host descriptor leakage over IPC. | **Blocked**: IPC stream handler strictly uses standard stream I/O; `SCM_RIGHTS` ancillary control messages are prohibited. |

---

## 6. Inherited File Descriptor & Channel Security

A critical security vulnerability in Unix process execution is the accidental inheritance of open file descriptors across `execve`.

### 6.1 The Inherited Descriptor Threat & Channel Hazards
Landlock filesystem access controls and mount namespaces restrict *future* path resolution operations (e.g., `openat(2)`). **They do not invalidate or revoke access to file descriptors that are already open prior to confinement.**
* If the `aurora-ai` daemon holds an open file descriptor (such as a directory handle to the host filesystem, an open database connection, or a logging socket) and fails to set `O_CLOEXEC`, a compromised child process inherits that descriptor.
* The compromised worker can read, write, or issue `fchdir(2)` on that descriptor, completely bypassing Landlock and filesystem namespace restrictions.
* **M9 Stderr Inherit Hazard**: In Milestone 9, child creation in `WorkerSupervisor` configured `cmd.stderr(Stdio::inherit())`. When launched from an interactive shell, FD 2 is an open handle to the controlling terminal (`/dev/pts/*`). A compromised worker with an open terminal descriptor could issue `ioctl(2, TIOCSTI, ...)` to inject simulated keystrokes into the host shell's input queue, potentially achieving arbitrary command execution in the parent user session. FD 2 must never be an uncontrolled inherited terminal descriptor.
* **`SCM_RIGHTS` Descriptor Smuggling Hazard**: Over Unix domain stream sockets, processes can transmit file descriptors via `sendmsg(2)` using `SCM_RIGHTS` ancillary control data. The worker IPC transport must strictly disallow descriptor transfers; the daemon must ignore or reject any received message bearing ancillary control buffers.

### 6.2 Explicit Inherited-FD Allowlist
The worker process execution boundary mandates an **explicit, closed allowlist** of inherited descriptors:

| Descriptor | Identity | Ownership | Required State | Consequence of Compromise |
| :---: | :--- | :--- | :--- | :--- |
| **FD 0** | Private IPC Stream (`socketpair`) | Shared (Worker Endpoint) | Bidirectional `SOCK_STREAM`, non-blocking, clean. `SCM_RIGHTS` ancillary descriptor passing strictly forbidden. | Normal protocol communication; bounded by 512 KiB NDJSON parser. |
| **FD 1** | Standard Output | Operating System | Explicitly redirected to `/dev/null` (`Stdio::null()`). | Write calls succeed into null sink without host impact. |
| **FD 2** | Standard Error | Operating System | Explicitly redirected to `/dev/null` (`Stdio::null()`) or a non-terminal unidirectional daemon logging pipe. **Must NOT be an inherited terminal (`Stdio::inherit()`).** | Worker diagnostic output; non-interactive; eliminates `TIOCSTI` terminal injection risk. |
| **FD $\ge$ 3** | **All Other Descriptors** | **FORBIDDEN** | **Must be strictly closed** via `close_range(3, ~0U, 0)`. | Leaked handles allow complete sandbox bypass. |

---

## 7. Residual Risks & Platform Boundary Constraints

The following threats are explicitly recognized as outside the scope of Milestone 10 worker confinement:

1. **Kernel Zero-Day Exploits**:
   - If a compromised worker executes a local privilege escalation (LPE) exploit against a Linux kernel vulnerability in permitted system calls, kernel-level sandboxing can be bypassed.
   - *Mitigation*: Seccomp filtering dramatically shrinks the available kernel attack surface by blocking dangerous subsystems (`bpf`, `io_uring`, `userfaultfd`, raw network protocols).
2. **Microarchitectural Side-Channels**:
   - Hardware side-channels (Spectre, Meltdown, MDS) allowing transient execution memory reads across CPU cores.
   - *Boundary*: Mitigated by standard kernel page-table isolation (KPTI) and speculative execution barriers; not solvable within userspace worker sandboxing alone.
3. **Pre-Existing External Hard Links in Sandbox**:
   - As documented in the M8 audit ([Tracked Item #2](../audit-m8.md#L308-L309)), `openat2` resolution flags cannot detect pre-existing hard links targeting external inodes inside the demonstration directory.
   - *Boundary*: Administrative hygiene ensures the sandbox directory contains no hard links pointing outside its tree.
4. **Physical & Hardware-Level Access**:
   - Physical tampering with host hardware, cold-boot memory extraction, or direct DMA attacks.

---

## 8. Summary of Defense-in-Depth Posture

```
[Layer 1: External Confinement]
  * Trusted launcher establishes environment before untrusted code runs.
  * Explicit inherited FD allowlist (FD 0, 1, 2 only; close_range on rest).

[Layer 2: Operating System Sandboxing]
  * Landlock LSM restricts VFS access: read-only whitelist, isolated writable scratch.
  * Network isolation: socket creation prohibited / CLONE_NEWNET.
  * Seccomp-BPF filters prohibited syscalls (execve, ptrace, kill, dangerous clone).
  * Cgroup v2 limits memory ceiling, CPU bandwidth, and total process/thread count.

[Layer 3: Deterministic Daemon Mediation]
  * Private anonymous socketpair transport.
  * Directional framing, turn correlation, 512 KiB bounds, proposal flood limits.
  * Default-deny deterministic policy engine evaluates all capability requests.
  * Observation providers execute only upon explicit authorization.
```
