# Aurora OS AI Worker Security & Sandbox Requirements

* **Status:** Approved Architectural Specification (Milestone 10a)
* **Date:** 2026-11-20
* **Authoritative Architecture Context:** [ADR-001](../decisions/0001-core-daemon-and-worker-runtime-architecture.md), [ADR-002](../decisions/0002-capability-and-permission-architecture.md), [ADR-003](../decisions/0003-socketpair-ipc-transport.md), and [Worker Threat Model](worker-threat-model.md)
* **Target Milestones:** Milestone 10a (Requirements), Milestone 10b (Design), Milestone 10c (Implementation), Milestone 10d (Audit)

---

## 1. Purpose & Confinement Principles

The objective of Milestone 10 is to enforce operating-system-level confinement on the Python AI worker process such that a completely compromised worker cannot compromise the host system, exfiltrate data, tamper with processes, or bypass capability authorization.

### 1.1 Core Confinement Invariants
1. **Confinement-Before-Execution Invariant**:
   * Essential security boundaries must be established **before** untrusted Python code, package imports, or native dynamic extensions execute.
   * **Python self-confinement is explicitly rejected as the primary security boundary.** Module imports (`import torch`, `import numpy`, or loading `.so` C extensions) execute arbitrary code at load time. If a dependency or model plugin is compromised, it executes *prior* to any in-Python lockdown routine. Confinement must be established externally by the trusted supervisor or a trusted launcher binary.
2. **Zero Ambient Authority**:
   * The worker process must not inherit the ambient VFS or networking privileges of the executing user account.
   * Access to host resources is denied by default; only the minimal resources strictly necessary for runtime operation are explicitly granted.
3. **Deterministic External Verification**:
   * The supervisor must never rely on worker-reported status flags (e.g. `{"sandboxed": true}`) as evidence of isolation. Isolation state must be guaranteed by the execution architecture and verified externally via kernel introspection.
4. **Lifecycle and IPC Preservation**:
   * Sandboxing mechanisms must remain 100% compatible with anonymous socketpair communication over FD 0, low-descriptor safety ($\ge 3$), `PR_SET_PDEATHSIG(SIGKILL)` parent death containment, and the orderly shutdown escalation ladder (EOF $\to$ SIGTERM $\to$ SIGKILL $\to$ `waitpid`).

---

## 2. Formal Security Requirements

### SEC-REQ-01: Pre-Execution Confinement & Trusted Launcher
* **Statement**: The operating system security boundary must be active before the Python virtual machine initializes.
* **Requirements**:
  1. Confinement must be established by the supervisor process or an intermediary trusted launcher prior to transferring execution to `python3`.
  2. The process boundary must invoke `libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)` before applying any Seccomp-BPF filters or Landlock rulesets, ensuring that child threads or future processes cannot acquire elevated privileges.
  3. The architecture must evaluate a dedicated, minimal native **trusted launcher** binary (`aurora-worker-launcher`) to decouple complex multi-step isolation setup from the supervisor's async-signal-safe `pre_exec` hook and from untrusted Python userspace.
  4. **Single-Threaded Confinement Timing**: While Landlock ABI 8 introduced thread synchronization (`LANDLOCK_RESTRICT_SELF_TSYNC`) starting in Linux 7.0, applying Landlock rules within a strictly single-threaded launcher environment *before* `execve("python3")` and before any secondary runtime threads exist remains our baseline approach. This ensures full compatibility with kernels that lack ABI 8 (such as our target development host running Linux 6.8, which probed as ABI 4), while treating ABI 8 TSYNC as an optional capability when supported.

### SEC-REQ-02: Filesystem Whitelisting & Partitioning
* **Statement**: The worker must operate within a partitioned, least-privilege filesystem view.
* **Requirements**:
  1. **Default-Deny**: Arbitrary host directories—including user `$HOME`, `/root`, `/etc`, `/var`, and `/boot`—must be inaccessible for both reading and writing.
  2. **Read-Only Whitelist**:
     - System Python executable and runtime libraries (e.g., `/usr`, `/lib`, `/usr/lib`, `/lib64`, `/usr/local/lib/python*`).
     - Aurora worker application package code (deployment path: `/usr/lib/aurora-ai/worker` or development path: `/workspaces/auroraos/worker`).
     - Minimal required dynamic linker paths (`/lib64/ld-linux-x86-64.so.2`).
  3. **Restricted Writable Scratch/Cache Directory**:
     - To permit standard Python interpreter initialization, temporary scratch buffers, and caching without granting host write access, the worker must be granted write access **strictly to a dedicated, isolated directory** (e.g., an unbacked `tmpfs` mount with a defined size limit such as `size=128M`, or an isolated daemon-managed directory like `$XDG_RUNTIME_DIR/aurora-ai/worker-scratch-[pid]` or `/tmp/aurora-worker-scratch-[pid]`).
     - Writing anywhere outside this designated scratch directory must be blocked by the kernel with `EACCES` or `EPERM`.
     - Environment variables `PYTHONDONTWRITEBYTECODE=1` and `PYTHONUNBUFFERED=1` must be enforced to minimize disk I/O requirements.
     - Note on Storage Bounds: POSIX `RLIMIT_FSIZE` bounds individual file creation size; aggregate scratch storage limits require a mount-level boundary (e.g. `tmpfs` size quota).

### SEC-REQ-03: Inherited Descriptor Hygiene & Leak Prevention
* **Statement**: The worker process must possess zero file descriptors beyond the explicitly approved IPC handles.
* **Requirements**:
  1. **Strict Inherited-FD Allowlist**:
     - **FD 0**: Private anonymous Unix stream socketpair endpoint connected to the daemon supervisor. Unintended `SCM_RIGHTS` file-descriptor passing over this channel is strictly prohibited.
     - **FD 1**: Standard output, redirected to `/dev/null` (`Stdio::null()`).
     - **FD 2**: Standard error, redirected to `/dev/null` (`Stdio::null()`) or a non-terminal unidirectional daemon logging pipe. **Must NOT be an inherited terminal (`Stdio::inherit()`)**, eliminating terminal injection (`TIOCSTI`) vectors.
  2. **Mandatory Close-Range**:
     - All file descriptors $\ge 3$ must be closed prior to executing the worker runtime using `libc::close_range(3, !0U, 0)` (or iterating `/proc/self/fd` on older kernels).
     - Daemon-side descriptors must maintain `O_CLOEXEC` to prevent accidental inheritance across fork boundaries.
  3. **Pre-Landlock Open FD Containment**:
     - Acknowledging that Landlock does not revoke access to pre-opened descriptors, the launcher/supervisor must ensure that no directory or file descriptors targeting the host filesystem remain open when Landlock is engaged.
  4. **Prohibition of Ancillary Descriptor Passing (`SCM_RIGHTS`)**:
     - The daemon IPC transport must explicitly reject or ignore `SCM_RIGHTS` ancillary control messages to prevent descriptor smuggling across the socketpair boundary.

### SEC-REQ-04: Network Disconnection by Default
* **Statement**: The worker process must not have default access to the host network stack.
* **Requirements**:
  1. Creation of network sockets (`socket(AF_INET, ...)`, `socket(AF_INET6, ...)`, `socket(AF_PACKET, ...)`, `socket(AF_BLUETOOTH, ...)`) must be blocked by the kernel.
  2. Where unprivileged user and network namespaces are supported, the worker must execute in a disconnected network namespace (`CLONE_NEWNET`) with no external interfaces and the loopback interface down.
  3. Where namespaces are unavailable, Seccomp-BPF filtering must unconditionally block `socket(2)` calls for network domains.

### SEC-REQ-05: System Call Filtering (Seccomp-BPF)
* **Statement**: The worker process system call surface must be restricted strictly to runtime-essential operations via Seccomp-BPF.
* **Requirements**:
  1. **Allowlist Strategy**: A BPF filter must allow only necessary system calls for memory allocation (`mmap`, `mprotect`, `munmap`, `brk`), basic I/O on inherited descriptors (`read`, `write`, `poll`, `ppoll`, `close`), signal handling, and thread control.
  2. **Prohibited System Calls**:
     - Process Creation: `fork`, `vfork`, `clone` (without `CLONE_THREAD`), `clone3` (without `CLONE_THREAD`).
     - Process Execution: `execve`, `execveat` (must be prohibited once the worker runtime initializes).
     - Process Tampering & Tracing: `ptrace`, `process_vm_readv`, `process_vm_writev`, `kcmp`.
     - Privileged / System Alteration: `mount`, `umount2`, `chroot`, `setuid`, `setgid`, `reboot`, `kexec_load`, `bpf`, `userfaultfd`, `io_uring_setup`.
  3. **Multi-Thread Synchronization (`SECCOMP_FILTER_FLAG_TSYNC`)**:
     - Filters must be installed with `SECCOMP_FILTER_FLAG_TSYNC` to ensure all existing and future threads in the worker process are bound to identical filtering constraints.
  4. **Signal Handling Syscalls**:
     - Syscalls essential for signal delivery and parent death containment (`rt_sigaction`, `rt_sigprocmask`, `rt_sigreturn`, `sigaltstack`) must be permitted.

### SEC-REQ-06: Resource Limits & Cgroup v2 Control
* **Statement**: The worker must be bounded by deterministic CPU, memory, and task limits to prevent denial-of-service against the host.
* **Requirements**:
  1. **The `RLIMIT_NPROC` Per-UID Trap**:
     - Architecture requirement: The system must **not** treat POSIX `RLIMIT_NPROC` as a per-worker process limit. Because `RLIMIT_NPROC` applies to the *entire real UID across all user processes*, setting a low limit would break other user applications or the daemon itself.
  2. **Cgroup v2 Resource Control (Primary)**:
     - Cgroup v2 is the preferred per-worker resource-containment mechanism. Where cgroup v2 delegation is available (e.g. systemd user manager scopes or write access to a delegated cgroup subtree), the worker process must be placed in a dedicated cgroup:
       - `pids.max`: Strictly limit maximum combined processes and threads (e.g., max 32 threads).
       - `memory.max` / `memory.high`: Hard ceiling for resident memory, containing memory spikes strictly to the worker cgroup and preventing system-wide OOM panic.
       - `cpu.max`: Quota-based CPU throttling to prevent runaway inference loops from starving the desktop shell.
  3. **POSIX Rlimit Fallback (Secondary / Baseline)**:
     - Regardless of cgroup availability, the supervisor/launcher must enforce:
       - `RLIMIT_CORE = 0`: Prevent core dumps from leaking memory or consuming disk.
       - `RLIMIT_FSIZE = 100M`: Limit maximum size of any individual file created in the scratch directory (Note: does not bound aggregate storage).
       - `RLIMIT_NOFILE = 64`: Cap maximum open file descriptors.
  4. **Degraded Policy vs. Strict Refusal**:
     - In strict security mode (`SandboxingMode::Enforce`), the supervisor must **refuse to start** the worker if mandatory resource controls (cgroups v2 or equivalent isolation) are unavailable.
     - In permissive/development mode (`SandboxingMode::Permissive`), the supervisor logs an explicit warning documenting that multi-thread fork-bomb and resident memory containment are running in a degraded baseline mode.

### SEC-REQ-07: Process Isolation & Non-Interference
* **Statement**: The worker must not be able to observe, signal, or tamper with sibling user processes.
* **Requirements**:
  1. **Dumpable Attribute**: The worker must set `libc::prctl(PR_SET_DUMPABLE, 0)`. Architectural clarification: `PR_SET_DUMPABLE(0)` protects the worker from being traced or inspected by other same-UID processes; it does not independently prevent the worker from tracing other processes. Preventing the worker from tracing others is enforced by Seccomp blocking `ptrace`, Yama `ptrace_scope`, and PID namespace isolation.
  2. **Process Group Isolation**: The worker must be isolated in its own process group (`process_group(0)`) to isolate terminal signal delivery.
  3. **PID Namespace & Procfs Semantics**:
     - Where supported, the worker must execute in a new PID namespace (`CLONE_NEWPID`).
     - **Child Entry Invariant**: In Linux, calling `unshare(CLONE_NEWPID)` does not place the calling process into the new namespace; only *subsequently created children* enter the new PID namespace. Therefore, the launcher must unshare the PID namespace and fork the worker process into it as a subsequently created child.
     - **Private Procfs Mounting**: Entering a new PID namespace while retaining the host's `/proc` mount leaves all host processes visible to the child. The confined worker environment must mount a fresh, private instance of `procfs` (or make `/proc` inaccessible) so that only processes inside the child PID namespace are visible.

### SEC-REQ-08: External Deterministic Sandbox Verification
* **Statement**: Sandboxing integrity must be verified externally by the supervisor, never by trusting the worker.
* **Requirements**:
  1. **Prohibition of Self-Reporting Trust**: The daemon supervisor must **never trust a worker-reported field** (such as `sandboxed: true` in `HandshakeResponse`) as verification that isolation is active.
  2. **Procfs Checks and Limitations**:
     - The supervisor may inspect the worker's status externally via Linux procfs:
       - Verify `/proc/<worker_pid>/status` contains `NoNewPrivs: 1`.
       - Verify `/proc/<worker_pid>/status` contains `Seccomp: 2` (filtering mode active).
       - When cgroup v2 is enabled, verify `/proc/<worker_pid>/cgroup` matches the expected delegated slice.
     - **Limitation Acknowledgment**: These procfs bits are useful sanity checks, but they do **not** prove the exact Seccomp BPF filter policy installed, nor do they prove Landlock VFS enforcement (Linux procfs provides no direct Landlock enforcement status bits).
  3. **Trusted-Launcher-Controlled Evidence**:
     - Deterministic evidence of successful sandbox setup must be established by the trusted launcher:
       - The launcher executes each confinement step sequentially (Landlock ruleset application, Seccomp BPF filter installation, namespace configuration, privilege dropping).
       - If any step fails, the launcher immediately terminates and reports a deterministic, machine-readable error exit code or failure payload over a dedicated supervisor sync pipe *prior* to `execve("python3")`.
       - Clean closure of the sync pipe with an explicit success handshake confirms verified sandbox establishment before the daemon accepts turns.

### SEC-REQ-09: IPC Protocol & Lifecycle Compatibility
* **Statement**: Sandbox enforcement must not degrade existing M9 lifecycle guarantees.
* **Requirements**:
  1. Low-descriptor safety ($\ge 3$) and standard input handoff on FD 0 must continue to function seamlessly.
  2. Emergency parent-death containment (`PR_SET_PDEATHSIG(SIGKILL)`) must remain active.
  3. The supervisor's signal-multiplexed wait loop (`signalfd`) and four-stage shutdown ladder (EOF $\to$ SIGTERM $\to$ SIGKILL $\to$ `waitpid`) must execute without hanging or zombie leaks.
  4. Max IPC frame bound of 512 KiB and NDJSON streaming performance must be preserved.

### SEC-REQ-10: Platform Compatibility & Safe Refusal Policy
* **Statement**: The supervisor must dynamically probe kernel capabilities and fail safely on unsupported systems.
* **Requirements**:
  1. **Runtime Probing vs. Kernel Version Inference**:
     - The supervisor must probe Landlock ABI support dynamically at runtime via `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)` rather than inferring ABI support from kernel version strings alone (accounting for vendor distributions, backports, or disabled LSM configurations).
     - **Runtime Baseline Probed**: On the target development environment (Linux 6.8.0-1070-azure), the runtime probe returns Landlock **ABI v4**. Upstream Linux 6.8 introduced ABI v4; ABI v5 was merged in Linux 6.10.
  2. **Configurable Platform Security Policy**:
     - `SandboxingMode::Enforce` (Default / Production): Refuses worker startup (`SupervisorError::SandboxUnavailable`) if required kernel primitives (Landlock, Seccomp, or mandatory cgroup controls) are unsupported.
     - `SandboxingMode::Permissive` (Development / Test): Allows execution on legacy kernels with loud warnings and explicit state tracking (`WorkerStatus::RunningDegradedIsolation`).

---

## 3. Evaluation of Candidate Isolation Mechanisms

### 3.1 Linux Landlock LSM
* **Mechanism**: Unprivileged Linux Security Module enforcing filesystem access controls via rulesets attached to the calling process.
* **ABI Version Compatibility & Upstream Timeline**:
  - **ABI v1 (Linux 5.13)**: Initial release; basic file read/write, directory creation, deletion.
  - **ABI v2 (Linux 5.19)**: Adds file reparenting (`LANDLOCK_ACCESS_FS_REFER`).
  - **ABI v3 (Linux 6.2)**: Adds file truncation (`LANDLOCK_ACCESS_FS_TRUNCATE`).
  - **ABI v4 (Linux 6.5 / 6.8)**: Adds network TCP port bind and connect control (`LANDLOCK_ACCESS_NET_BIND_TCP`, `LANDLOCK_ACCESS_NET_CONNECT_TCP`).
  - **ABI v5 (Linux 6.10)**: Adds device ioctl restriction (`LANDLOCK_ACCESS_FS_IOCTL_DEV`).
  - *Landlock ABI 8 & TSYNC*: Landlock ABI 8 introduced `LANDLOCK_RESTRICT_SELF_TSYNC` to synchronize rules across existing threads, and is available from Linux 7.0.
* **Actual Runtime Probe Result**:
  - Probed directly on development host: `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)` returns **4**. Upstream Linux 6.8 provides ABI v4; ABI v5 requires Linux 6.10+.
* **Thread Synchronization Strategy**:
  - Because `LANDLOCK_RESTRICT_SELF_TSYNC` is only available from Linux 7.0 (ABI 8) and is absent on kernels providing ABI v1–v5 (including our probed Linux 6.8 development environment), `landlock_restrict_self` applies only to the calling thread and future children on those systems.
  - **Evaluation & Architecture**: Applying Landlock in a multi-threaded Python runtime without ABI 8 would fail to protect existing sibling threads. Therefore, the single-threaded trusted launcher (`aurora-worker-launcher`) remains our baseline architectural approach: Landlock **must be applied within the single-threaded trusted launcher before `execve("python3")` and before any secondary worker threads exist**. This ensures that all threads subsequently created by Python or native extensions inherit the launcher's Landlock domain regardless of kernel version. On platforms where runtime probing confirms ABI $\ge 8$, `LANDLOCK_RESTRICT_SELF_TSYNC` will be leveraged as an optional defense-in-depth capability.
* **Verdict**: **Primary mechanism for filesystem confinement.**

### 3.2 Seccomp-BPF (System Call Filtering)
* **Mechanism**: Berkeley Packet Filter program executed on every system call, returning `SECCOMP_RET_ALLOW`, `SECCOMP_RET_ERRNO(EPERM)`, or `SECCOMP_RET_KILL_PROCESS`.
* **Availability**: Linux $\ge 3.5$; universal across modern Linux distributions and container environments.
* **Design Strategy**:
  - To prevent breaking dynamic linking or runtime initialization, Seccomp must be installed either:
    1. By a trusted launcher binary immediately before `execve("python3")`, where `execve` is permitted once, or
    2. In a staged launcher sequence where all required shared libraries are loaded before the filter is sealed.
  - Multi-thread enforcement requires `SECCOMP_FILTER_FLAG_TSYNC`.
* **Verdict**: **Primary mechanism for syscall restriction and network blocking.**

### 3.3 Linux Namespaces & The Trusted Launcher Evaluation
* **Namespace Setup Nuances**:
  - **Creating vs. Moving**: Creating a namespace requires `clone(flags)` or `unshare(flags)`. Moving an existing process into a namespace requires `setns(fd, nstype)`.
  - **Unprivileged User Namespaces (`CLONE_NEWUSER`)**: While standard in modern kernels, some enterprise distributions disable unprivileged user namespaces via `kernel.unprivileged_userns_clone = 0` or AppArmor profiles.
  - **PID Namespaces (`CLONE_NEWPID`) & `/proc`**:
    - Calling `unshare(CLONE_NEWPID)` does not place the caller into the new namespace; it causes subsequently created child processes to enter the new PID namespace, with the first child becoming PID 1.
    - If `/proc` is not remounted, the child still sees host PIDs. The launcher must configure a private mount namespace (`CLONE_NEWNS`) and mount a fresh `procfs` instance for the child.
* **The Trusted Launcher Evaluation**:
  - Relying on the supervisor's `pre_exec` hook to configure complex namespaces, Landlock rulesets, and Seccomp filters introduces severe liabilities: Rust's `pre_exec` must be strictly async-signal-safe (no heap allocations, no locks, no complex string manipulation).
  - **Recommended Architecture**: A standalone native binary (`aurora-worker-launcher`) executed by the supervisor:
    ```
    WorkerSupervisor -> fork() -> pre_exec (minimal) -> execve("aurora-worker-launcher")
                            │
                            ▼
              [aurora-worker-launcher (Trusted Native C/Rust)]
              1. Close unapproved descriptors (close_range; FD 0, 1, 2 only)
              2. Apply Landlock ruleset while strictly single-threaded (ABI v4)
              3. Unshare PID & mount namespaces; mount private /proc
              4. Configure Seccomp-BPF filter (allowlist + TSYNC)
              5. Set PR_SET_NO_NEW_PRIVS and PR_SET_DUMPABLE(0)
              6. Signal supervisor over sync pipe of verified sandbox readiness
              7. Fork child into new PID namespace -> execve("python3", ["-m", "worker.main"])
                            │
                            ▼
              [AI Worker (Python - Untrusted Execution)]
              * Starts already confined by kernel
              * Cannot escape, trace host processes, or access arbitrary host state
    ```
* **Verdict**: **The trusted launcher architecture is recommended for detailed design in Milestone 10b.**

### 3.4 Cgroup v2 vs. POSIX `setrlimit`
* **Mechanism Comparison**:
  - `RLIMIT_NPROC`: Evaluated against the calling user's UID globally. **Unsafe for per-worker isolation** in shared-UID environments.
  - `cgroup v2`: Provides true per-tree hierarchical control (`pids.max`, `memory.max`, `cpu.max`).
* **Verdict**: **Use cgroup v2 for tree-level process, memory, and CPU bounds where available; use POSIX rlimits (`RLIMIT_CORE`, `RLIMIT_NOFILE`, `RLIMIT_FSIZE`) as baseline defensive guards.**

---

## 4. Operational Environment & Path Mapping

To decouple requirements from the temporary development environment, paths are categorized by functional role:

| Path Functional Role | Development Mapping (Codespace) | Deployment Mapping (Systemd / Desktop) | Confinement Permission |
| :--- | :--- | :--- | :--- |
| **Worker Application Code** | `/workspaces/auroraos/worker` | `/usr/lib/aurora-ai/worker` | **Read-Only** (Execute / Read File) |
| **Python Standard Library** | `/opt/conda/lib/python3.x`, `/usr/lib/python3.x` | `/usr/lib/python3.x`, `/usr/local/lib/python3.x` | **Read-Only** (Read File / Read Dir) |
| **Dynamic Linker & Shared Libs** | `/lib/x86_64-linux-gnu`, `/lib64` | `/usr/lib`, `/lib64`, `/usr/lib64` | **Read-Only** (Execute / Read File) |
| **Worker Scratch / Cache** | `/tmp/aurora-worker-scratch-[pid]` | `$XDG_RUNTIME_DIR/aurora-ai/scratch` or `tmpfs` | **Read-Write** (Create, Read, Write, Unlink) |
| **User Home Directory** | `/home/codespace` | `/home/<user>` | **DENIED** (No Access) |
| **System Secret Paths** | `/etc/shadow`, `/root`, `/etc/sudoers` | `/etc/shadow`, `/root`, `/etc/sudoers` | **DENIED** (No Access) |
| **Host Temp & Shared Memory** | `/tmp` (ambient), `/dev/shm` | `/tmp`, `/dev/shm` | **DENIED** (Isolated to worker scratch) |

---

## 5. Traceability to Subsequent Milestone Deliverables

This specification establishes the authoritative requirements for the remaining Milestone 10 sub-milestones:

* **Milestone 10a (Threat Model & Security Requirements)**: Complete with the delivery of [Worker Threat Model](worker-threat-model.md) and this requirements document.
* **Milestone 10b (Sandbox Architecture & Design)**:
  - Design of the `aurora-worker-launcher` native binary and execution flow.
  - Landlock ruleset construction, ABI fallback handling, and path resolution algorithms.
  - Seccomp-BPF filter generation and syscall allowlist specification.
  - Cgroup v2 integration and systemd scope delegation design.
* **Milestone 10c (Sandbox Implementation)**:
  - Implementation of the launcher and supervisor integration.
  - Implementation of external verification routines (`/proc/<pid>/status` checking).
  - Configuration of restricted scratch directory lifecycle.
* **Milestone 10d (Adversarial Testing & Security Audit)**:
  - Adversarial test harness executing inside the confined worker to verify:
    - Attempted reads of `$HOME` and `/etc` return `EACCES`.
    - Attempted writes outside scratch return `EACCES`.
    - Attempted network socket creation returns `EPERM`.
    - Attempted `fork()` beyond cgroup limit fails.
    - Attempted `execve()` fails.
  - Full audit of descriptor leaks and regression testing across all existing capabilities.
