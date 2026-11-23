# ADR-004: Operating-System-Level Sandboxing and Confinement for AI Worker Processes

* **Status:** Accepted
* **Date:** 2026-11-23
* **Deciders:** Aurora OS Architecture & Security Engineering
* **Consulted:** Systems Engineering, Platform Security, Core Daemon Engineering
* **Related ADRs:**
  - [ADR-001: Core Daemon Language, Initial Worker Runtime, and Process Boundary](0001-core-daemon-and-worker-runtime-architecture.md)
  - [ADR-002: Capability and Permission Architecture](0002-capability-and-permission-architecture.md)
  - [ADR-003: Anonymous Socketpair IPC Transport](0003-socketpair-ipc-transport.md)
* **Authoritative Specifications:**
  - [Milestone 10b Sandbox Architecture and Design Specification](../architecture/m10b-sandbox-design.md)
  - [AI Worker Threat Model](../security/worker-threat-model.md)
  - [Worker Security & Sandbox Requirements](../security/worker-sandbox-requirements.md)

---

## 1. Problem

Under ADR-001 and ADR-002, Aurora OS incorporates artificial intelligence as an untrusted, unprivileged guest service. The core daemon (`aurora-ai`) mediates all privileged capability requests over an anonymous Unix domain socketpair (ADR-003), formatted as newline-delimited JSON.

However, in Milestones 1 through 9, the underlying Python AI worker process executed as an unconfined operating system process sharing the invoking user's User ID (`UID`) and Group ID (`GID`). At the operating-system layer, the worker retained full ambient authority:
1. **Unrestricted Host VFS Access**: Ambient read/write access to the user's home directory (`~/.ssh`, `~/.bashrc`, browser profiles, confidential documents) and system paths.
2. **Ambient Network Access**: Outbound socket creation to external networks or local loopback services, enabling command-and-control exfiltration.
3. **Cross-Process Interference**: Visibility and signaling of sibling processes via `/proc`, vulnerable to `ptrace` inspection or memory scraping.
4. **Unbounded Resource Consumption**: Susceptibility to fork-bombs and uncontrolled memory consumption, threatening system stability.
5. **Direct Capability Bypasses**: Bypassing capability mediation by directly reading system files such as `/proc/stat` and `/proc/meminfo`.

If an attacker achieves Arbitrary Code Execution (ACE) within the Python worker (via prompt injection, malicious model weights, memory corruption in native neural acceleration libraries, or compromised dependencies), software-level guardrails inside Python are completely bypassed.

Aurora OS requires an operating-system-enforced security boundary that prevents a fully compromised worker from accessing host resources or bypassing the core daemon's capability architecture.

---

## 2. Context

* **Milestone 10 Security Invariant**: *"If the Python AI worker is completely compromised, it must not gain unrestricted access to the host system. It must operate within an explicitly defined, operating-system-enforced security boundary."*
* **Security Requirements (M10a)**: Formalized in `docs/security/worker-sandbox-requirements.md` as ten mandatory requirements (SEC-REQ-01 through SEC-REQ-10).
* **Target Environment & Probed Kernel**: Probed on `Linux 6.8.0-1070-azure`. Supports unprivileged user namespaces (`unprivileged_userns_clone = 1`), Landlock ABI v4, and Seccomp-BPF. Modern production targets (Ubuntu 24.04+, Fedora 40+) run systemd with cgroup v2. Containerized developer environments (e.g. GitHub Codespaces / Docker) lack systemd as PID 1.
* **IPC Transport Contract (ADR-003)**: Worker communication is strictly conducted over a pre-connected, anonymous Unix stream socketpair passed via file descriptor, bounded by a 512 KiB frame limit.

---

## 3. Decision

Adopt **Option C: Hybrid Architecture — Native Rust Trusted Launcher + Systemd-Assisted Cgroup v2 Resource Management** as the operating-system-level sandbox architecture for the Aurora OS AI worker.

### 3.1 Three-Tier Process Hierarchy and Proxy Supervision
Establish a three-tier process model:
$$\text{aurora-ai (WorkerSupervisor)} \longrightarrow \text{aurora-worker-launcher} \longrightarrow \text{Python AI Worker (PID 1)}$$

1. **`WorkerSupervisor` (`aurora-ai`)**: Directly spawns and supervises `aurora-worker-launcher` ($P_{launch}$) using `std::process::Child`. Manages IPC over socketpair, conducts lifecycle state transitions, and executes the shutdown escalation ladder.
2. **`aurora-worker-launcher`**: A dedicated, minimal standalone native Rust executable. Executes strictly on a single operating-system thread. Establishes namespaces, builds the rootfs, applies security filters, forks the worker child, and blocks in `waitpid()` to act as an unprivileged reaper proxy, mirroring worker exit codes and signals to the supervisor.
3. **Python AI Worker**: Forks into a new PID namespace as **PID 1**. Executes trusted bootstrap, applies Seccomp Stage 2 execution sealing, registers a `SIGTERM` handler, and serves inference requests over the inherited socketpair.

### 3.2 Linux Namespaces Isolation
Isolate the worker using four Linux namespaces:
1. **User Namespace (`CLONE_NEWUSER`)**: Operates rootless. Denies `setgroups`, maps the host user to container UID/GID 1000, and drops all capability sets (`effective`, `permitted`, `inheritable`, `bounding`, `ambient`).
2. **Network Namespace (`CLONE_NEWNET`)**: Created with zero network interfaces. Loopback interface (`lo`) is deliberately left **DOWN**. Network socket creation is blocked.
3. **PID Namespace (`CLONE_NEWPID`)**: Worker child enters as PID 1. Hides all host and sibling processes. Uncaught termination of PID 1 cleans up all child tasks.
4. **Mount Namespace (`CLONE_NEWNS`)**: Worker child creates an independent mount namespace (`unshare(CLONE_NEWNS)`) decoupled from the launcher. Propagation is set to `MS_REC | MS_PRIVATE`.

### 3.3 Minimal Root Filesystem and Atomic `pivot_root`
Construct a minimal, detached root filesystem:
1. Mount a private tmpfs root (`size=64M,mode=0755,nosuid,nodev`).
2. Mount read-only bind mounts (`MS_RDONLY | MS_NODEV | MS_NOSUID`) on `/usr`, `/lib`, `/lib64`, and the application root `/app`.
3. Mount a minimal `/dev` tmpfs containing only bind-mounted `/dev/null`, `/dev/zero`, `/dev/urandom`, and symlinked `random -> urandom`.
4. Mount private scratch storage at `/tmp` (`size=128M,mode=0700,nosuid,nodev,noexec`).
5. Execute `pivot_root`, `chdir("/")`, and `umount2("/put_old", MNT_DETACH)` to completely detach the host filesystem.

### 3.4 Private Procfs and Telemetry Protection
Mount procfs inside the worker's mount namespace using `subset=pid`:
`mount("proc", "/proc", "proc", MS_NODEV | MS_NOSUID | MS_NOEXEC, "subset=pid")`
- Top-level host telemetry files (`/proc/stat`, `/proc/meminfo`, `/proc/cpuinfo`) do not exist and return `ENOENT`.
- **Strict Safe Refusal**: If `subset=pid` is unsupported by the kernel, strict production mode **refuses startup** (`ERR_PROCFS_SUBSET_PID_UNSUPPORTED`). Strict mode never falls back to unrestricted procfs.

### 3.5 Landlock LSM Filesystem Confinement
Apply Landlock rulesets targeting probed **ABI v4** (Linux 6.8 baseline):
1. **Handled Rights**: Explicitly define all 15 filesystem access rights and 2 TCP network rights supported in ABI v4.
2. **Scoped Execution**: `LANDLOCK_ACCESS_FS_EXECUTE` is granted **strictly and exclusively** to `/usr/bin/python3` and the dynamic linker `/lib64/ld-linux*`. Execution from `/tmp`, `/dev`, or library paths is explicitly denied.
3. **Read-Only Paths**: Granted to `/lib`, `/lib64`, `/usr/lib`, and `/app`.
4. **Writable Paths**: Restricted strictly to `/tmp` (scratch) and `/dev/null`.
5. **Single-Threaded Baseline**: The launcher applies Landlock rulesets before any worker threads exist, ensuring full compatibility on kernels lacking ABI 8 `TSYNC`.

### 3.6 Progressive Two-Stage Seccomp-BPF Policy
Enforce syscall filtering in two cumulative stages:
1. **Architecture & ABI Validation**: Every filter verifies `arch == AUDIT_ARCH_X86_64` and unconditionally kills syscalls carrying `__X32_SYSCALL_BIT` (`0x40000000`).
2. **Stage 1 (Pre-Exec Launcher Filter)**:
   - Returns `SECCOMP_RET_ERRNO(ENOSYS)` on `SYS_clone3` (forcing glibc fallback to classic `clone`).
   - Filters `SYS_clone`: verifies upper 32 bits are zero, mandates `CLONE_THREAD | CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_SYSVSEM`, blocks prohibited flags (`CLONE_NEW*`), and requires exit signal 0.
   - Denies `io_uring` (`io_uring_setup`, `io_uring_enter`, `io_uring_register`).
   - Denies `SYS_socket`, `SYS_socketpair`, `SYS_connect`, `SYS_bind`, `SYS_listen`, `SYS_accept`.
   - Denies `SYS_sendmsg`, `SYS_sendmmsg`, `SYS_recvmsg`, `SYS_recvmmsg` (preventing `SCM_RIGHTS` descriptor smuggling).
3. **Stage 2 (Post-Bootstrap Interpreter Seal)**:
   - Applied by `aurora_seal` in `bootstrap.py` with `SECCOMP_FILTER_FLAG_TSYNC`.
   - Permanently maps `SYS_execve` and `SYS_execveat` to `SECCOMP_RET_KILL_PROCESS`.
   - Execution of external binaries is completely disabled before application modules or models are loaded.

### 3.7 Python Trusted Bootstrap
Launch Python in isolated mode without site initialization or bytecode writing:
`/usr/bin/python3 -I -S -B /app/worker/bootstrap.py`
- Bypasses global `.pth` files and site hooks (`-S`).
- `bootstrap.py` loads `aurora_seal` native extension directly via modern `importlib.util` APIs (`spec_from_file_location`, `module_from_spec`, `exec_module`) from `/app/worker/aurora_seal.so`.
- Applies Stage 2 Seccomp seal.
- Registers PID 1 `SIGTERM` handler (`signal.signal(SIGTERM, ...)`).
- Initializes application runtime and sends `HandshakeResponse`.

### 3.8 Resource Management & Dual-Mode Policy
1. **Cgroup v2 Containment**:
   - `WorkerSupervisor` attaches the launcher PID to a systemd transient scope via D-Bus (`StartTransientUnit`) before worker creation.
   - Limits: `memory.max = 512M`, `pids.max = 32` (all tasks/TIDs), `cpu.max = 100000 100000` (100% of 1 core).
   - Startup Gate: Launcher blocks on a gate pipe until the supervisor verifies cgroup attachment and controller activation.
2. **Strict Mode (Production Default)**: Requires cgroup v2 and procfs `subset=pid`. Refuses to start if mandatory controls are missing.
3. **Permissive Mode (Development Fallback)**: For containerized environments lacking systemd. Falls back to POSIX resource limits (`RLIMIT_CORE=0`, `RLIMIT_NOFILE=64`, `RLIMIT_FSIZE=100M`) and tmpfs 128M quota. Emits explicit degraded-isolation warnings.

### 3.9 Descriptor Hygiene & Parent-Death Containment
1. **FD Manifest & Cleanup**: Launcher closes worker-side IPC socket (FD 0) post-fork. Worker executes `close_range(10, UINT_MAX, 0)` post-pivot to purge all setup descriptors $\ge 10$. Subsequent closures deterministically eliminate FD 4 (post-gate), FD 6–9 (post-pdeath sync), FD 3 (via `O_CLOEXEC` on `execve`), and FD 5 (post-bootstrap ack). Steady-state Python retains only FD 0 (`/dev/null`), FD 1 (`/dev/null`), FD 2 (stderr log pipe), and FD 3 (active IPC stream).
2. **Two-Way Parent-Death Handshake**: Worker arms `prctl(PR_SET_PDEATHSIG, SIGKILL)` after credential drops, exchanges `TOKEN_ARMED`/`TOKEN_CONTINUE` tokens with launcher over dedicated pipes, closing the fork-to-prctl race without relying on `getppid()`.

---

## 4. Alternatives Considered and Rejected

1. **In-Daemon Launcher (`pre_exec` in `aurora-ai`) [Option A]**:
   - *Rejected*: In a multi-threaded Rust daemon running Tokio and D-Bus, executing non-async-signal-safe operations (allocators, complex mount calls, string parsing) between `fork()` and `execve()` causes deadlocks. Furthermore, Landlock ABI v4 rulesets cannot be applied to multi-threaded processes without ABI 8 `TSYNC`.
2. **External Container Engine / CLI Wrappers (`podman`, `bubblewrap`, `systemd-run --scope`) [Option B]**:
   - *Rejected*: Introduces heavy external runtime dependencies, increases startup latency, and disrupts direct parent-child process ownership, breaking `std::process::Child` exit status capturing and signal escalation.
3. **Cooperative Python In-Process Sandboxing (RestrictedPython, PyCapsule)**:
   - *Rejected*: Software-level sandboxes inside Python provide zero security against ACE, native memory corruption, or raw syscall invocation via `ctypes`.
4. **POSIX `RLIMIT_NPROC` as Primary Task Bound**:
   - *Rejected*: In Linux, `RLIMIT_NPROC` limits processes across the user's *entire real UID system-wide*, not per-worker. Restricting `RLIMIT_NPROC` in unprivileged containers breaks daemon threads. Cgroup v2 `pids.max` is the only safe per-worker task limit.

---

## 5. Rationale

Option C provides the optimal balance of uncompromising kernel-enforced security, minimal overhead, and native Rust integration:
- **Zero Elevated Privileges**: Operates rootless via Linux unprivileged user namespaces (`CLONE_NEWUSER`).
- **Deterministic Confinement Before Execution**: All security boundaries (namespaces, mounts, Landlock, Seccomp) are established prior to running a single line of Python application code.
- **Fail-Safe Shutdown & Reaping**: Preserves the M9 shutdown escalation ladder (200 ms EOF $\to$ 300 ms SIGTERM $\to$ SIGKILL) with immediate namespace teardown upon PID 1 death.
- **Strict Capability Delegation**: Prevents direct telemetry scraping, enforcing that hardware introspection must route through `aurora-ai` capability APIs.

---

## 6. Consequences & Trade-offs

### 6.1 Positive Consequences
* **Defense-in-Depth**: A compromised worker under full ACE cannot read host user files, exfiltrate data over the network, trace host processes, spawn external shells, or flood system memory.
* **Complete Auditability**: Deterministic 4-event startup protocol enables external verification of sandbox readiness before IPC turns commence.
* **Zero Host Pollution**: Rootless tmpfs construction leaves zero residual files on disk upon crash or termination.

### 6.2 Costs and Liabilities
* **Architectural Complexity**: Introduces a new native binary (`aurora-worker-launcher`), a two-stage Seccomp architecture, and a native C sealing module (`aurora_seal`).
* **Kernel Feature Dependency**: Full strict isolation mandates modern Linux features (cgroup v2, Landlock ABI $\ge 4$, procfs `subset=pid`).
* **Debugging Friction**: Once Seccomp Stage 2 is sealed, `gdb`, `strace`, or external inspection of the running worker requires debugging from the host namespace.

### 6.3 Required Mitigations
* Provide explicit error diagnostics when strict mode safely refuses to start.
* Provide permissive development mode with prominent logging for non-systemd container environments.
* Maintain comprehensive unit, lifecycle, and adversarial test suites in M10c and M10d.

---

## 7. Security Implications

* Satisfies all ten security requirements (SEC-REQ-01 through SEC-REQ-10) established in M10a.
* Eliminates the `TIOCSTI` terminal injection vector by redirecting FD 2 to a bounded non-terminal pipe.
* Eliminates `SCM_RIGHTS` descriptor smuggling over IPC by blocking message-based socket system calls.
* Protects internal model state and credentials against external same-UID tracing via `PR_SET_DUMPABLE(0)`.

---

## 8. Compatibility Constraints

* **Host Kernel**: Linux $\ge 6.8$ recommended. Landlock ABI v4 is the minimum supported baseline for filesystem confinement.
* **Init System**: systemd v250+ recommended for cgroup v2 transient scope integration. Permissive fallback supported for non-systemd containers.
* **Python Runtime**: Python 3.10+ required for modern `importlib.util` native extension loading.

---

## 9. Reconsideration Criteria

This architectural decision shall be formally reconsidered if:
1. Linux upstream deprecates unprivileged user namespaces or restricts them by default in major distribution kernels without viable alternatives.
2. Landlock ABI 8 (`LANDLOCK_RESTRICT_SELF_TSYNC`) becomes ubiquitous across 100% of target production and enterprise deployments, potentially simplifying multithreaded filter application.
3. MicroVM runtimes (e.g. Firecracker, Cloud Hypervisor) achieve startup latencies and memory footprints comparable to native Linux namespaces ($\le 20$ ms, $\le 10$ MB overhead).

---

## 10. References

* Architecture Specification: [`docs/architecture/m10b-sandbox-design.md`](../architecture/m10b-sandbox-design.md)
* Threat Model: [`docs/security/worker-threat-model.md`](../security/worker-threat-model.md)
* Sandbox Requirements: [`docs/security/worker-sandbox-requirements.md`](../security/worker-sandbox-requirements.md)
* ADR-001 (Core Daemon & Worker Runtime): [`docs/decisions/0001-core-daemon-and-worker-runtime-architecture.md`](0001-core-daemon-and-worker-runtime-architecture.md)
* ADR-002 (Capability & Permission Architecture): [`docs/decisions/0002-capability-and-permission-architecture.md`](0002-capability-and-permission-architecture.md)
* ADR-003 (Socketpair IPC Transport): [`docs/decisions/0003-socketpair-ipc-transport.md`](0003-socketpair-ipc-transport.md)
