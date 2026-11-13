# ADR-003: Anonymous Socketpair IPC Transport for Internal Worker Communication

* **Status:** Accepted
* **Date:** 2026-10-27 (Proposed) / 2026-11-13 (Accepted)
* **Deciders:** Aurora OS Architecture Team
* **Consulted:** Systems Engineering, Security Architecture

---

## 1. Problem

The Aurora OS core daemon (`aurora-ai`) communicates with the isolated AI worker process over a private, internal IPC channel. In Milestones 1 through 7, this channel was implemented using filesystem-path Unix domain sockets (`UnixListener::bind(&path)`), defaulting to `/tmp/aurora-ai-{PID}.sock` or an explicit operator `--socket-path`.

As documented in the M7 security findings and the M8 system audit, filesystem pathname sockets have inherent Linux VFS architectural limitations:
1. **Post-Bind Ownership-Capture Race:** Between `UnixListener::bind(&path)` returning and the supervisor inspecting the socket inode, a concurrent same-UID process could unlink the socket and replace it, causing the daemon to validate a substituted entry.
2. **Shutdown Check-Then-Unlink Race:** Between inspecting the socket path on shutdown and issuing `unlink()`, a concurrent same-UID process could swap the socket with an arbitrary file, causing the supervisor to unlink an unintended file. Linux provides no atomic `unlink_if_matches` syscall, and `fstat` on a socket descriptor queries `sockfs` (which diverges from the host filesystem's inode), making atomic path validation impossible.
3. **Stale Sockets on Abrupt Termination:** When a fixed `--socket-path` is configured, abrupt process termination (e.g., `SIGKILL` or unhandled `SIGINT`/`SIGTERM`) leaves an orphaned socket file on disk. Subsequent restarts fail with `EADDRINUSE` until manual administrative cleanup occurs.
4. **Filesystem Permission Dependence:** Protection against unprivileged cross-UID access requires enforcing `0700` permissions on the enclosing directory, which is vulnerable to misconfiguration in deployment environments.

Aurora OS requires an internal IPC transport that eliminates all filesystem pathname races, guarantees point-to-point connection privacy, and cleans up automatically upon process termination.

---

## 2. Context

* **ADR-001 (Core Daemon Language & Process Boundary):** Mandates an isolated process boundary between the Rust core daemon and the Python worker runtime, connected via a private Unix domain socket.
* **Vertical Slice Architecture:** The IPC protocol is stream-oriented, bidirectional, and formatted as newline-delimited JSON (NDJSON).
* **Linux Kernel Primitives:** Linux provides `socketpair(AF_UNIX, SOCK_STREAM, 0)`, which creates an anonymous, connected pair of bidirectional socket descriptors directly in the kernel without touching the VFS namespace.

---

## 3. Decision

Transition the internal daemon ↔ worker private IPC transport from filesystem pathname sockets to **anonymous `socketpair(AF_UNIX, SOCK_STREAM, 0)`**:

### 3.1 Creation and Process Spawning Lifecycle
1. **Socket Creation:** When launching an AI worker, `WorkerSupervisor` calls `UnixStream::pair()`, producing two connected descriptors: `(daemon_stream, worker_stream)`.
2. **Low-Descriptor Safety:** If either allocated descriptor is $\le 2$ (which can happen if the parent process closed stdin, stdout, or stderr), the descriptor is duplicated above descriptor 2 using `fcntl(F_DUPFD_CLOEXEC, 3)` to ensure standard streams cannot collide with IPC handles.
3. **Standard Input Handoff (`Stdio::from(OwnedFd)`):**
   * The `worker_stream` descriptor is passed natively to the child process as standard input (FD 0) using Rust's standard library `Stdio::from(worker_stream)`.
   * Standard output (FD 1) is redirected to `/dev/null` (`Stdio::null()`), and standard error (FD 2) is inherited (`Stdio::inherit()`).
4. **Child Process Configuration & Parent Death Containment:**
   * In Rust, `std::os::unix::process::CommandExt::process_group(0)` assigns the child to its own process group, isolating it from terminal `SIGINT` signals intended for the daemon.
   * Inside `pre_exec`:
     - The daemon supervisor's endpoint descriptor is explicitly closed in the child via `libc::close(daemon_fd)`.
     - Signal masks blocked by the daemon (e.g. for `signalfd`) are reset via `sigprocmask(SIG_SETMASK, &empty_set, NULL)`.
     - Emergency parent-death containment is registered via `libc::prctl(PR_SET_PDEATHSIG, SIGKILL)`.
     - Parent process existence is verified: `if libc::getppid() != parent_pid { return Err(io::Error::from_raw_os_error(libc::EPIPE)); }`.
     - All `pre_exec` operations are strictly async-signal-safe with zero heap allocations.
5. **Python Worker Descriptor Hygiene:**
   * In the worker process (`worker/main.py`), Python instantiates the socket from descriptor 0, closes `old_stdin`, redirects FD 0 to `/dev/null`, and rebinds `sys.stdin` with `closefd=False` to prevent GC from closing reused descriptors:
     ```python
     raw_fd = 0
     sock = socket.fromfd(raw_fd, socket.AF_UNIX, socket.SOCK_STREAM)
     old_stdin = sys.stdin
     if old_stdin is not None:
         old_stdin.close()
     devnull_fd = os.open(os.devnull, os.O_RDONLY)
     if devnull_fd != raw_fd:
         os.dup2(devnull_fd, raw_fd)
         os.close(devnull_fd)
     sys.stdin = open(raw_fd, "r", closefd=False)
     ```
   * This preserves the socket object independently, closes raw descriptor 0, and redirects `sys.stdin` to `/dev/null` to prevent subsequent code from reading standard input.

### 3.2 Protocol and Message Framing Preservation
* The IPC framing and serialization remain **100% identical**:
  * Newline-delimited JSON (NDJSON) over streaming stream sockets (`SOCK_STREAM`).
  * Typed protocol messages (`Handshake`, `HandshakeResponse`, `RequestTurn`, `ProposeCapability`, `CapabilityResult`, `CompleteTurn`) remain unchanged.
  * Version negotiation and directional framing remain active.
  * Maximum IPC frame size of exactly 512 KiB (524,288 bytes) remains strictly enforced.

### 3.3 Worker Lifecycle, Lazy Replacement Recovery & Restart Accounting
* **Deterministic Lifecycle State Machine:** Governed by `WorkerState` (`Uninitialized`, `Starting`, `Ready`, `Busy`, `Recovering`, `Degraded`, `Terminated`).
* **Explicit Health Polling:** `WorkerSupervisor::poll_status()` explicitly propagates `waitpid` errors rather than assuming child health on failure:
  - `Ok(Some(status))`: Worker terminated; child reaped and transitions to `Recovering`.
  - `Ok(None)`: Worker process alive; verifies non-blocking socket health; transitions to `Recovering` on `POLLHUP`.
  - `Err(e)`: Propagates I/O failure explicitly without silent fallback.
* **Lazy Replacement Strategy:** Worker crash detection marks the supervisor as `Recovering`. Child re-spawn, new socketpair allocation, and handshake exchange occur lazily upon the subsequent request turn, avoiding background supervisor threads.
* **Strict 3-Failed-Replacement Bound:**
  - Initial worker launch failure transitions directly to `Terminated` (1/1 attempt budget).
  - Once healthy, a subsequent worker crash triggers recovery without consuming a replacement failure.
  - Exactly three failed replacement attempts transition the supervisor into `Degraded` (`WorkerRestartLimitExceeded`).
  - An incompatible protocol version or handshake rejection transitions directly into `Degraded`.
  - Replacement workers remaining continuously healthy for $\ge 10$ seconds (`healthy_reset_window`) reset the consecutive failure counter to zero.
  - Programmatic operator recovery: `supervisor.reset()` clears degraded state and relaunches the worker.
* **Non-Replay Invariant:** Turns interrupted by worker crashes fail closed immediately with `WorkerTerminatedDuringTurn`, recording completed proposal names and exit codes. Interrupted turns and capability proposals are never silently replayed.

### 3.4 Signal Handling & Orderly Shutdown Escalation
* **Signal-Integrated IPC Waiting (`signalfd`):** The supervisor thread blocks `SIGINT` and `SIGTERM` via `pthread_sigmask` and allocates a dedicated `signalfd`. IPC wait loops monitor both the worker stream and `signalfd` concurrently via `poll()`, achieving sub-millisecond signal wake-up without polling delays.
* **Child Signal Disposition:** In `pre_exec`, the child process unmasks all signals via `sigprocmask(SIG_SETMASK, &empty_set, NULL)` and sets `process_group(0)`, ensuring terminal Ctrl+C signals reach only the daemon while the worker remains responsive to signals delivered by the supervisor.
* **Four-Stage Shutdown Escalation:**
  1. *Stage 1 (Cooperative EOF):* Dropping socket writer and reader handles sends EOF to the worker, waiting up to 200 ms.
  2. *Stage 2 (SIGTERM Escalation):* Delivers `SIGTERM` to the child process group, waiting up to 300 ms.
  3. *Stage 3 (SIGKILL Fallback):* Delivers emergency `SIGKILL` to force termination of unresponsive workers.
  4. *Stage 4 (Mandatory Wait):* Issues blocking `child.wait()` to guarantee zero zombie leaks.

### 3.5 Thread Pinning & Parent-Death Containment Analysis
* **Thread Pinning:** `WorkerSupervisor` captures `owner_thread_id` and is marked non-`Send`/non-`Sync` via `PhantomData<*const ()>`. Worker creation is strictly confined to a single, long-lived supervisor thread.
* **PR_SET_PDEATHSIG Race Boundaries:**
  - Linux `PR_SET_PDEATHSIG` is architecturally tied to the creating *thread*, not the parent process. If a thread exits while the parent process remains alive, the kernel delivers the parent-death signal to the child. Pinning supervisor operations to a long-lived thread prevents unexpected worker death.
  - `getppid()` mismatch checks detect parent process death prior to `prctl()`, but cannot detect creating thread termination if the parent process survives.
  - Honest boundary: Socketpair IPC and `PR_SET_PDEATHSIG` eliminate filesystem socket races and provide best-effort parent death containment; they do not constitute full OS-level process sandboxing or ambient UID authority elimination.

---

## 4. Rationale

1. **Complete Elimination of Filesystem Path Races:**
   * Anonymous sockets do not exist in the VFS hierarchy.
   * There is no filesystem path to bind, probe, inspect, unlink, or swap.
   * Post-bind capture races, symlink substitution, and shutdown check-then-unlink races are structurally impossible.
2. **Deterministic Cleanup and Crash Resilience:**
   * Because the socket exists only as kernel file descriptor references, terminating either process (whether cleanly, via crash, or via `SIGKILL`) immediately closes the descriptor endpoints.
   * The kernel delivers `POLLHUP` / `EOF` to the surviving peer without leaving any stale socket files, temporary files, or directory entries behind.
3. **Point-to-Point Security Invariance:**
   * No third-party process on the system (even processes sharing the daemon's own UID) can connect to or discover the socket via filesystem path scanning. Only the supervisor and its explicitly spawned child hold the descriptors.
4. **Foundation for M9 Worker Restarting:**
   * Under `socketpair`, restarting a crashed worker requires no filesystem cleanup: the supervisor simply calls `UnixStream::pair()` again, spawns a fresh worker child, passes the new descriptor, and resumes operation without touching disk state.

---

## 5. Alternatives Considered

* **Retain Filesystem Sockets with External Mode `0700` Directory:**
  * *Rejected:* While setting directory mode `0700` isolates against cross-UID tampering, it offers zero protection against a compromised process sharing the daemon's UID. Furthermore, it leaves the shutdown check-then-unlink race and stale-socket leftovers unsolved.
* **Linux Abstract Unix Domain Sockets (`\0name`):**
  * *Rejected:* Abstract sockets bypass the filesystem, but they reside in a shared network namespace. Any process in the same network namespace can connect to the abstract name regardless of user permissions, expanding the attack surface unless accompanied by complex `SO_PEERCRED` validation.
* **Dedicated FD 3 Handoff via `dup2`:**
  * *Rejected:* Hard-coding descriptor 3 requires manual `dup2` descriptor juggling in `pre_exec` and risks overwriting application-owned or runtime-internal descriptors. Handoff via `Stdio::from(OwnedFd)` on FD 0 leverages the standard library's native, collision-free descriptor assignment machinery.

---

## 6. Consequences & Trade-offs

### Positive
* Zero filesystem races or stale-inode cleanup bugs under any termination condition.
* No temporary directory permissions or path management required.
* Eliminates pathname-based connection discovery.
* Enables robust lazy worker restart implementation in Milestone 9.

### Negative & Trade-offs
* **Worker Stdin Redirection:** The worker runtime must treat FD 0 strictly as the socket stream and redirect `sys.stdin` to `/dev/null` upon startup.
* **Tooling Observability:** Operators cannot observe the socket connection as a visible file in `/tmp`. Inspection must occur via procfs descriptor tables (`/proc/<pid>/fd/`) or `ss -x`.
* **Not OS Sandboxing:** Socket-pair IPC secures the IPC channel; it does not sandbox the worker process against host filesystem access or OS-level capabilities.

---

## 7. Reconsideration Criteria

This decision should be reconsidered only if:
1. The AI worker is relocated to an external host or distinct network container where Unix descriptor inheritance is impossible, requiring networked TLS/TCP sockets.
2. Linux operating-system support is deprecated in favor of a platform lacking POSIX `socketpair(2)` semantics.
