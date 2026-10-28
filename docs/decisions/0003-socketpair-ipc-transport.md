# ADR-003: Anonymous Socketpair IPC Transport for Internal Worker Communication

* **Status:** Proposed
* **Date:** 2026-10-27
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
1. **Socket Creation:** When launching an AI worker, `WorkerSupervisor` calls `socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)`, producing two connected descriptors: `(daemon_fd, worker_fd)`.
2. **Descriptor Inheritance:**
   * In Rust, `std::os::unix::process::CommandExt` is used to configure the child process:
     * The `worker_fd` descriptor has its `FD_CLOEXEC` flag cleared for the child, or is duplicated to a fixed descriptor (e.g., standard descriptor `3`).
     * The assigned descriptor number is passed to the worker via an environment variable (`AURORA_AI_IPC_FD=3`) or command-line argument (`--ipc-fd 3`).
3. **Descriptor Hygiene:**
   * Immediately following `fork()` / `exec()`, the supervisor closes its copy of `worker_fd` in the daemon process.
   * In the worker process (`worker/main.py`), Python instantiates the socket using:
     ```python
     ipc_fd = int(os.environ["AURORA_AI_IPC_FD"])
     sock = socket.fromfd(ipc_fd, socket.AF_UNIX, socket.SOCK_STREAM)
     os.close(ipc_fd)  # Close the inherited raw descriptor
     ```
   * All other daemon file descriptors retain `O_CLOEXEC` to prevent descriptor leakage into the untrusted worker.

### 3.2 Protocol and Message Framing Preservation
* The IPC framing and serialization remain **100% identical**:
  * Newline-delimited JSON (NDJSON) over streaming stream sockets (`SOCK_STREAM`).
  * Typed protocol messages (`Handshake`, `HandshakeResponse`, `RequestTurn`, `ProposeCapability`, `CapabilityResult`, `CompleteTurn`) remain unchanged.
  * Version negotiation and directional framing remain active.

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
   * No third-party process on the system (even processes sharing the daemon's own UID) can connect to or eavesdrop on the anonymous socketpair. Only the supervisor and its explicitly spawned child hold the descriptors.
4. **Foundation for M9 Worker Restarting:**
   * Implementing worker restart under pathname sockets required managing socket unlinking, file locks, or PID-named files.
   * Under `socketpair`, restarting a crashed worker is trivial: the supervisor simply calls `socketpair()` again, spawns a fresh worker child, passes the new descriptor, and resumes operation without touching disk state.

---

## 5. Alternatives Considered

* **Retain Filesystem Sockets with External Mode `0700` Directory:**
  * *Rejected:* While setting directory mode `0700` isolates against cross-UID tampering, it offers zero protection against a compromised process sharing the daemon's UID. Furthermore, it leaves the shutdown check-then-unlink race and stale-socket leftovers unsolved.
* **Linux Abstract Unix Domain Sockets (`\0name`):**
  * *Rejected:* Abstract sockets bypass the filesystem, but they reside in a shared network namespace. Any process in the same network namespace can connect to the abstract name regardless of user permissions, expanding the attack surface unless accompanied by complex `SO_PEERCRED` validation.
* **In-Process FFI / Dynamic Libraries:**
  * *Rejected:* As established in ADR-001, running Python in-process breaks fault containment; a segmentation fault in an ML dependency would crash the entire operating system daemon.

---

## 6. Consequences & Trade-offs

### Positive
* Zero filesystem races or stale-inode cleanup bugs under any termination condition.
* No temporary directory permissions or path management required.
* Guarantees true point-to-point connection privacy against same-UID tampering.
* Simplifies supervisor restart implementation in Milestone 9.

### Negative & Trade-offs
* **Descriptor Leakage Hygiene:** The supervisor must strictly maintain `O_CLOEXEC` across all daemon descriptors to prevent ambient file descriptors (e.g., database handles, system sockets) from leaking into the child process.
* **Tooling Observability:** Operators cannot observe the socket connection as a visible file in `/tmp`. Inspection must occur via procfs descriptor tables (`/proc/<pid>/fd/`) or `ss -x`.

---

## 7. Reconsideration Criteria

This decision should be reconsidered only if:
1. The AI worker is relocated to an external host or distinct network container where Unix descriptor inheritance is impossible, requiring networked TLS/TCP sockets.
2. Linux operating-system support is deprecated in favor of a platform lacking POSIX `socketpair(2)` semantics.
