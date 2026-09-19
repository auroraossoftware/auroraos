# ADR-001: Core Daemon Language, Initial Worker Runtime, and Process Boundary

* **Status:** Proposed
* **Date:** 2026-09-19
* **Deciders:** Aurora OS Architecture Team

---

## 1. Problem
Aurora OS requires a central system service (`aurora-ai`) to provide controlled AI capabilities across the desktop platform, mediate permissions, and interact with underlying model runtimes.

The project must establish:
1. The programming language for the `aurora-ai` core system daemon.
2. The runtime environment for the initial AI worker.
3. The IPC boundaries separating applications, the core daemon, and the model worker.
4. The strategy for client tools and inference runtimes during the MVP phase.

## 2. Context
As documented in [`docs/architecture-variants/architecture-v1`](../architecture-variants/architecture-v1):
* **Linux First & Fault Isolation (Principles 3.1 & 3.2):** Aurora runs on standard Linux. If an AI model crashes or hangs, the operating system and system services must continue functioning uninterrupted.
* **Worker Isolation (Section 11):** The model execution runtime must be isolated from the system daemon in a separate process to contain memory leaks, crashes, and resource spikes.
* **Tiered IPC Architecture (Section 15):** 
  * Aurora desktop and user applications communicate with system services using standard Linux desktop IPC (**D-Bus**).
  * High-frequency, dedicated internal service communication should use private mechanisms such as **Unix domain sockets**.
* **Language Strategy (Sections 49 & 50):** Long-running core services benefit from memory safety and low overhead (Rust), while AI experimentation moves rapidly in Python. The model runtime must not dictate the language of the core OS.
* **MVP Scope (Section 55 & 57):** The MVP must prove the core architectural concepts without premature dependencies on specific hardware (e.g., CUDA) or complex distributed frameworks.

## 3. Decision
For the Aurora OS MVP:

1. **Core System Daemon (`aurora-ai`): Rust**
   * Implemented in Rust as a long-running, memory-safe system daemon.
   * Responsible for OS integration (`systemd`), managing permissions and policy, client request routing, and supervising the lifecycle of worker processes.

2. **AI Worker / Model Runtime: Python (Initially)**
   * Implemented initially in Python as an isolated, unprivileged child process dedicated solely to model loading and inference execution.

3. **Two-Tier IPC Architecture:**
   * **System-Level / Public IPC: D-Bus**
     * Applications, desktop shell components, and external services communicate with `aurora-ai` over D-Bus.
     * Integrates with standard Linux desktop conventions, access controls, and service discovery.
   * **Private Internal IPC: Unix Domain Socket**
     * Communication between the `aurora-ai` core daemon and the isolated AI worker process occurs over a dedicated, private Unix domain socket.
     * The core daemon acts as the supervisor; the worker does not expose its socket to the rest of the system.

4. **Worker Replaceability via Stable Internal Protocol**
   * The Python worker is decoupled behind the private Unix domain socket boundary.
   * A stable, versioned protocol contract will govern daemon ↔ worker communication, ensuring the Python worker can be replaced in the future (e.g., with a native C++ or Rust runtime like llama.cpp, Candle, or ONNX Runtime) without redesigning or recompiling the `aurora-ai` daemon or changing client-facing APIs.

5. **Language-Agnostic Client Tools**
   * Client utilities, CLI tools, and desktop integration helpers may be written in whatever language is most appropriate (Rust, Python, shell scripts), consuming the public D-Bus interfaces.

6. **No CUDA or Specific Model Runtime Yet**
   * To prevent premature hardware lock-in and excessive environment complexity, the MVP will not introduce CUDA or mandate a specific production model runtime.
   * Initial validation will use a lightweight CPU runtime or stub/mock provider to test the plumbing, IPC contracts, and failure handling.

## 4. Rationale
* **Rust for Core Daemon:** Provides memory safety, deterministic resource usage, zero-cost abstractions, and robust Linux systems primitives (systemd, async I/O, D-Bus bindings) without garbage collection pauses.
* **Python for Initial Worker:** Maximizes development velocity, leverages the vast ML ecosystem for early exploration, and keeps heavy AI dependencies completely outside the OS daemon.
* **Strict Two-Tier IPC Separation:**
  * D-Bus provides standard desktop discovery, introspection, and policy enforcement for clients.
  * Private Unix domain sockets provide low-overhead, local-only, direct streaming between daemon and worker without exposing raw worker endpoints to user applications.
* **Process Boundary over In-Process FFI:** Python crashes, GIL bottlenecks, or memory fragmentation cannot destabilize the `aurora-ai` daemon. Unhealthy workers can be terminated and restarted by the daemon supervisor.
* **Deferring CUDA:** Keeps the build environment lightweight, testable on any Linux CPU machine (including CI/containers), and driver-independent during initial development.

## 5. Alternatives Considered
* **Monolithic Python Daemon & Worker:** Rejected due to GIL bottlenecks, higher memory footprint, and lack of fault containment (an inference crash would kill the entire system daemon).
* **Pure Rust Daemon with In-Process Inference:** Rejected for MVP because an inference engine crash would crash the core daemon, and in-process bindings add compilation overhead and friction during early model experimentation.
* **Pure C/C++ Implementation:** Rejected due to lack of memory safety for a core daemon handling untrusted application inputs.
* **D-Bus for Worker Communication:** Rejected because internal daemon-to-worker streaming and lifecycle control does not require desktop-wide discovery and benefits from a private, point-to-point Unix domain socket.

## 6. Consequences & Trade-offs
### Positive
* Clear separation of responsibilities: systems programming (Rust) vs. AI runtime (Python).
* Fault containment: worker crashes do not impact daemon availability.
* Future-proof: the Python worker is swappable without core redesign.
* Accessible development: no GPU or proprietary drivers required to build and test the MVP.

### Negative & Trade-offs
* Multi-language repository tooling (Cargo and Python packaging).
* Requires careful definition and maintenance of the private IPC protocol between daemon and worker.

## 7. Reconsideration Criteria
This decision will be reconsidered if:
1. The Python worker's memory overhead or cold-start latency is prohibitive on targeted hardware profiles.
2. The Unix domain socket IPC introduces measurable throughput bottlenecks for local inference streaming.
3. A stable, production-ready native inference engine (in Rust or C++) is selected, enabling replacement of the Python worker.
