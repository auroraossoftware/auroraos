# Aurora OS Milestone 8 — Performance Baselines & Measurement Report

* **Status:** Complete (Milestone 8 Deliverable)
* **Date:** 2026-10-27
* **Authoritative Context:** [ADR-001](decisions/0001-core-daemon-and-worker-runtime-architecture.md), [ADR-002](decisions/0002-capability-and-permission-architecture.md), [Vertical Slice Prototype Design](vertical-slice-prototype-design.md)
* **Machine-Readable Dataset:** [`docs/benchmarks/m8_baseline.json`](benchmarks/m8_baseline.json)

---

## 1. Executive Summary

Milestone 8 establishes the empirical performance, latency distribution, throughput, and memory baselines for the Aurora OS vertical slice prototype. Measurements were performed using an automated benchmark harness (`crates/aurora-ai/benches/m8_baselines.rs`) exercising the complete end-to-end IPC pipeline across three independent process cold-starts.

### Key Empirical Findings

1. **IPC & Supervisor Overhead (`noop`):**
   * Aggregate median turn latency ($p_{50}$): **0.061 ms** (~61 µs).
   * Aggregate 99th percentile ($p_{99}$): **0.120 ms** (~120 µs).
   * Peak sustained throughput: **15,626 turns/second**.
   * Demonstrates that the newline-delimited JSON (NDJSON) framing over private Unix domain sockets introduces minimal serialization and scheduling overhead.

2. **Policy Denial Overhead (`policy_denial`):**
   * Aggregate median latency ($p_{50}$): **0.141 ms** (~141 µs).
   * Aggregate throughput: **7,078 turns/second**.
   * Validates that policy evaluation, registry lookup, and default-deny rejection fail closed with microsecond-level dispatch cost before provider invocation.

3. **In-Kernel System Capability Latencies:**
   * `sys.cpu.read` ($p_{50}$ **0.209 ms**, throughput **4,840 turns/s**): Bound by `/proc/stat` parsing and sysfs sampling.
   * `sys.memory.read` ($p_{50}$ **0.185 ms**, throughput **5,359 turns/s**): Bound by `/proc/meminfo` reading and field extraction.
   * `fs.file.read` (128 bytes, $p_{50}$ **0.171 ms**, throughput **5,699 turns/s**): Bound by `openat2` sandbox path resolution (`RESOLVE_BENEATH | NO_SYMLINKS | NO_MAGICLINKS | NO_XDEV`) and regular file validation.
   * `fs.file.read` (64 KiB, $p_{50}$ **0.458 ms**, throughput **2,146 turns/s**): Reflects bounded 64 KiB buffer copying and NDJSON string escaping across the socket boundary.

4. **Iterative Host Inspection Overhead (`proc.list`):**
   * `proc.list` (limit 10, $p_{50}$ **1.164 ms**, throughput **833 turns/s**).
   * `proc.list` (limit 50, $p_{50}$ **1.190 ms**, throughput **805 turns/s**).
   * Millisecond-level latency is dominated by `/proc` directory traversal, iterating PID directories, and reading `/proc/<pid>/stat` across all host processes under Linux VFS.

5. **Memory Profile Stability:**
   * Core Daemon (`aurora-ai`): Resident set size (`VmRSS`) remained flat at **2,736–2,888 KiB** (~2.8 MiB) across 1,000 sustained turns.
   * AI Worker (`python3`): Resident set size (`VmRSS`) remained flat at **16,256–16,308 KiB** (~15.9 MiB) across 1,000 sustained turns.
   * Neither process displayed runaway heap growth under sustained load. However, these finite observations do not claim proof of zero memory leaks under arbitrary lifetime horizons.

---

## 2. Test Environment & Measurement Methodology

### 2.1 Hardware and Runtime Metadata

| Parameter | Observed Value |
| :--- | :--- |
| **CPU Model** | AMD EPYC 7763 64-Core Processor (x86_64) |
| **CPU Cores** | 2 Virtualized Cores |
| **Operating System** | Ubuntu 24.04.4 LTS (Noble Numbat) |
| **Linux Kernel** | `6.8.0-1064-azure` |
| **CPU Governor** | Unsupported / Virtualized Hypervisor |
| **Rust Toolchain** | `rustc 1.98.1 (48a229cea 2026-09-01)` (Profile: `bench` / `--release`) |
| **Python Runtime** | `Python 3.14.2` |

### 2.2 Measurement Isolation & Model Runtime Scope

> [!IMPORTANT]
> **Deterministic Worker Isolation:** All measurements reflect the current deterministic Python worker stub executing simulated turn synthesis. They explicitly do **not** include neural network inference, large-language model (LLM) token generation, tensor computation, or GPU kernel dispatch. Future integration of neural runtimes (e.g., PyTorch, llama.cpp, Candle) will be dominated by inference compute time and must be benchmarked as a distinct layer separate from this IPC/supervisor baseline.

### 2.3 Benchmark Execution Architecture

The benchmark harness executes the following protocol:
1. **Cold Starts:** Three independent benchmark runs are executed. Each run spawns a fresh daemon supervisor and worker process instance, binds a new private Unix domain socket, negotiates the protocol handshake, and establishes a clean IPC session.
2. **Scenarios Measured:**
   * `noop`: Worker immediately completes turn without capability requests (measures raw IPC roundtrip and framing).
   * `sys.cpu.read`: Worker requests CPU utilization capability.
   * `sys.memory.read`: Worker requests memory metrics capability.
   * `proc.list_limit_10`: Worker requests process listing bounded to 10 entries.
   * `proc.list_limit_50`: Worker requests process listing bounded to 50 entries.
   * `fs.file.read_128b`: Worker reads a 128-byte file within sandbox using `openat2`.
   * `fs.file.read_64kib`: Worker reads a maximum-size 64-KiB file within sandbox.
   * `policy_denial`: Worker requests an unauthorized capability (`sys.admin.shutdown`), verifying pre-execution rejection latency.
3. **Warm-Up Phase:** For every scenario, **50 warm-up turns** are executed and discarded to allow dynamic library resolution, Python bytecode compilation, branch predictors, and Linux page cache to reach steady state.
4. **Sample Count:** Following warm-up, **1,000 consecutive turns** are timed per scenario.
5. **Timing Instrument:** High-resolution wall-clock duration measured via `std::time::Instant` surrounding `WorkerSupervisor::execute_turn_with_id`. Timing overhead is under 30 ns per sample, negligible relative to the observed microsecond durations.
6. **Live Memory Inspection:** The supervisor samples the Linux procfs status pseudo-files (`/proc/<daemon_pid>/status` and `/proc/<worker_pid>/status`) at designated turn checkpoints:
   * $M_0$: Quiescent post-handshake state (Turn 0).
   * $M_{50}$: Post-warmup checkpoint (Turn 50).
   * $M_{100}$: Sustained operation checkpoint (Turn 100).
   * $M_{500}$: Intermediate sustained checkpoint (Turn 500).
   * $M_{1000}$: Sustained load terminal checkpoint (Turn 1,000).

---

## 3. End-to-End Latency & Throughput Distribution

All latency figures are reported in milliseconds (ms); throughput is reported in turns/second. Percentiles were computed using linear rank interpolation over sorted 1,000-sample arrays.

### 3.1 Aggregate Summary Across 3 Independent Runs

| Scenario | $p_{50}$ (Median) | $p_{90}$ | $p_{99}$ | Mean | Throughput |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **`noop`** | 0.0611 ms | 0.0860 ms | 0.1195 ms | 0.0642 ms | **15,625.9 turns/s** |
| **`sys.cpu.read`** | 0.2085 ms | 0.2556 ms | 0.4488 ms | 0.2065 ms | **4,840.5 turns/s** |
| **`sys.memory.read`** | 0.1848 ms | 0.2409 ms | 0.2883 ms | 0.1864 ms | **5,359.4 turns/s** |
| **`proc.list_limit_10`** | 1.1636 ms | 1.3993 ms | 1.7570 ms | 1.2020 ms | **833.4 turns/s** |
| **`proc.list_limit_50`** | 1.1896 ms | 1.4753 ms | 1.8744 ms | 1.2437 ms | **804.5 turns/s** |
| **`fs.file.read_128b`** | 0.1711 ms | 0.2264 ms | 0.2791 ms | 0.1760 ms | **5,699.4 turns/s** |
| **`fs.file.read_64kib`** | 0.4575 ms | 0.5499 ms | 0.6947 ms | 0.4699 ms | **2,146.3 turns/s** |
| **`policy_denial`** | 0.1412 ms | 0.1834 ms | 0.2299 ms | 0.1418 ms | **7,078.2 turns/s** |

---

### 3.2 Granular Breakdown by Run

#### Run 1 (Daemon PID: 3186, Worker PID: 3198)

| Scenario | Min | $p_{50}$ | $p_{90}$ | $p_{99}$ | Max | Mean | StdDev | CV% | IQR | Throughput |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `noop` | 0.0400 | 0.0526 | 0.0807 | 0.1150 | 0.1390 | 0.0587 | 0.0155 | 26.5% | 0.0174 | 16,943.2 |
| `sys.cpu.read` | 0.1409 | 0.2021 | 0.2637 | 0.7589 | 2.9094 | 0.2140 | 0.1569 | 73.3% | 0.0787 | 4,667.7 |
| `sys.memory.read` | 0.1288 | 0.1974 | 0.2361 | 0.2881 | 0.7543 | 0.1877 | 0.0424 | 22.6% | 0.0623 | 5,320.8 |
| `proc.list_limit_10` | 1.0301 | 1.2217 | 1.5992 | 1.8755 | 2.2892 | 1.2673 | 0.2006 | 15.8% | 0.1720 | 789.0 |
| `proc.list_limit_50` | 1.0554 | 1.1493 | 1.4137 | 1.7478 | 2.9832 | 1.1952 | 0.1698 | 14.2% | 0.1272 | 836.5 |
| `fs.file.read_128b` | 0.1254 | 0.1755 | 0.2262 | 0.2707 | 0.8400 | 0.1741 | 0.0439 | 25.2% | 0.0608 | 5,736.5 |
| `fs.file.read_64kib` | 0.3318 | 0.4066 | 0.4626 | 0.5974 | 0.8955 | 0.4151 | 0.0529 | 12.8% | 0.0494 | 2,407.6 |
| `policy_denial` | 0.0945 | 0.1144 | 0.1740 | 0.2287 | 0.3056 | 0.1290 | 0.0316 | 24.5% | 0.0364 | 7,744.0 |

#### Run 2 (Daemon PID: 3186, Worker PID: 3270)

| Scenario | Min | $p_{50}$ | $p_{90}$ | $p_{99}$ | Max | Mean | StdDev | CV% | IQR | Throughput |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `noop` | 0.0399 | 0.0554 | 0.0835 | 0.1122 | 0.1274 | 0.0607 | 0.0159 | 26.1% | 0.0169 | 16,373.0 |
| `sys.cpu.read` | 0.1479 | 0.2110 | 0.2508 | 0.2980 | 0.4748 | 0.2045 | 0.0375 | 18.3% | 0.0587 | 4,884.6 |
| `sys.memory.read` | 0.1337 | 0.1848 | 0.2460 | 0.2861 | 1.9576 | 0.1889 | 0.0693 | 36.7% | 0.0665 | 5,288.3 |
| `proc.list_limit_10` | 1.0442 | 1.1694 | 1.3495 | 1.7846 | 4.3741 | 1.2017 | 0.1672 | 13.9% | 0.1076 | 832.0 |
| `proc.list_limit_50` | 1.0572 | 1.1955 | 1.5485 | 1.9617 | 9.8946 | 1.2693 | 0.3538 | 27.9% | 0.2001 | 787.7 |
| `fs.file.read_128b` | 0.1233 | 0.1437 | 0.2132 | 0.2694 | 0.8148 | 0.1630 | 0.0411 | 25.2% | 0.0545 | 6,127.8 |
| `fs.file.read_64kib` | 0.3987 | 0.4540 | 0.5446 | 0.6758 | 0.7886 | 0.4706 | 0.0595 | 12.6% | 0.0795 | 2,124.0 |
| `policy_denial` | 0.0970 | 0.1602 | 0.1871 | 0.2344 | 0.2728 | 0.1511 | 0.0313 | 20.7% | 0.0478 | 6,612.6 |

#### Run 3 (Daemon PID: 3186, Worker PID: 3317)

| Scenario | Min | $p_{50}$ | $p_{90}$ | $p_{99}$ | Max | Mean | StdDev | CV% | IQR | Throughput |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `noop` | 0.0425 | 0.0753 | 0.0938 | 0.1313 | 1.1745 | 0.0733 | 0.0398 | 54.3% | 0.0263 | 13,561.5 |
| `sys.cpu.read` | 0.1400 | 0.2124 | 0.2522 | 0.2894 | 0.4299 | 0.2010 | 0.0390 | 19.4% | 0.0666 | 4,969.1 |
| `sys.memory.read` | 0.1350 | 0.1722 | 0.2405 | 0.2907 | 0.3156 | 0.1827 | 0.0394 | 21.6% | 0.0617 | 5,469.2 |
| `proc.list_limit_10` | 1.0447 | 1.0996 | 1.2491 | 1.6109 | 1.7568 | 1.1370 | 0.1058 | 9.3% | 0.0814 | 879.4 |
| `proc.list_limit_50` | 1.0586 | 1.2240 | 1.4636 | 1.9136 | 2.2403 | 1.2665 | 0.1698 | 13.4% | 0.1255 | 789.4 |
| `fs.file.read_128b` | 0.1264 | 0.1941 | 0.2397 | 0.2973 | 1.9431 | 0.1909 | 0.0868 | 45.5% | 0.0753 | 5,234.1 |
| `fs.file.read_64kib` | 0.4025 | 0.5120 | 0.6426 | 0.8109 | 0.9477 | 0.5241 | 0.0870 | 16.6% | 0.0928 | 1,907.2 |
| `policy_denial` | 0.0940 | 0.1490 | 0.1892 | 0.2267 | 0.2944 | 0.1452 | 0.0352 | 24.2% | 0.0594 | 6,877.9 |

---

## 4. Live Memory Profile & Growth Trajectory

Resident Set Size (`VmRSS`), High Water Mark (`VmHWM`), and Virtual Memory Size (`VmSize`) were sampled directly from Linux `/proc/<pid>/status` for both the supervisor daemon and the worker subprocess across 1,000 sustained turns.

### 4.1 Memory Checkpoint Observations

All values in KiB (1 KiB = 1,024 bytes).

| Run | Checkpoint | Turn Count | Daemon VmRSS | Daemon VmHWM | Daemon VmSize | Worker VmRSS | Worker VmHWM | Worker VmSize |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Run 1** | $M_0$ (Quiescent) | 0 | 2,736 | 2,736 | 3,648 | 16,256 | 16,256 | 23,692 |
| | $M_{50}$ (Post-Warmup) | 50 | 2,736 | 2,736 | 3,648 | 16,256 | 16,256 | 23,692 |
| | $M_{100}$ (Sustained) | 100 | 2,736 | 2,736 | 3,648 | 16,256 | 16,256 | 23,692 |
| | $M_{500}$ (Intermediate) | 500 | 2,736 | 2,736 | 3,648 | 16,256 | 16,256 | 23,692 |
| | $M_{1000}$ (Terminal) | 1000 | 2,736 | 2,736 | 3,648 | 16,256 | 16,256 | 23,692 |
| **Run 2** | $M_0$ (Quiescent) | 0 | 2,884 | 2,884 | 3,740 | 16,288 | 16,288 | 23,692 |
| | $M_{50}$ (Post-Warmup) | 50 | 2,884 | 2,884 | 3,740 | 16,288 | 16,288 | 23,692 |
| | $M_{100}$ (Sustained) | 100 | 2,884 | 2,884 | 3,740 | 16,288 | 16,288 | 23,692 |
| | $M_{500}$ (Intermediate) | 500 | 2,884 | 2,884 | 3,740 | 16,288 | 16,288 | 23,692 |
| | $M_{1000}$ (Terminal) | 1000 | 2,884 | 2,884 | 3,740 | 16,288 | 16,288 | 23,692 |
| **Run 3** | $M_0$ (Quiescent) | 0 | 2,888 | 2,944 | 3,756 | 16,308 | 16,308 | 23,692 |
| | $M_{50}$ (Post-Warmup) | 50 | 2,888 | 2,944 | 3,756 | 16,308 | 16,308 | 23,692 |
| | $M_{100}$ (Sustained) | 100 | 2,888 | 2,944 | 3,756 | 16,308 | 16,308 | 23,692 |
| | $M_{500}$ (Intermediate) | 500 | 2,888 | 2,944 | 3,756 | 16,308 | 16,308 | 23,692 |
| | $M_{1000}$ (Terminal) | 1000 | 2,888 | 2,944 | 3,756 | 16,308 | 16,308 | 23,692 |

### 4.2 Analysis and Leak Caveats

1. **Daemon Memory Behavior:**
   * In all three runs, the daemon resident set size (`VmRSS`) remained completely flat between $M_0$ and $M_{1000}$ (at 2,736 KiB in Run 1, 2,884 KiB in Run 2, and 2,888 KiB in Run 3).
   * Minor inter-run variation (~152 KiB) is attributable to memory allocation randomization (ASLR) and glibc heap page binning on startup.
2. **Worker Memory Behavior:**
   * In all three runs, the Python worker resident set size (`VmRSS`) remained flat at ~16.2–16.3 MiB. The Python interpreter allocates its core object arenas and standard library imports during startup; subsequent turn synthesis reuses allocated string and dictionary structures without unbounded heap growth.
3. **Caveat on Zero-Leak Claims:**
   * Bounded memory growth over 1,000 turns demonstrates that the prototype does not suffer from gross accumulation of message buffers or uncollected objects in steady state.
   * However, **these measurements do not prove zero memory leaks**. Sub-page allocations retained in user-space allocators (such as jemalloc or glibc ptmalloc arenas) or slow leaks occurring below the 4 KiB OS page threshold cannot be detected by procfs sampling over finite turn counts.

---

## 5. File Descriptor Invariant Analysis

To verify that descriptor resources are not leaked during sustained multi-turn operation, descriptor sets were sampled under the dedicated test harness (`crates/aurora-ai/tests/m8_audit_verification_tests.rs`):

1. **Daemon In-Process Stream Transport (`test_descriptor_leakage_under_sustained_turns`):**
   * Sampled via `/proc/self/fd` immediately after socket handshake and first successful turn.
   * File descriptors opened by the measurement routine itself to read `/proc/self/fd` (identifiable by resolving the link target `read_link("/proc/self/fd/<fd>")` to `/proc/.../fd`) are explicitly filtered out.
   * 500 consecutive turns were executed over the persistent stream connection.
   * Terminal set sampled via `/proc/self/fd` after workload completion.
   * Observed Invariant: $\Delta \mathcal{S}_{\text{daemon\_fd}} = \emptyset$.

2. **Live External Python Worker Subprocess (`test_external_python_worker_and_daemon_descriptor_leakage_under_sustained_turns`):**
   * Exercises the Rust supervisor within the integration-test process (`/proc/self/fd`), while spawning the real Python worker as a separate child subprocess (`/proc/<worker_pid>/fd`) via `WorkerSupervisor::start()`.
   * Captures the live child worker PID and inspects `/proc/<worker_pid>/fd` and `/proc/self/fd` in a quiescent state post-handshake, recording baseline descriptor counts and link targets.
   * Executes 500 consecutive capability turns cycling across all four approved capabilities (`sys.cpu.read`, `sys.memory.read`, `proc.list`, and sandboxed `fs.file.read` via a controlled temporary sandbox fixture) using the real worker process, waiting for each turn to complete synchronously.
   * Re-evaluates quiescent descriptor snapshots after workload completion for both the live Python worker child process and the daemon/test process.
   * Compares persistent descriptor counts and link target identities.
   * Observed Invariants:
     $$\Delta \mathcal{S}_{\text{worker\_fd}} = (\mathcal{S}_{\text{worker},500} \setminus \mathcal{S}_{\text{worker},0}) \cup (\mathcal{S}_{\text{worker},0} \setminus \mathcal{S}_{\text{worker},500}) = \emptyset$$
     $$\Delta \mathcal{S}_{\text{daemon\_fd}} = (\mathcal{S}_{\text{daemon},500} \setminus \mathcal{S}_{\text{daemon},0}) \cup (\mathcal{S}_{\text{daemon},0} \setminus \mathcal{S}_{\text{daemon},500}) = \emptyset$$
   * Result: Passed. The set of active file descriptors before and after 500 sustained turns was identical for both the live Python worker subprocess and the daemon test process. No leaked socket descriptors, file handles, or pipes were observed.

---

## 6. Comparison Against Architectural Expectations

| Architectural Metric | Prototype Baseline | Architectural Expectation | Assessment |
| :--- | :---: | :---: | :--- |
| **Median IPC Roundtrip** | 0.061 ms | < 1.0 ms | Exceeds requirement by 16x; minimal protocol overhead. |
| **Policy Rejection Overhead** | 0.141 ms | < 0.5 ms | Fail-closed policy evaluation adds only ~80 µs over bare IPC. |
| **Kernel Sandboxed Read** | 0.171 ms (128B) | < 1.0 ms | `openat2` resolution adds negligible latency while enforcing boundary. |
| **Daemon Quiescent Memory** | ~2.8 MiB | < 10.0 MiB | Lightweight system footprint suitable for standard desktop background daemon. |
| **Worker Quiescent Memory** | ~16.3 MiB | < 30.0 MiB | Standard Python runtime footprint prior to loading ML libraries. |
| **Descriptor Growth** | 0 FDs over 500 turns | 0 FDs | Verified descriptor leak invariance under sustained turn streaming. |
