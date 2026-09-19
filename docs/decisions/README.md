# Architecture Decision Records (ADRs)

This directory contains the Architecture Decision Records (ADRs) for **Aurora OS**.

An Architecture Decision Record captures an important architectural decision made on the project, along with the context, alternatives considered, rationale, trade-offs, and consequences.

The ADR process is governed by the principles outlined in [`docs/architecture-variants/architecture-v1`](../architecture-variants/architecture-v1) (Section 56).

---

## Decision Lifecycle

Each ADR transitions through the following statuses:

* **Proposed** — The decision is under review and open for architectural evaluation.
* **Accepted** — The decision has been approved by project deciders and represents project policy.
* **Rejected** — The proposed decision was evaluated and not adopted.
* **Superseded** — The decision was previously accepted but has been replaced by a newer ADR.
* **Deprecated** — The decision is no longer relevant or active.

---

## ADR Format

Each ADR documents:

1. **Problem** — What specific architectural challenge is being addressed?
2. **Context** — What relevant architectural principles, technical constraints, or system requirements inform this decision?
3. **Decision** — What is the exact decision and direction?
4. **Rationale** — Why was this decision made over alternatives?
5. **Alternatives Considered** — What alternative approaches were evaluated, and why were they rejected?
6. **Consequences & Trade-offs** — What are the positive outcomes, costs, liabilities, and required mitigations?
7. **Reconsideration Criteria** — Under what specific conditions should this decision be revisited?

---

## Index of Decisions

| ADR | Title | Status | Date |
| :--- | :--- | :--- | :--- |
| [ADR-001](0001-core-daemon-and-worker-runtime-architecture.md) | Core Daemon Language, Initial Worker Runtime, and Process Boundary | Proposed | 2026-09-19 |
