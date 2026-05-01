# ADR-0001: Foundational Architecture

- **Status:** Accepted
- **Date:** 2026-05-01
- **Deciders:** Lead architect (cybersec + AI), with multi-expert panel review (red-team, AI/ML, DevSecOps, CTI, compliance)

## Context

We are building the **Automated Agentic RAG Threat Emulation Framework**: an
intelligence-driven adversary-emulation system where an agentic Claude core
ingests live threat intelligence, retrieves relevant context via a hybrid RAG
+ ATT&CK graph, plans an ordered TTP chain, executes selected Atomic Red Team /
Stratus / CALDERA tests inside an isolated lab, and produces an explainable
report - all behind defensive-research-grade guardrails.

This ADR captures the foundational architecture decisions agreed before any
implementation begins. Subsequent ADRs may revisit individual decisions.

## Decisions

### D1 - Unit of emulation = `Campaign`, not individual atomic tests

A flat list of techniques is not adversary emulation. The framework treats a
**`Campaign`** (ordered TTP chain bound to an actor profile and a signed
scope-of-engagement) as the canonical unit of work. Atomic tests are the
backend representation; the agent operates over campaigns.

### D2 - Hybrid retrieval: Qdrant + BM25 + ATT&CK graph

Pure dense embeddings over flattened STIX lose structural information
(`intrusion-set --uses--> attack-pattern`). We combine:

- **Qdrant** (dense vectors) for semantic recall.
- **BM25** (sparse) for keyword precision (CVE IDs, technique IDs).
- **NetworkX** ATT&CK graph for structural traversal (group -> technique ->
  mitigation -> data-source).

The retriever returns chunks plus the graph path, both cited in reports.

### D3 - Two embedding stacks (cloud + local) for TLP routing

Default embedder is `voyage-3` (cloud). For any source tagged
`TLP:AMBER` or higher, the retriever transparently routes through a local
`bge-m3` embedder. AMBER+ content **never** crosses the third-party API
boundary. Enforcement is in the retriever, validated by an integration test
with a network-recording proxy.

### D4 - Agentic core: typed blackboard + Claude tool-use, no free-form chat

Three logical roles (Planner, Executor, Reporter) share a typed Pydantic
**blackboard state**. Inter-agent communication is via state mutations and
declared **tool-use** schemas, not free-form natural-language chat. This:

- keeps token usage bounded (prompt caching on system + intel-summary blocks),
- makes every step auditable (input/output hashes per tool call),
- removes the "creative interpretation" failure mode for safety-critical fields.

Default model: `claude-sonnet-4-6`. Hard planning steps escalate to
`claude-opus-4-7`. A local-LLM fallback (Ollama / vLLM) is supported for
air-gapped or restricted-mode deployments.

### D5 - `EmulationAdapter` interface over multiple backends

Atomic Red Team alone is biased toward Windows endpoint TTPs. We define a small
`EmulationAdapter` interface and ship adapters for:

- **Atomic Red Team** (`invoke-atomicredteam`) - Windows + Linux atomics.
- **Stratus Red Team** - cloud TTPs (AWS / Azure / GCP).
- **CALDERA** - multi-step adversary operations.

Adapters are interchangeable; campaigns can mix them.

### D6 - Tiered isolated lab, IaC per run-id

The lab is **ephemeral infrastructure-as-code** provisioned per `run_id` and
torn down on completion. Components:

- **Vagrant Windows** VM (with EDR / Sysmon / Wazuh) for Windows atomics.
- **Kata-isolated Docker** Linux containers for Linux / cloud SDK paths.
- **INetSim / FakeNet-NG** as the egress sink - **no real internet from the
  lab**, ever. C2-style traffic terminates at the sink.
- Default network policy: **deny-by-default egress**.

Teardown is verified before the run is marked complete; an unverified teardown
fails the run.

### D7 - Pydantic policy DSL (not OPA / Rego)

For a Python-only project, OPA adds a sidecar without commensurate value. The
guardrail policy engine is a small **Pydantic DSL**:

- `scope.targets` allowlist (CIDR / hostnames / cloud-account IDs).
- `tests.allowlist` + per-test `destructiveness in {observational, intrusive, destructive}`.
- `dry_run: true` default; `destructive` requires **2-person integrity**.
- `egress: deny` by default; per-test exceptions only via signed policy diff.

Policies are versioned artefacts; every loaded policy is content-hashed into
audit events.

### D8 - 2-person integrity HITL via OIDC + signed JWT

A single bearer token is insufficient for destructive tests. We require:

- OIDC authentication (any compliant provider).
- RBAC mapping operators / approvers / auditors.
- `destructive` tier requires **two distinct OIDC subjects** to sign approval
  JWTs over the campaign hash + scope-of-engagement hash.
- Kill-switch is **dual-channel**: API endpoint AND an out-of-band signal-file
  watched by the executor supervisor (so a wedged API can still be killed).

### D9 - Tamper-evident audit (Merkle + Sigstore Rekor + WORM)

A flat append-only file is not legal evidence. Audit pipeline:

1. Every event (intel ingest, retrieval, agent tool call, approval, execution,
   teardown) is a `Pydantic AuditEvent`.
2. Events are **Merkle-chained** per run.
3. Periodic Merkle roots are published to **Sigstore Rekor** (transparency log).
4. Batched events export to **WORM storage** (S3 Object Lock or local
   immutable volume).
5. Every event embeds the **scope-of-engagement hash** for chain-of-custody
   binding plus a clock attestation.

### D10 - Offline evaluation harness gates the planner

"Ranking quality" is otherwise unfalsifiable. We maintain an `eval/` harness
with golden-CTI -> expected-TTP datasets. The CI computes:

- **precision@10** and **recall@k** against the golden set,
- **chain plausibility** (kill-chain ordering coherence).

Regression is a non-blocking warning; a crash is blocking. Every Claude model
upgrade re-runs the harness before being made default.

## Consequences

**Positive**

- Strong separation of concerns: schemas, intel, RAG, agent, emulation,
  guardrails, audit, reporting are independently testable.
- Defensive-research-grade safety properties are encoded in code, not in prose.
- Every conclusion the framework draws is traceable to (a) cited intel chunks,
  (b) graph paths, (c) agent reasoning trace, (d) executed test artefacts.
- The framework can run in air-gapped / TLP:RED environments.

**Negative / accepted trade-offs**

- More moving pieces than a "single-agent over a Chroma store" prototype.
  Mitigated by phased delivery (Phase 0 -> 6) and a tight schema layer that
  lets pieces evolve independently.
- Vagrant + Windows VM adds host-OS requirements vs. pure Docker. Accepted
  because Windows atomics realism outweighs the convenience of Docker-only.
- Two embedding stacks = re-embedding migrations when defaults change. The
  `migrations/` module is a first-class citizen for this reason.

## Out of scope (this ADR)

- Specific actor-profile schema beyond `actors/aliases.yaml` (future ADR).
- Detection-engineering output format choice (Sigma vs. Elastic EQL) - to be
  decided in Phase 5.
- Cloud-deployment topology (the framework runs on a single host today).

## References

- Multi-expert panel review (recorded in `/root/.claude/plans/act-as-expert-in-precious-quasar.md`).
- MITRE ATT&CK STIX 2.1 schema.
- NIST SP 800-115 (engagement ground rules).
- Sigstore project (Rekor transparency log).
