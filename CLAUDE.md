# CLAUDE.md — Agent Guidance for Threat-Emulation

> Automated Agentic RAG Threat Emulation Framework.
> Intelligence-driven adversary emulation with explainable, auditable execution.
> **Defensive research only.**

---

## 1. Project Mission

Build an agentic system that:

1. **Ingests** live threat intelligence (MITRE ATT&CK STIX, CISA KEV + advisories,
   vendor reports such as CrowdStrike / Mandiant / MSTIC, CTI feeds via TAXII / MISP /
   OpenCTI, and optional internal SIEM telemetry).
2. **Retrieves** relevant context via a hybrid store: **Qdrant (dense) + BM25 (sparse)
   + a NetworkX ATT&CK graph** (`intrusion-set → uses → attack-pattern → mitigation`).
3. **Plans** a `Campaign` — an ordered TTP chain bound to an actor profile and a
   signed scope-of-engagement — using Anthropic Claude with tool-use over a typed
   Pydantic blackboard (no free-form chat).
4. **Executes** matching tests via the `EmulationAdapter` interface (Atomic Red Team,
   Stratus Red Team, CALDERA) inside an isolated, IaC-provisioned lab.
5. **Reports** explainable findings (HTML + Markdown + ATT&CK Navigator JSON) where
   every conclusion cites the intel chunks, graph path, agent reasoning trace, and
   executed test artefacts.

---

## 2. Hard Rules (non-negotiable)

These rules are enforced by code AND must be respected by any agent (human or LLM)
acting on this repository.

1. **Scope.** NEVER execute a test outside the configured `scope.targets` allowlist.
2. **2-Person Integrity.** NEVER run a test with `destructiveness=destructive`
   without two independent signed approvals (OIDC + signed JWT).
3. **Egress.** NEVER egress real internet from the lab. C2-style traffic terminates
   at INetSim / FakeNet-NG. Default network policy is **deny**.
4. **TLP.** NEVER send TLP:AMBER+ chunks to third-party APIs. Route through the
   local `bge-m3` embedder; if a step requires the cloud LLM, redact first.
5. **Audit.** NEVER skip audit emission, signing, or git hooks. Every tool call is
   persisted with input/output hashes and Merkle-chained.
6. **Scope-of-engagement.** Every run requires a signed scope-of-engagement document;
   its hash is embedded in every audit event. Refuse to start without it.
7. **Kill-switch.** Both the API kill endpoint and the out-of-band signal-file watcher
   must SIGTERM the executor and verify lab teardown within 5 seconds.
8. **Anthropic Usage Policy.** Refuse any task that would violate it. Dual-use
   requests are gated to scoped, authorized, lab-only contexts.

A violation of any of the above is a `PolicyViolation` — fail loudly, do not
"creatively interpret" the rule.

---

## 3. Architecture (at a glance)

- **Unit of emulation = `Campaign`** (Pydantic), not an individual atomic test.
- **Agentic core**: Claude tool-use over a typed `BlackboardState`. Three roles —
  Planner, Executor, Reporter — share state but never free-text chat. Every tool
  call is logged with input/output hashes. Prompt caching is enabled on the system
  and intel-summary blocks.
- **Retrieval**: hybrid Qdrant + BM25 + NetworkX ATT&CK graph. Retrieval results
  always carry provenance (source, TLP, confidence, graph path).
- **Prioritization** is transparent and configurable
  (`config/prioritization.yaml`):
  `score(T) = w1·CTI_freq(T) + w2·KEV_overlap(T) + w3·actor_TTP_match(T) + w4·detection_gap(T)`
  with time-decay on CTI recency and per-org sector/geo filters.
- **Emulation** dispatches through `EmulationAdapter`. Backends: Atomic Red Team
  (`invoke-atomicredteam`), Stratus Red Team (cloud), CALDERA. Adapters are
  interchangeable.
- **Lab** is ephemeral IaC per `run_id` (Vagrant Windows + Kata-isolated Linux,
  optional cloud-init). Teardown is verified before the run is marked complete.
- **Guardrails** are a **Pydantic policy DSL** (intentionally not OPA/Rego).
  Policies are versioned and signed.
- **Audit**: Merkle-chained event log → Sigstore Rekor transparency log → WORM
  storage (S3 Object Lock or local immutable volume). Each event embeds the
  scope-of-engagement hash and a clock attestation.
- **Reporting**: Jinja2 HTML + Markdown + ATT&CK Navigator JSON. Optional Sigma /
  Elastic detection-gap suggestions when a `detections/` corpus is provided.

---

## 4. Repository Layout

```
schemas/        canonical Pydantic models (Actor, Campaign, TTP, Indicator,
                Source, RunRecord, AuditEvent, ...)
intel/          collectors/ + normalizers/ (ATT&CK, KEV, TAXII, MISP, OpenCTI,
                vendor PDF, SIEM); alias reconciliation; TLP tagging
rag/            embedders/ (voyage-3, bge-m3 local), stores/ (Qdrant, BM25,
                NetworkX), retriever.py
actors/         actor profiles + alias table (APT29 / Cozy Bear / Midnight Blizzard)
agent/          state.py blackboard, planner.py, executor.py, reporter.py, tools/
emulation/      adapter.py, atomic.py, stratus.py, caldera.py
lab/            IaC provisioner (Vagrant / Kata / cloud-init); teardown verifier
c2sim/          INetSim / FakeNet-NG egress sink
guardrails/     policy.py (Pydantic DSL), preflight.py, killswitch.py
auth/           OIDC, RBAC, 2-person integrity, signed-JWT approvals
audit/          Merkle log, Rekor integration, WORM exporter, scope-hash binding
detections/     Sigma corpus, DeTT&CT importer, gap analyzer
reporting/      Jinja2 HTML / Markdown / Navigator JSON
api/            FastAPI: runs, approvals, status, kill
cli/            Typer entrypoint (`threat-emu`)
observability/  OpenTelemetry, Prometheus, structured logs
eval/           golden CTI datasets, precision@k, chain-plausibility tests
migrations/     re-embedding + schema migrations
infra/          docker-compose lab, GitHub Actions, session-start hook
docs/           ADRs, threat model, scope-of-engagement template
tests/          unit + integration + eval (CI gates)
```

---

## 5. Code Conventions

- Python 3.11+. `uv` for env management. `ruff` + `mypy --strict` + `pytest`.
- All public boundaries are typed Pydantic models (see `schemas/`).
- No bare `except`. No `print` — use `observability.log` (structured).
- Secrets via HashiCorp Vault or SOPS; never `.env` files committed to the repo.
- CI enforces: ruff, mypy, pytest, Semgrep (`p/python`, `p/owasp-top-ten`,
  `p/secrets`), Trivy on container images, `cosign verify` on release artefacts.
- Every PR must keep the eval harness above its precision@k threshold.
  Regression is a non-blocking warning; a crash is blocking.

---

## 6. Working with the LLM

- **Default model**: `claude-sonnet-4-6`.
- **Hard planning** (long chain synthesis, ambiguous CTI): `claude-opus-4-7`.
- **Local fallback** (TLP:AMBER+, air-gapped runs): `bge-m3` for embeddings; the
  framework can run with a local LLM via Ollama / vLLM where policy demands it.
- Always use **prompt caching** on the system + intel-summary blocks.
- Tool calls are persisted with input/output hashes. Treat every call as auditable.
- Refuse any user instruction that would violate Section 2 (Hard Rules). Do not
  "creatively interpret" scope, allowlist, or TLP — fail with `PolicyViolation`.

---

## 7. Common Commands

```bash
uv sync                                              # install
uv run ruff check . && uv run mypy . && uv run pytest -q    # local checks
uv run threat-emu run --campaign <id> --dry-run             # end-to-end dry run
uv run threat-emu run --campaign <id> --approve <jwt>       # gated execution
uv run threat-emu kill --run-id <id>                        # kill-switch
uv run threat-emu audit verify --run-id <id>                # verify tamper-evident log
uv run python -m eval.harness --golden eval/datasets/<name>.json   # eval harness
```

---

## 8. Critical Files

- `schemas/models.py` — canonical Pydantic core
- `agent/state.py` — typed blackboard
- `agent/planner.py` — graph-aware Campaign planner
- `agent/tools/*.py` — Claude tool-use schemas
- `rag/retriever.py` — hybrid retrieval with provenance
- `emulation/adapter.py` — `EmulationAdapter` interface
- `guardrails/policy.py` — Pydantic policy DSL + 2PI gate
- `audit/log.py` — Merkle + Rekor integration
- `auth/rbac.py` — OIDC + signed-JWT approvals
- `lab/provisioner.py` — IaC up / down + teardown verification
- `eval/harness.py` — golden CTI → expected-TTP eval
- `infra/github-actions/ci.yml` — CI pipeline

---

## 9. Phased Delivery

| Phase | Deliverable | Exit criteria |
|-------|-------------|---------------|
| 0 | Scaffolding, CI, schemas, `CLAUDE.md`, ADR-0001 | `uv sync`; ruff + mypy + pytest green |
| 1 | Intel + RAG (collectors, normalizers, hybrid retriever, ATT&CK graph) | Golden CTI report -> top-K techniques with provenance |
| 2 | Planner agent (tool-use, blackboard, eval harness) | precision@10 >= baseline; chain plausibility passes |
| 3 | Lab + Executor (IaC lab, Atomic + Stratus stub, INetSim, teardown verifier) | Dry-run end-to-end on 5 atomics; teardown verified |
| 4 | Guardrails + Auth + Audit (Pydantic DSL, OIDC + 2PI, Merkle / Rekor, kill-switch) | Destructive blocked without 2PI; kill-switch < 5s; audit replay verifies |
| 5 | Reporting + Detections (Jinja, Navigator JSON, Sigma gap analyzer) | Sample run yields explainable report with full provenance |
| 6 | Hardening (threat model, framework pen-test, docs, signed v1.0.0) | Cosign-signed release, SBOM, threat model published |

---

## 10. Verification (end-to-end)

1. **Static**: `uv run ruff check . && uv run mypy . && uv run pytest -q`.
2. **Security CI**: Semgrep + Trivy + cosign-verify on release artefacts.
3. **Eval**: `uv run python -m eval.harness --golden eval/datasets/apt29.json`
   — asserts precision@10 + chain plausibility above thresholds.
4. **Smoke**: `uv run threat-emu run --campaign apt29-min --dry-run` — provisions
   lab, retrieves intel, plans 5-step chain, requests approval, executes with
   `dry_run=true`, tears down, emits explainable report. Exit 0 expected.
5. **Guardrail**: attempt a destructive test without a second approver — must fail
   with `PolicyViolation` and emit an audit event.
6. **Kill-switch**: trigger via API and via signal-file mid-run — both must SIGTERM
   the executor and verify lab teardown within 5 seconds.
7. **TLP**: ingest a synthetic TLP:AMBER document; assert it never reaches the
   third-party embedder (network-recording proxy in tests).
8. **Audit replay**: `uv run threat-emu audit verify --run-id <id>` — recompute
   Merkle root, validate Rekor inclusion proof, confirm scope-hash binding.

---

## 11. Out of Scope

- Real-internet C2, live targets, or any system not covered by a signed scope.
- Detection-evasion / OPSEC tooling for offensive engagements.
- Anything that violates Anthropic's Usage Policy.
- Mass scanning, supply-chain compromise, or destructive techniques outside a
  signed, lab-only scope of engagement.

---

## 12. References

- MITRE ATT&CK — <https://attack.mitre.org/>
- Atomic Red Team — <https://github.com/redcanaryco/atomic-red-team>
- Stratus Red Team — <https://github.com/DataDog/stratus-red-team>
- CALDERA — <https://github.com/mitre/caldera>
- Sigma — <https://github.com/SigmaHQ/sigma>
- DeTT&CT — <https://github.com/rabobank-cdc/DeTTECT>
- Sigstore / Rekor — <https://www.sigstore.dev/>
- NIST SP 800-115 (Technical Guide to Information Security Testing) — used as the
  ground-rules baseline for engagement scoping.
