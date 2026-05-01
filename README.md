# Threat-Emulation

> **Automated Agentic RAG Threat Emulation Framework**
> Intelligence-driven adversary emulation with explainable, auditable execution.
> Defensive research only.

[![CI](https://github.com/AlbshriAdel/Threat-Emulation/actions/workflows/ci.yml/badge.svg)](https://github.com/AlbshriAdel/Threat-Emulation/actions/workflows/ci.yml)

## What it does

1. **Ingests** live threat intelligence — MITRE ATT&CK STIX, CISA KEV +
   advisories, vendor reports (CrowdStrike / Mandiant / MSTIC), CTI feeds via
   TAXII / MISP / OpenCTI, and optional internal SIEM telemetry.
2. **Retrieves** relevant context via a hybrid store: **Qdrant (dense) + BM25
   (sparse) + a NetworkX ATT&CK graph** (`intrusion-set → uses → attack-pattern
   → mitigation`).
3. **Plans** a `Campaign` — an ordered TTP chain bound to an actor profile and
   a signed scope-of-engagement — using Anthropic Claude with tool-use over a
   typed Pydantic blackboard (no free-form chat).
4. **Executes** matching tests via the `EmulationAdapter` interface (Atomic
   Red Team, Stratus Red Team, CALDERA) inside an isolated, IaC-provisioned
   lab with deny-by-default egress (INetSim sink).
5. **Reports** explainable findings (HTML + Markdown + ATT&CK Navigator JSON).
   Every conclusion cites the intel chunks, graph path, agent reasoning trace,
   and executed test artefacts.

See [`CLAUDE.md`](./CLAUDE.md) for the operating contract (hard rules, agent
guidance, common commands) and [`docs/adr/0001-architecture.md`](./docs/adr/0001-architecture.md)
for the foundational architecture decisions.

## Status

**Phase 0 — scaffolding.** Canonical Pydantic schemas, CI, dev tooling, and
documentation. No emulation execution yet; see the phased delivery table in
`CLAUDE.md`.

## Development

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync --extra dev

uv run ruff check .
uv run ruff format --check .
uv run mypy .
uv run pytest -q
```

## Repository layout

```
src/threat_emulation/        package source
├── schemas/                 canonical Pydantic models + enums
└── cli.py                   Typer entrypoint (threat-emu)
tests/                       pytest suite
docs/adr/                    architecture decision records
infra/                       session-start hook, CI helpers
.github/workflows/           GitHub Actions CI
```

## Hard rules (excerpt)

- **Scope.** Never execute outside a signed scope-of-engagement.
- **2PI.** Destructive tests require two independent OIDC-signed approvals.
- **Egress.** No real internet from the lab; C2 traffic terminates at INetSim.
- **TLP.** TLP:AMBER+ never reaches third-party APIs (local embedder only).
- **Audit.** Every tool call is Merkle-chained and bound to the scope hash.

Full text in [`CLAUDE.md`](./CLAUDE.md#2-hard-rules-non-negotiable).

## License

Apache-2.0.
