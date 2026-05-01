"""Threat-intelligence ingestion: collectors and normalisers.

The intel layer pulls raw data from external sources (ATT&CK STIX bundles,
CISA KEV, TAXII feeds, MISP, OpenCTI, vendor reports) and normalises it into
the canonical Pydantic models in :mod:`threat_emulation.schemas`. Everything
downstream — RAG, planner, executor, reporter — consumes only canonical types.
"""
