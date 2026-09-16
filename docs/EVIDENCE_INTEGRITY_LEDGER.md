# Evidence integrity ledger

This prototype uses a local, append-only, tamper-evident SHA-256 hash chain. It is not a blockchain and it makes no public, distributed, or consensus-backed immutability claim. `IntegrityLedger` and `LocalHashChainLedger` provide a deliberate boundary for a future external ledger implementation.

## Canonical artifact representation

Every hash is generated from UTF-8 JSON with sorted object keys, compact separators, and preserved array order. Formatting and JSON key order therefore do not change a hash. The canonical artifact envelope contains the algorithm (`SHA-256`), schema version (`integrity-v2` for newly written records; older `integrity-v1` records remain readable), artifact type, artifact ID, and payload. Values that cannot be represented as deterministic JSON are rejected. UI-only state and request presentation fields are not included.

New records cover `CONFIGURATION`, `ANALYSIS`, `EVIDENCE`, `MAPPING_VERSION`, `AI_PROPOSAL`, `REMEDIATION_SIMULATION`, and `REPORT` metadata. Configuration entries retain the existing configuration-content SHA-256 fingerprint. Analysis entries contain the persisted analysis response, stored Security IR snapshot, and configuration fingerprint; evidence entries contain the stored evidence record. Verification reads those stored snapshots and never reruns compliance evaluation.

## Ledger operation

Each ledger record stores its artifact content hash and the prior record hash. Its record hash covers the immutable record fields, including actor ID and timestamp. SQLite also stores an expected record count and final hash. Verification rejects changed records, broken prior links, missing records, and state/chain mismatches. It does not repair a failed ledger.

Actor identity comes from the authenticated server-side request state where an action creates an analysis, re-analysis, remediation simulation, mapping version, or report. Client-provided reviewer identity is not used as ledger authority.

## APIs

- `GET /api/integrity/chain` verifies the complete chain.
- `GET /api/integrity/records` lists metadata only.
- `GET /api/integrity/{artifact_type}/{artifact_id}` retrieves current verification status.
- `POST /api/integrity/{artifact_type}/{artifact_id}/verify` explicitly verifies an artifact.

The APIs are authenticated by the existing RBAC dependency. They expose hashes and verification state, never configuration upload content or secrets. Verification is explicit; dashboard requests do not traverse the chain.

## Report behavior

Reports include the stored analysis integrity status, analysis content hash, and the ledger record ID for the generated report metadata. Report generation uses stored analysis, mapping, and simulation data and does not recalculate controls. Raw PDF files are not persisted by this offline prototype, so a report integrity record proves the issued report's captured lineage metadata, not long-term custody of a downloadable binary.

## What this proves and does not prove

The ledger detects unexpected changes to records that remain in the local database. It is not encryption, does not hide evidence, does not prevent a database administrator from altering both artifacts and the ledger, and cannot provide independently witnessed timestamping or public-chain finality. An external anchored or blockchain implementation remains future work behind the ledger interface.

Existing historical records from before this checkpoint have no retroactive hash until an explicit migration/backfill process is designed and approved. New records are appended as the associated audit artifacts are created.
