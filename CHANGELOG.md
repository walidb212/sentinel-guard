# Changelog

All notable changes to this project are documented here. The format follows Keep a Changelog; versions follow SemVer.

## [0.1.0] - 2026-10-11

First public release.

### Added
- MCP server (`sentinel-guard`, `python -m sentinel_guard`) over stdio, or streamable HTTP with an optional bearer token.
- Tools: `screen_payment` (verdict in the strict AgenticPaymentVerdict schema), `authorize_payment` (connected mode:
  on-chain visa, flag or pending mark through the hosted API), `explain_decision`; human tools (`list_pending`,
  `approve_pending`, `lift_flag`) only when `SENTINEL_APPROVER_TOKEN` is set.
- The guard engine: sanitizer (hidden HTML, invisible Unicode, encoded blobs), seven layers of signals, degressive trust
  score, thresholds, human queue with one-time visas, local incident registry, JSONL audit trail.
- Operator config kept apart from guard state (`SENTINEL_CONFIG_DIR`, read only; `SENTINEL_STATE_DIR`, default
  `~/.sentinel-guard/state`), with a synthetic example config shipped in the package.
- Mandate model: the operator's mandate, a caller mandate that can only tighten it, `SENTINEL_UNREGISTERED=review|block`,
  `SENTINEL_ISSUER` binding, provenance of the effective mandate.
- Connected mode: shared incident registry lookups (`GET /flagged/{address}`, cached, local fallback) and `POST /authorize`.
- Optional LLM judgement: `SENTINEL_LLM=anthropic|bedrock` (extras `[anthropic]`, `[bedrock]`), off by default.
- CLI: `init`, `screen`, `pending`, `approve`, `lift`, `eval`; a shipped evaluation corpus of 75 cases.
