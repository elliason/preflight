# 0007 — Native protocol adapters and signed conversation state

## Status
Proposed

## Context
Anthropic Messages carries text, tool history, signed thinking, and encrypted
provider state. Preflight screens accidental disclosures; field names establish
neither provenance nor inspection. Five captured Claude Code 2.1.302 requests
contained no opaque blocks; hosted tools and resumed sessions remain unmeasured.

## Decision
Use typed route adapters and closed inspection plans ahead of shared inspection
and approval. Classify every supplied field or reject it. Legacy Responses and
Chat Completions keep their parser and walker; only `ApprovedRequest` supplies
upstream body bytes. Unchanged requests and upstream SSE retain their bytes.

Inspect signed `thinking` text, signatures, keys, and structural values without
rewriting the signed group or authenticating its signature. Findings block in
`redact` and `no-go`; `advisory` forwards the original request, as for other
unsafe-to-rewrite findings. Reject unsupported opaque state in every mode.

Open question for maintainers: keep reject-all as the default for opaque state in
this change, and consider a future typed, opt-in scan-only policy, off by default, with a
field allowlist v1: `redacted_thinking.data`, `encrypted_content`,
`encrypted_index`, and `encrypted_code_execution_result.encrypted_stdout`.
Require well-formed base64, at most 1 MiB decoded per field and 4 MiB per request,
with encoded lengths bounded accordingly. Scan literal values and decoded bytes
when printable or UTF-8. Any finding blocks in enforcing modes. Never
rewrite these fields; unknown fields and malformed or oversized values reject.
This bounded exception fits accidental-disclosure screening, but cannot inspect
ciphertext or prove its origin and needs an explicit inspection-contract change.

Exact recorded replay is a stricter alternative: bind complete provider-issued
groups to upstream, protocol, and conversation/security scope, accepting only
unchanged recorded bytes. This proves provenance, not plaintext inspection, and
needs bounded JSON/SSE parsing plus separate authority from the approval cache.
Missing records fail closed after resumes, compaction, pre-proxy histories,
restarts, or routing across instances; retention and eviction add availability
costs. Neither optional policy is implemented here.

## Consequences
All five captured bodies passed inspection without an opaque-state exception.
Unknown block families and encrypted-history impact need additional coverage.
Golden HTTP regressions, Hegel properties, and mock-upstream tests guard
complete-before-forward behavior without adding response observation.
