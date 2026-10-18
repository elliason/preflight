# 0007 — Preserve Responses opaque state

## Status
Accepted

## Context
Responses clients replay reasoning and compaction ciphertext on later turns.
Redacting a scanner match corrupts that state, causing provider rejection.

## Decision
For `POST /v1/responses`, scan without rewriting string `encrypted_content` in
direct `input` items of type `reasoning` or `compaction`, as defined by the
[Responses API](https://developers.openai.com/api/reference/resources/responses/methods/create).
Strings starting with `data:` or whose trimmed form starts with `{` or `[` are
excluded from opaque handling and retain existing decoding, parsing and resolution.
Other opaque values are never decoded, parsed as JSON, rewritten or logged; if
one equals the base64 encoding of an inspected attachment with findings, refuse.
Literal findings also set `unsafe_findings`: redact/no-go return the existing
`409 secrets_detected` before forwarding any bytes. Advisory remains report-only.
Non-string values, plaintext `summary[].text`, nested objects and other routes
keep their ordinary handling; this adds no compaction endpoint.

## Consequences
Detection stays unchanged: a buggy client's literal secret is refused or redacted,
including on item-type disagreement. Rewriting cannot make ciphertext safe, and
literal scanning never inspects its plaintext. Clean opaque bytes remain identical.
A ciphertext false positive returns an explicit error on every later replay of the
stored state; the user sees `409 secrets_detected` and must start a new session.
There is no unscreened fallback. Per-cause visibility is possible future work;
this change adds no metrics or error type.

Rejecting all opaque state breaks every conversation that replays reasoning state.
Exact-replay digests require response-side observation and persistent state, so
remain a separate proposal. The multi-turn stub is a compatibility regression guard.
