# Legacy HTTP fixtures

`legacy-http-eb13fc0.json` was captured from the unmodified inference and forwarding
implementation at `eb13fc015686202d15c7ed57faa3d975482bcc32`. The harness sends HTTP
requests through the actual router to an in-process loopback upstream. It covers
both OpenAI inference paths in redact, no-go, and advisory mode: original bytes,
redaction, scan-only findings, nested JSON, text attachments, adjacent text blocks,
auth/encoding/JSON ordering, size limits, incomplete inspection, and upstream
errors/redirects. Rejected requests must produce zero upstream requests.

The fixture retains exact request/response body strings, status codes, header
values, methods, paths, and query behavior. Generated UUIDv4s, HTTP dates, and the
ephemeral upstream authority are validated and replaced with stable placeholders;
all other bytes are compared verbatim. All content and credentials are fake.

To reproduce, create a disposable checkout at the base revision, copy
`src/legacy_http_tests.rs` and this fixtures directory into it, then run:

```sh
git apply tests/fixtures/legacy-http-base.patch
cargo test --locked --all-features --bin preflight legacy_http_tests::capture_legacy_http_goldens -- --ignored --exact
cargo test --locked --all-features --bin preflight legacy_http_tests::legacy_routes_match_base_http_goldens_in_every_mode -- --exact
```

The patch only extracts the base's existing router expression into `router(live)`
and declares the test module. It does not modify parsing, policy, authentication,
errors, or forwarding. Copy the captured JSON back to the implementation checkout
and run the second command there. Do not regenerate the fixture from the changed
implementation: it is a regression oracle for the base behavior.
