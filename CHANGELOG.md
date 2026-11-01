# Changelog

## 1.0.0 — First release

- PowerDNS Recursor Lua DNS hook plus a loopback-only asynchronous Python bridge that applies Blockinator `/api/v1/decision` policy, with NXDOMAIN, REFUSED, NODATA and zero-address responses.
- Asynchronous `udpQueryResponse` follow-up so policy calls do not block Recursor workers; packet cache disabled for policy-dependent answers while the record cache keeps working.
- Configurable fail-open/fail-closed behavior, total request timeout, concurrency limit and server ID; redirects and ambient proxies are never used.
- Python 3.10 support: timeouts no longer crash the bridge or leave Recursor without a reply.
- Every policy request receives a reply, including malformed or deeply nested JSON bodies.
- Failure counters are logged only when they change, with per-interval and total counts.
- systemd unit ordered before `pdns-recursor` with additional sandboxing.
- Unit tests and live Recursor tests in CI on Python 3.10 and 3.12.
