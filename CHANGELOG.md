Release Notes
=============

___

v3.2.2 (2026-10-09)
-------------------

The family lockstep artifact: the sanitizer export surface, lockstep with guard-agent 3.2.2 (v3.2.2)
-----------------------------------------------------------------------------------------------------

### About this release

- **Lockstep with guard-agent 3.2.2 on PyPI.** The Go agent ships the wave's runtime content (the sanitizer export surface) under the same version number the Python reference carries; `version.go` moves to 3.2.2, the `agent_version` the agent reports to the ingestion API.

### Added

- **The sanitizer export surface** (#25, the FEATURE_MATRIX_GO GAP 19 closure): the reference sanitizer family (`guard_agent/utils.py`) beyond `SanitizeHeaders`/`TruncatePayload`/`HashIP` exports onto the Go module: `GenerateBatchID` (the `{unix_millis}-{8 hex chars}` reference `generate_batch_id` shape, the internal `newBatchID` seam exported), `SummarizeResponseBody` (the whitespace-collapsing bounded single-line response-body summary with the original-length truncation note), `SafeJSONSerialize`/`SafeJSONDeserialize`/`SerializationError` (the compact-JSON transport serialization with the typed failure, and the object-only tolerant deserialization where a non-object payload or a parse failure returns nil), and `ValidateConfig` (the advisory config audit returning the normalize problems as a list of strings without mutating or applying defaults; construction-time normalize stays the fail-closed surface). The unrepresentable non-ConfigError fallback arm in `ValidateConfig` is dropped so the strict coverage gate stays at 100%.
- **The `get_stats` dict view** (#26): `Agent.AgentStats` renders the reference `get_stats` dict shape (`_client_status.py get_stats` with the buffer and transport-lifecycle nested blocks), satisfying guardcore's `AgentStatsProvider` seam so the middleware `agent_stats` property merges it. Keys the Go agent tracks carry the same values as the typed `Stats` snapshot; the reference's per-loop consecutive-failure counters and `last_status_push_ok` have no tracked counterpart and are omitted.

### Changed

- **Dependencies**: `github.com/redis/go-redis/v9` to v9.23.0 (#27), the engine-family bump train (guard-core-go #67), carrying the x/sys v0.48.0 line that clears the stdlib-adjacent exposure; govulncheck stays clean.

___

v3.2.1 (2026-10-07)
-------------------

The family lockstep artifact: the 3.2.1 wave tag (v3.2.1)
----------------------------------------------------------

### About this release

- **An empty lockstep release for the Guard agent family 3.2.1 wave.** No shipped change: no `guardagent` code, dependency, or behavior delta since 3.2.0. The tag exists so the family stays version-aligned while the TypeScript port ships the wave's only runtime fix (the js/polynomial-redos endpoint normalization hardening, guard-agent-ts 3.2.1).

### Changed

- **Version only.** `version.go` moves to 3.2.1 (the `agent_version` the agent reports to the ingestion API). The engine floor stays at `github.com/rennf93/guard-core-go/v4 v4.3.0`.

### Compatibility

- **Drop-in.** Consumers on 3.2.0 can move to 3.2.1 with no code or config changes; the module path and the engine floor are unchanged.

___

v3.2.0 (2026-10-01)
-------------------

The 4.3.0-train artifact: coverage-gate hardening and the engine 4.3.0 floor (v3.2.0)
-------------------------------------------------------------------------------------

### Added

- **The 100% line coverage gate is enforced fail-closed** (guard-agent-go #19, #20, #21). The gate now aborts on a missing or empty coverage profile instead of passing silently, the wake-flush coverage branches are deterministic rather than timing-dependent, and the agent surface is covered to the full line floor with real inputs.
- **The process scaffold** (guard-agent-go #20): the family CI conventions - issue-link, labeler, scheduled lint, dependabot grouping - and the community health files.

### Changed

- **The engine floor moves to `github.com/rennf93/guard-core-go/v4 v4.3.0`** (the 4.3.0 train): the agent consumes the engine release that carries the corpus runners, the event-surface closures and the manager-level geo verdicts.

___

v3.1.0 (2026-09-27)
-------------------

Parity release: the 3.0.2 to 3.1.0 agent feature set (v3.1.0)
-------------------------------------------------------------

### Added

- **AES-256-GCM encrypted ingest.** Batches can now be encrypted end to end before they leave the host, matching the Python agent's encrypted ingest contract.
- **Recursive sensitive-header redaction.** Authorization, cookie, and set-cookie style headers (and their nested occurrences) are redacted before a payload is built.
- **Dynamic rules.** The agent can pull rule updates from the ingestion API and apply them to the local runtime without a restart.
- **Local rate limiters.** Token-bucket style local limiting protects the host from event floods before anything is buffered or shipped.
- **`on_error` and `max_payload` configuration knobs.** Operators choose the failure behavior (log and continue versus surface the error) and cap the serialized payload size.

### Changed

- **`version.go` is bumped to 3.1.0** so the reported `agent_version` and the User-Agent match the release tag; `make bump-version` updates `version.go` and this changelog.
- **Parity tests** (`parity_test.go`) pin the new 3.1.0 surface against the reference Python agent behavior.

___

v3.0.2 (2026-09-24)
-------------------

First tagged release: parity with guard-agent 3.0.2 and the /v3 module path (v3.0.2)
------------------------------------------------------------------------------------

### Breaking Changes

- **Import paths now end in `/v3`.** The module path is `github.com/rennf93/guard-agent-go/v3` and the release tag is `v3.0.2`; Go modules reject a `v3+` tag unless the module path carries the `/v3` suffix, so the migration is mandatory for this release to be fetchable. Update every import from `github.com/rennf93/guard-agent-go` to `github.com/rennf93/guard-agent-go/v3` (package name stays `guardagent`). Installation is now `go get github.com/rennf93/guard-agent-go/v3@v3.0.2`.

### Added

- **First tagged release of the Go agent, at parity with the reference guard-agent 3.0.2 (Python).** The port covers the full agent surface: event and metric buffering with at-least-once delivery, the overflow policies, Redis persistence, circuit breaking, and the batch transport.
- **The payload-signature contract matches the server.** `X-Payload-Signature` is an HMAC over the uncompressed body: the agent signs the body before any compression is applied, and the server verifies the signature after decompression. Compressed batches therefore verify correctly on both the encrypted and unencrypted POST paths.
- **An mkdocs documentation site** under `docs/`, covering configuration, the buffering and overflow model, the transport and signing contract, and Redis persistence.
- **A `basic_usage` wiring example** (`examples/basic_usage`) that wires the agent into a guard-core-go engine through the engine's `OnBlock` telemetry seam.

### Changed

- **`version.go` is bumped to 3.0.2** so the reported `agent_version` and the User-Agent match the release tag, and `make bump-version` (via `.github/scripts/bump_version.py`) now updates both `version.go` and this changelog.
- **Makefile harmonized with the guard family.** `install`, `test` (unit plus `-tags integration` with `REDIS_HOST` in docker), `lint` (`gofmt` check plus `go vet`), `bump-version` and `clean` match the conventions used across the Python guard repos.

___
