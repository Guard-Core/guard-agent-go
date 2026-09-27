# Configuration

Everything is the `guardagent.Config` struct; there are no environment
variables inside the agent (your application maps its environment onto the
struct, as the example app does). `guardagent.DefaultConfig()` returns the
documented defaults.

## Required

| Field | Purpose |
|---|---|
| `APIKey` | Ingestion API key, sent as `X-API-Key` (minimum 10 characters) |

## Endpoints and identity

| Field | Default | Purpose |
|---|---|---|
| `Endpoint` | `https://api.guard-core.com` | Ingestion base URL; a trailing `/api/v1` suffix is removed automatically |
| `ProjectID` | empty | Sent as `X-Project-Id` when non-empty |
| `InstallID` / `InstallIDPath` | `~/.guard-agent/install-id` | Persisted agent identity, sent as `X-Agent-Install-Id` |
| `GuardVersion` / `GuardCoreVersion` | empty | Reported as `guard_version` / `guard_core_version` |

## Buffering

| Field | Default | Purpose |
|---|---|---|
| `BufferSize` | 100 | Per-kind queue capacity |
| `FlushInterval` | 30s | Periodic flush cadence and retry backoff base |
| `HighWatermarkRatio` | 0.8 | Combined occupancy that triggers an early flush |
| `DynamicRuleInterval` | 300s | SaaS dynamic rules polling cadence, minimum 60s; a background loop started by `Start` |
| `MaxConcurrentFlushes` | 1 | In-flight flush cycle bound |
| `Overflow` | `OverflowDrop` | Full-buffer policy (`drop`, `block`, `raise`) |
| `EnableEvents` / `EnableMetrics` | true | Per-kind send switches |

## Network

| Field | Default | Purpose |
|---|---|---|
| `RetryAttempts` | 3 | Retries after a failed attempt (0 disables) |
| `Timeout` | 30s | Per-request HTTP timeout |
| `BackoffFactor` | 1.0 | Exponential retry delay base in seconds |
| `CompressionEnabled` | true | Gzip bodies at or above the threshold |
| `CompressionThreshold` | 1024 | Gzip cutoff in bytes |
| `SigningSecret` | empty | HMAC-SHA256 secret over the uncompressed body |
| `ProjectEncryptionKey` | empty | AES-256 key (urlsafe base64, from the core backend); enables encrypted ingest |
| `SensitiveHeaders` | defaults | Header names redacted from metadata/tags; nil = defaults, non-nil replaces |
| `MaxPayloadSize` | 1024 | Payload size (bytes) a host adapter should truncate at with `TruncatePayload` |
| `OnError` | nil | Best-effort failure callback `(stage, err, context)`; stages are `transport_send`, `encryption`, `flush_events`, `flush_metrics` |

With `WithHTTPClient` you can supply a custom `*http.Client` (proxies, mTLS,
custom TLS pools); the agent only overrides its timeout when `Timeout` is set.

## Encrypted ingest

When `ProjectEncryptionKey` is set, event and metric batches are serialized
to the canonical Python JSON bytes, encrypted with AES-256-GCM (fresh 12-byte
nonce per batch), and posted to `/api/v1/events/encrypted` in the Python
envelope; status reports stay plaintext. An invalid key or a failed round-trip
verification fails construction: there is no plaintext fallback. A 413 on the
encrypted path drops durably because an encrypted payload cannot be split.

## Redis persistence

```go
cfg.Redis = &guardagent.RedisConfig{
    URL:    os.Getenv("GUARD_AGENT_REDIS_URL"), // redis:// or rediss://
    Prefix: "guard:agent",                      // default
}
```

Keys are `{Prefix}:{namespace}:{short-key}` with namespaces `agent_events`
and `agent_metrics`. Persistence is optional; without it, a process crash
loses buffered-but-unsent items.

## Dynamic rules

`GetDynamicRules(ctx)` returns the SaaS rule document from `GET /api/v1/rules`
as a `*guardagent.DynamicRules` (the full Python-agent surface: IP lists,
ban duration, countries, rate limits, cloud providers, user agents,
suspicious patterns, feature toggles, emergency mode). Results are cached in
memory for the document's `ttl` seconds; a failed poll serves the last known
rules instead of surfacing the error, mirroring the Python agent. `Start`
runs a background polling loop on `DynamicRuleInterval`; `Stats().RulesFetched`
counts successful refreshes. Outgoing rules polls share the batch-send retry
machinery: the local rate limiter, the circuit breaker, capped Retry-After on
429, and exponential backoff.

## Helpers

- `guardagent.TruncatePayload(payload, maxSize)` truncates with a visible
  `...[TRUNCATED]` marker; pair it with `MaxPayloadSize` before embedding a
  request payload in event metadata.
- `guardagent.HashIP(ip, salt)` returns the first 16 hex characters of
  SHA-256 over `ip+salt` for privacy-conscious telemetry.
- `guardagent.KnownEventTypes` / `guardagent.IsKnownEventType` document the
  39 event types the ecosystem emits. They are documentation, not
  validation: `SendEvent` accepts any non-empty event type.
