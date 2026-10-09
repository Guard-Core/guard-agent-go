<p align="center">
    <a href="https://guard-core.github.io/guard-core/latest/">
        <img src="https://guard-core.github.io/guard-core/latest/assets/guard_core_legend.svg" alt="Guard Core">
    </a>
</p>

___

<p align="center">
    <strong>Go telemetry agent for the [Guard ecosystem](https://github.com/Guard-Core/guard-core). Buffers security events, metrics, and agent status locally and ships them to the Guard Core App ingestion API with at-least-once delivery: nothing acknowledged is lost, nothing unacknowledged is forgotten.</strong>
</p>

<p align="center">
    <a href="https://github.com/Guard-Core/guard-agent-go/releases">
        <img src="https://img.shields.io/github/v/tag/Guard-Core/guard-agent-go?label=release&color=0080ff" alt="Release tag">
    </a>
    <a href="https://guard-core.github.io/guard-agent-go/latest/">
        <img src="https://img.shields.io/badge/docs-latest-0080ff.svg" alt="Docs">
    </a>
    <a href="https://github.com/Guard-Core/guard-agent-go/actions/workflows/release.yml">
        <img src="https://github.com/Guard-Core/guard-agent-go/actions/workflows/release.yml/badge.svg" alt="Release">
    </a>
    <a href="https://opensource.org/licenses/MIT">
        <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
    </a>
    <a href="https://github.com/Guard-Core/guard-agent-go/actions/workflows/ci.yml">
        <img src="https://github.com/Guard-Core/guard-agent-go/actions/workflows/ci.yml/badge.svg" alt="CI">
    </a>
    <a href="https://github.com/Guard-Core/guard-agent-go/actions/workflows/code-ql.yml">
        <img src="https://github.com/Guard-Core/guard-agent-go/actions/workflows/code-ql.yml/badge.svg" alt="CodeQL">
    </a>
</p>

<p align="center">
    <a href="https://github.com/Guard-Core/guard-agent-go/actions/workflows/pages/pages-build-deployment">
        <img src="https://github.com/Guard-Core/guard-agent-go/actions/workflows/pages/pages-build-deployment/badge.svg?branch=gh-pages" alt="PagesBuildDeployment">
    </a>
    <a href="https://github.com/Guard-Core/guard-agent-go/actions/workflows/docs.yml">
        <img src="https://github.com/Guard-Core/guard-agent-go/actions/workflows/docs.yml/badge.svg" alt="DocsUpdate">
    </a>
    <img src="https://img.shields.io/github/last-commit/Guard-Core/guard-agent-go?style=flat&amp;logo=git&amp;logoColor=white&amp;color=0080ff" alt="last-commit">
</p>

<p align="center">
    <img src="https://img.shields.io/badge/Go-00ADD8.svg?style=flat&logo=go&logoColor=white" alt="Go"> <img src="https://img.shields.io/badge/Redis-FF4438.svg?style=flat&logo=redis&logoColor=white" alt="Redis">
</p>

<p align="center">
    <a href="https://guard-core.com">Website</a> &middot;
    <a href="https://guard-core.github.io/guard-agent-go/latest/">Docs</a> &middot;
    <a href="https://playground.guard-core.com">Playground</a> &middot;
    <a href="https://app.guard-core.com">Dashboard</a> &middot;
    <a href="https://discord.gg/ZW7ZJbjMkK">Discord</a>
</p>

---


## Ecosystem

Guard Core is the Python engine. Framework adapters are thin wrappers that translate native request/response types into Guard Core's protocols. The telemetry agents ship security events and metrics to the monitoring backend. Parallel engine implementations exist for Go, PHP, TypeScript (on npm), and Rust (on crates.io) - all ports of the same reference semantics, conformance-tested against the shared adversarial corpus.

### Python

| Package | Role | PyPI |
|---|---|---|
| [guard-core](https://github.com/Guard-Core/guard-core) | Framework-agnostic security engine | [![PyPI](https://img.shields.io/pypi/v/guard-core)](https://pypi.org/project/guard-core/) |
| [guard-agent](https://github.com/Guard-Core/guard-agent) | Telemetry agent | [![PyPI](https://img.shields.io/pypi/v/guard-agent)](https://pypi.org/project/guard-agent/) |
| [fastapi-guard](https://github.com/Guard-Core/fastapi-guard) | FastAPI / Starlette adapter | [![PyPI](https://img.shields.io/pypi/v/fastapi-guard)](https://pypi.org/project/fastapi-guard/) |
| [flaskapi-guard](https://github.com/Guard-Core/flaskapi-guard) | Flask adapter | [![PyPI](https://img.shields.io/pypi/v/flaskapi-guard)](https://pypi.org/project/flaskapi-guard/) |
| [djapi-guard](https://github.com/Guard-Core/djapi-guard) | Django adapter | [![PyPI](https://img.shields.io/pypi/v/djapi-guard)](https://pypi.org/project/djapi-guard/) |
| [tornadoapi-guard](https://github.com/Guard-Core/tornadoapi-guard) | Tornado adapter | [![PyPI](https://img.shields.io/pypi/v/tornadoapi-guard)](https://pypi.org/project/tornadoapi-guard/) |

### Go

Go modules published via GitHub releases. **Production-ready.**

| Package | Role | Release |
|---|---|---|
| [guard-core-go](https://github.com/Guard-Core/guard-core-go) | Go engine | [![release](https://img.shields.io/github/v/tag/Guard-Core/guard-core-go?label=tag)](https://github.com/Guard-Core/guard-core-go/releases) |
| [nethttp-guard](https://github.com/Guard-Core/nethttp-guard) | net/http adapter | [![release](https://img.shields.io/github/v/tag/Guard-Core/nethttp-guard?label=tag)](https://github.com/Guard-Core/nethttp-guard/releases) |
| [gin-guard](https://github.com/Guard-Core/gin-guard) | Gin adapter | [![release](https://img.shields.io/github/v/tag/Guard-Core/gin-guard?label=tag)](https://github.com/Guard-Core/gin-guard/releases) |
| [echo-guard](https://github.com/Guard-Core/echo-guard) | Echo (v4) adapter | [![release](https://img.shields.io/github/v/tag/Guard-Core/echo-guard?label=tag)](https://github.com/Guard-Core/echo-guard/releases) |
| [fiber-guard](https://github.com/Guard-Core/fiber-guard) | Fiber (v3) adapter | [![release](https://img.shields.io/github/v/tag/Guard-Core/fiber-guard?label=tag)](https://github.com/Guard-Core/fiber-guard/releases) |
| [guard-agent-go](https://github.com/Guard-Core/guard-agent-go) | Telemetry agent | [![release](https://img.shields.io/github/v/tag/Guard-Core/guard-agent-go?label=tag)](https://github.com/Guard-Core/guard-agent-go/releases) |

### PHP

Published on [Packagist](https://packagist.org/) under the `rennf93` vendor. **Production-ready.**

| Package | Role | Packagist |
|---|---|---|
| [guard-core-php](https://github.com/Guard-Core/guard-core-php) | PHP engine | [![Packagist](https://img.shields.io/packagist/v/rennf93/guard-core-php)](https://packagist.org/packages/rennf93/guard-core-php) |
| [laravel-guard](https://github.com/Guard-Core/laravel-guard) | Laravel adapter | [![Packagist](https://img.shields.io/packagist/v/rennf93/laravel-guard)](https://packagist.org/packages/rennf93/laravel-guard) |
| [symfony-guard](https://github.com/Guard-Core/symfony-guard) | Symfony adapter | [![Packagist](https://img.shields.io/packagist/v/rennf93/symfony-guard)](https://packagist.org/packages/rennf93/symfony-guard) |
| [psr15-guard](https://github.com/Guard-Core/psr15-guard) | PSR-15 adapter | [![Packagist](https://img.shields.io/packagist/v/rennf93/psr15-guard)](https://packagist.org/packages/rennf93/psr15-guard) |
| [slim-guard](https://github.com/Guard-Core/slim-guard) | Slim 4 adapter | [![Packagist](https://img.shields.io/packagist/v/rennf93/slim-guard)](https://packagist.org/packages/rennf93/slim-guard) |
| [guard-agent-php](https://github.com/Guard-Core/guard-agent-php) | Telemetry agent | [![Packagist](https://img.shields.io/packagist/v/rennf93/guard-agent-php)](https://packagist.org/packages/rennf93/guard-agent-php) |

### TypeScript / JavaScript

Published under the [`@guardcore`](https://www.npmjs.com/org/guardcore) npm scope; source in the [guard-core-ts](https://github.com/Guard-Core/guard-core-ts) monorepo. **Production-ready.**

| Package | Role | npm |
|---|---|---|
| | [@guardcore/core](https://github.com/Guard-Core/guard-core-ts/tree/master/packages/core) | Core engine | [![npm](https://img.shields.io/npm/v/@guardcore%2Fcore)](https://www.npmjs.com/package/@guardcore/core) |
| [@guardcore/express](https://github.com/Guard-Core/guard-core-ts/tree/master/packages/express) | Express adapter | [![npm](https://img.shields.io/npm/v/@guardcore%2Fexpress)](https://www.npmjs.com/package/@guardcore/express) |
| [@guardcore/nestjs](https://github.com/Guard-Core/guard-core-ts/tree/master/packages/nestjs) | NestJS adapter | [![npm](https://img.shields.io/npm/v/@guardcore%2Fnestjs)](https://www.npmjs.com/package/@guardcore/nestjs) |
| [@guardcore/fastify](https://github.com/Guard-Core/guard-core-ts/tree/master/packages/fastify) | Fastify adapter | [![npm](https://img.shields.io/npm/v/@guardcore%2Ffastify)](https://www.npmjs.com/package/@guardcore/fastify) |
| [@guardcore/hono](https://github.com/Guard-Core/guard-core-ts/tree/master/packages/hono) | Hono (edge) adapter | [![npm](https://img.shields.io/npm/v/@guardcore%2Fhono)](https://www.npmjs.com/package/@guardcore/hono) |
| [guardagent](https://github.com/Guard-Core/guard-agent-ts) | Telemetry agent | [![npm](https://img.shields.io/npm/v/guardagent)](https://www.npmjs.com/package/guardagent) |

### Rust

Published on crates.io. **Production-ready.**

| Package | Role | crates.io |
|---|---|---|
| [guard-core-engine](https://github.com/Guard-Core/guard-core-rs) | Core engine crate | [![crates.io](https://img.shields.io/crates/v/guard-core-engine)](https://crates.io/crates/guard-core-engine) |
| [guard-core-rs](https://github.com/Guard-Core/guard-core-rs) | Facade crate (consumer entry point) | [![crates.io](https://img.shields.io/crates/v/guard-core-rs)](https://crates.io/crates/guard-core-rs) |
| [actix-guard-rs](https://github.com/Guard-Core/actix-guard-rs) | Actix Web adapter | [![crates.io](https://img.shields.io/crates/v/actix-guard-rs)](https://crates.io/crates/actix-guard-rs) |
| [axum-guard-rs](https://github.com/Guard-Core/axum-guard-rs) | Axum adapter | [![crates.io](https://img.shields.io/crates/v/axum-guard-rs)](https://crates.io/crates/axum-guard-rs) |
| [tower-guard-rs](https://github.com/Guard-Core/tower-guard-rs) | Tower adapter | [![crates.io](https://img.shields.io/crates/v/tower-guard-rs)](https://crates.io/crates/tower-guard-rs) |
| [rocket-guard-rs](https://github.com/Guard-Core/rocket-guard-rs) | Rocket adapter | [![crates.io](https://img.shields.io/crates/v/rocket-guard-rs)](https://crates.io/crates/rocket-guard-rs) |
| [guard-agent-rs](https://github.com/Guard-Core/guard-agent-rs) | Telemetry agent | [![crates.io](https://img.shields.io/crates/v/guard-agent-rs)](https://crates.io/crates/guard-agent-rs) |

### AI Coding Agents

| Package | Role | PyPI |
|---|---|---|
| [guard-core-mcp](https://github.com/Guard-Core/guard-core-mcp) | MCP server: config validation, docs search, detection sandbox | [![PyPI](https://img.shields.io/pypi/v/guard-core-mcp)](https://pypi.org/project/guard-core-mcp/) |

___

## Documentation

📚 **[Documentation](https://guard-core.github.io/guard-agent-go/latest/)** - full technical documentation for this package.

🛡️ **[Guard Core](https://guard-core.github.io/guard-core/latest/)** - the engine's reference documentation.

🤖 **[Monitoring Agent Integration](https://github.com/Guard-Core/guard-agent)** - monitor your Guard instance with a monitoring agent.
___

## Status

Released. Version `v3.2.2` is tagged and published to the Go module proxy; releases are cut as `v*` git tags.

## Features

- Per-kind queues (events, metrics) with size and time flush triggers and a high-watermark early flush.
- Overflow policies: `drop` (default), `block`, `raise`.
- At-least-once handshake: drain, send, then confirm or requeue in the original order.
- gzip request bodies and an HMAC-SHA256 `v1=` signature that covers the **uncompressed** body, which is what the server verifies after decompression.
- Retry with exponential backoff, `Retry-After` honoring (capped at 300s), 413 recursive split-or-drop, 400/404/422 permanent rejection, 200-partial requeue, per-kind failure-streak backoff, and a 5-failure / 60s circuit breaker.
- Optional Redis persistence: write-on-enqueue with a TTL, delete-on-confirm, reload on `Start`, fail-open on any Redis error.
- Stable install identity persisted to `~/.guard-agent/install-id`.
- Failure isolation: no exported method panics out or blocks the host beyond the configured overflow policy.

## Install

```sh
go get github.com/rennf93/guard-agent-go/v3@v3.2.2
```

Package name is `guardagent`; the module is `github.com/rennf93/guard-agent-go/v3`.

## Usage

```go
package main

import (
	"context"
	"log"

	"github.com/rennf93/guard-agent-go/v3"
)

func main() {
	cfg := guardagent.DefaultConfig()
	cfg.APIKey = "your-ingest-api-key"
	cfg.ProjectID = "your-project-id"
	// cfg.Endpoint = "https://your-guard-core-app.example.com"

	agent, err := guardagent.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	if err := agent.Start(context.Background()); err != nil {
		log.Fatal(err)
	}
	defer func() { _ = agent.Stop(context.Background()) }()

	ctx := context.Background()
	if err := agent.SendEvent(ctx, guardagent.SecurityEvent{
		EventType: "penetration_attempt",
		IPAddress: "203.0.113.7",
		Method:    "GET",
		Endpoint:  "/admin",
		Reason:    "suspicious pattern",
	}); err != nil {
		log.Printf("telemetry: %v", err)
	}
	_ = agent.SendMetric(ctx, guardagent.SecurityMetric{
		MetricType: guardagent.MetricRequestCount,
		Value:      1,
	})
}
```

Redis durability is one field away and never makes the agent depend on Redis being up:

```go
cfg.Redis = &guardagent.RedisConfig{URL: "redis://localhost:6379"}
cfg.SigningSecret = os.Getenv("INGEST_PAYLOAD_SIGNING_SECRET")
```

## Reliability semantics

| Situation | Behavior |
| --- | --- |
| Buffer full, `drop` (default) | Evict the oldest item of that kind, confirm its persisted record, log every 100th drop |
| Buffer full, `block` | Wait for a flush to free space (returns `ctx.Err()` if the context ends first) |
| Buffer full, `raise` | `SendEvent`/`SendMetric` return `*BufferFullError` (`errors.Is(err, guardagent.ErrBufferFull)`) |
| Flush trigger | Combined occupancy at or above `BufferSize * HighWatermarkRatio`, or `FlushInterval` elapsed |
| 200 | Confirm: delete persisted records, reset the failure streak |
| 200 with `success:false` or `errors[]` | Requeue the whole batch in original order (at-least-once: duplicates possible, losses are not) |
| 429 | Honor `Retry-After` (60s default, 300s cap) and retry |
| 413 | Halve the batch and send both halves; a singleton that still 413s is dropped durably |
| 400 / 404 / 422 | Permanent: drop durably, never requeue |
| 401 / 403 / 5xx / network | Retry with `BackoffFactor * 2^attempt` (60s cap) |
| Repeated per-kind failure | Gate that kind for `min(FlushInterval * 2^(streak-1), 300s)` |
| 5 consecutive transport failures | Circuit breaker opens for 60s, then admits one probe (half-open); permanent rejections and 413s are exempt |
| `Status()` | `healthy`, `degraded` (breaker open, 90% occupancy, or >10% lifetime failure rate), or `failed` after `Stop` |
| Redis unavailable | Log, count, keep going; writes pause for 30s after 3 consecutive failures; records expire by TTL |
| `Stop` | Cancel the loops, then one final flush that bypasses the backoff gates |

### The signature covers the uncompressed body

The ingestion API verifies `X-Payload-Signature` **after** its gzip middleware decompresses the request (`telemetry_router.py`, `payload_signature.py`), so the signature must be an HMAC-SHA256 over the uncompressed JSON. This agent signs before compression and sends `v1=<hex>` accordingly.

The Python and TypeScript agents sign the post-compression wire bytes instead, so their signatures stop verifying as soon as gzip kicks in. That mismatch is a known defect on their side; this agent intentionally does not reproduce it, and the test suite asserts the server-side semantic with a mock that decompresses first and verifies second.

### Dynamic rules

`GetDynamicRules(ctx)` fetches the SaaS rule document from `GET /api/v1/rules` (the full Python-agent `DynamicRules` surface) and caches it for the document's `ttl`; a failed poll serves the last known rules. `Start` runs a background polling loop on `DynamicRuleInterval`, and `Stats().RulesFetched` counts refreshes. `TruncatePayload`, `HashIP`, and `KnownEventTypes` round out the host-adapter helper surface.

## Configuration

Start from `guardagent.DefaultConfig()` and override. `RetryAttempts` and `CompressionThreshold` are zero-honest (0 means zero retries, and 0 compresses every body); the feature booleans are false in a hand-built `Config{}`.

| Field | Default | Notes |
| --- | --- | --- |
| `APIKey` | required | At least 10 characters |
| `Endpoint` | `https://api.guard-core.com` | Trailing `/` and `/api/v1` are stripped |
| `ProjectID` | empty | Sent as `X-Project-Id` |
| `BufferSize` | 100 | Per-kind capacity |
| `FlushInterval` | 30s | Flush cadence and backoff base |
| `StatusInterval` | 300s | Minimum 60s |
| `DynamicRuleInterval` | 300s | Dynamic rules polling cadence, minimum 60s |
| `HighWatermarkRatio` | 0.8 | Early flush threshold |
| `MaxConcurrentFlushes` | 1 | Wake-driven flushers |
| `Overflow` | `drop` | `drop`, `block`, `raise` |
| `RetryAttempts` | 3 via `DefaultConfig()` | 0 disables retries |
| `Timeout` | 30s | Per request |
| `BackoffFactor` | 1.0 | Seconds, base of `2^attempt` |
| `CompressionEnabled` / `CompressionThreshold` | true / 1024 | gzip at or above the threshold |
| `SigningSecret` | empty | Enables `X-Payload-Signature` |
| `SensitiveHeaders` | defaults | Header names redacted from event metadata and metric tags (case-insensitive); nil = defaults, non-nil replaces |
| `MaxPayloadSize` | 1024 | Payload size (bytes) to truncate at with `TruncatePayload` before embedding in event metadata |
| `OnError` | nil | Best-effort failure callback `(stage, err, context)`; stages: `transport_send`, `encryption`, `flush_events`, `flush_metrics` |
| `InstallID` / `InstallIDPath` | auto / `~/.guard-agent/install-id` | Override either |
| `Redis` | nil | `URL`, `Prefix` (`guard:agent`), `TTL` (1h) |
| `GuardVersion` / `GuardCoreVersion` | empty | Reported to the API |

## Development

```sh
go build ./...
gofmt -l .
go vet ./...
go test ./...
REDIS_HOST=127.0.0.1 go test -tags integration ./...
go install golang.org/x/vuln/cmd/govulncheck@latest && govulncheck ./...
```

The integration build skips itself when `REDIS_HOST` is unset. On hosts without a Go toolchain, run the same commands in `golang:1.25-alpine` with a `redis:7-alpine` container reachable as `redis` on a shared Docker network.

## Links

- [guard-core](https://github.com/Guard-Core/guard-core): the Python engine that anchors the ecosystem.
- [guard-agent](https://github.com/Guard-Core/guard-agent) / [guard-agent-rs](https://github.com/Guard-Core/guard-agent-rs): Python and Rust sibling agents.
- [guard-core-app](https://github.com/Guard-Core/guard-core-app): hosts the ingestion API.
- [gin-guard](https://github.com/Guard-Core/gin-guard) / [nethttp-guard](https://github.com/Guard-Core/nethttp-guard): Go adapters that emit the events.

## License

MIT
