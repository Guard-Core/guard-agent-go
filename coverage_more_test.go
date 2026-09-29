package guardagent

// Coverage tests, unit tier part two: the transport, dynamic-rules, and
// agent branches that need targeted seams or crafted inputs. Redis-backed
// durability branches live in coverage_integration_test.go.

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeAEAD is a cipher.AEAD whose Open always fails, so VerifyKey's
// decrypt-failure branch can be exercised deterministically.
type fakeAEAD struct{}

func (fakeAEAD) NonceSize() int                                { return 12 }
func (fakeAEAD) Overhead() int                                 { return 16 }
func (fakeAEAD) Seal(dst, nonce, plaintext, aad []byte) []byte { return append(dst, plaintext...) }
func (fakeAEAD) Open(dst, nonce, ciphertext, aad []byte) ([]byte, error) {
	return nil, errors.New("open exploded")
}

func TestVerifyKeyFailsWhenDecryptFails(t *testing.T) {
	p := &PayloadEncryptor{aead: fakeAEAD{}}
	if p.VerifyKey() {
		t.Fatal("VerifyKey must fail when the round-trip open fails")
	}
}

func TestPayloadTooLargeErrorRenders(t *testing.T) {
	err := &payloadTooLargeError{detail: "huge"}
	if err.Error() != "guardagent: payload too large: huge" {
		t.Fatalf("payloadTooLargeError message mismatch: %q", err.Error())
	}
}

func TestCanonicalJSONWritesFalseBool(t *testing.T) {
	if got := canonicalJSON(map[string]any{"flag": false}); got != `{"flag":false}` {
		t.Fatalf("false bool must render, got %s", got)
	}
}

func TestResolveInstallIDFallsBackToDefaultPathAndMemory(t *testing.T) {
	t.Setenv("HOME", "")
	logger := log.New(io.Discard, "", 0)
	// Empty override and empty default path resolve a fresh in-memory id.
	if id := resolveInstallID("", "", logger); id == "" {
		t.Fatal("no override, state path, or home must still yield an id")
	}
}

func TestCanonicalItemsJSONDecodeFailure(t *testing.T) {
	// Malformed canonical bytes (from the marshal seam) must surface as a
	// decode failure for both kinds.
	jsonMarshal = func(v any) ([]byte, error) { return []byte("{not json"), nil }
	defer func() { jsonMarshal = jsonMarshalProd }()
	if _, err := canonicalItemsJSON([]SecurityEvent{testEvent(1, "")}, nil); err == nil {
		t.Fatal("event decode failure must surface")
	}
	jsonMarshal = func(v any) ([]byte, error) { return []byte("[1,"), nil }
	if _, err := canonicalItemsJSON(nil, []SecurityMetric{testMetric(1)}); err == nil {
		t.Fatal("metric decode failure must surface")
	}
	jsonMarshal = jsonMarshalProd
}

func TestSendEncryptedBatchEnvelopeMarshalFailure(t *testing.T) {
	withSeamRestore := func() { jsonMarshal = jsonMarshalProd }
	defer withSeamRestore()
	jsonMarshal = func(v any) ([]byte, error) {
		// Fail only the envelope step: items and inner maps marshal fine.
		if _, ok := v.(encryptedEnvelope); ok {
			return nil, errors.New("envelope marshal exploded")
		}
		return jsonMarshalProd(v)
	}
	tr := newTransport(DefaultConfig(), "install", nil, log.New(io.Discard, "", 0))
	tr.encryptor = &PayloadEncryptor{aead: fakeAEAD{}}
	outcome, err := tr.sendEncryptedBatch(context.Background(), []SecurityEvent{testEvent(1, "")}, nil)
	if outcome != outcomePartial || err == nil {
		t.Fatalf("envelope marshal failure must be partial, got %v %v", outcome, err)
	}
}

// jsonMarshalProd mirrors the production marshaler; the test file swaps the
// seam and restores it to this value.
var jsonMarshalProd = json.Marshal

func TestMarshalBatchRemarshalFailure(t *testing.T) {
	withSeamRestore := func() { jsonMarshal = jsonMarshalProd }
	defer withSeamRestore()
	calls := 0
	jsonMarshal = func(v any) ([]byte, error) {
		calls++
		if calls >= 2 {
			return nil, errors.New("remarshal exploded")
		}
		return jsonMarshalProd(v)
	}
	cfg := DefaultConfig()
	cfg.CompressionThreshold = 16
	tr := newTransport(cfg, "install", nil, log.New(io.Discard, "", 0))
	batch := &eventBatch{ProjectID: "p", Events: []SecurityEvent{testEvent(1, strings.Repeat("x", 64))}}
	if _, err := tr.marshalBatch(batch); err == nil {
		t.Fatal("a failed compression re-marshal must surface")
	}
}

func TestSendBatchLocalLimiterDefersThenSends(t *testing.T) {
	m := newMockIngest(t)
	cfg := DefaultConfig()
	cfg.APIKey = "test-api-key-123"
	cfg.Endpoint = m.URL
	cfg.ProjectID = "acme"
	cfg.RetryAttempts = 1
	tr := newTransport(cfg, "install", nil, log.New(io.Discard, "", 0))
	tr.limiter = newRateLimiter(1, 20*time.Millisecond)
	tr.limiter.mu.Lock()
	tr.limiter.calls = []time.Time{time.Now()}
	tr.limiter.mu.Unlock()
	outcome, err := tr.sendBatch(context.Background(), eventsPath, []byte(`{}`), true)
	if outcome != outcomeAccepted || err != nil {
		t.Fatalf("a deferred local gate must retry and accept, got %v %v", outcome, err)
	}
	if got := len(m.callsTo(eventsPath)); got != 1 {
		t.Fatalf("the deferred attempt must not reach the API, got %d calls", got)
	}
}

func TestSendMetricsThroughEncryptor(t *testing.T) {
	m := newMockIngest(t)
	cfg := DefaultConfig()
	cfg.APIKey = "test-api-key-123"
	cfg.Endpoint = m.URL
	cfg.ProjectEncryptionKey = testEncryptionKey()
	tr := newTransport(cfg, "install", nil, log.New(io.Discard, "", 0))
	encryptor, err := NewPayloadEncryptor(testEncryptionKey())
	if err != nil {
		t.Fatalf("encryptor: %v", err)
	}
	tr.encryptor = encryptor
	outcome, err := tr.sendMetrics(context.Background(), []SecurityMetric{testMetric(1)})
	if outcome != outcomeAccepted || err != nil {
		t.Fatalf("encrypted metrics must confirm, got %v %v", outcome, err)
	}
	if len(m.callsTo(encryptedPath)) != 1 {
		t.Fatal("encrypted metrics must hit the encrypted endpoint")
	}
}

func TestSplitOrDropEventsFailsWhenHalfFails(t *testing.T) {
	m := newMockIngest(t)
	cfg := DefaultConfig()
	cfg.APIKey = "test-api-key-123"
	cfg.Endpoint = m.URL
	cfg.RetryAttempts = 0
	tr := newTransport(cfg, "install", nil, log.New(io.Discard, "", 0))
	// Four events: the full batch trips the size guard, both halves fit,
	// and the first half fails so the aggregate reports failure.
	pad := strings.Repeat("x", 40)
	events := make([]SecurityEvent, 4)
	for i := range events {
		events[i] = testEvent(i, pad)
	}
	m.setMaxBody(320)
	m.failNext(2)
	if outcome := tr.splitOrDropEvents(context.Background(), events); outcome != outcomeFailed {
		t.Fatalf("a failed split half must fail the aggregate, got %v", outcome)
	}
	m.clearKnobs()
	m.setMaxBody(262144)
}

func TestSendBatchNewRequestFailure(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKey = "test-api-key-123"
	cfg.Endpoint = "://bad endpoint"
	tr := newTransport(cfg, "install", nil, log.New(io.Discard, "", 0))
	outcome, err := tr.sendBatch(context.Background(), eventsPath, []byte(`{}`), true)
	if outcome != outcomeFailed || err == nil {
		t.Fatalf("an unparseable endpoint must fail the request build, got %v %v", outcome, err)
	}
}

func TestSendBatchRetriesAfter429(t *testing.T) {
	m := newMockIngest(t)
	cfg := DefaultConfig()
	cfg.APIKey = "test-api-key-123"
	cfg.Endpoint = m.URL
	cfg.RetryAttempts = 2
	cfg.BackoffFactor = 0.001
	tr := newTransport(cfg, "install", nil, log.New(io.Discard, "", 0))
	m.rateLimitNext(1, "0.05")
	outcome, err := tr.sendBatch(context.Background(), eventsPath, []byte(`{}`), true)
	if outcome != outcomeAccepted || err != nil {
		t.Fatalf("a 429 followed by a success must accept, got %v %v", outcome, err)
	}
	if got := len(m.callsTo(eventsPath)); got != 2 {
		t.Fatalf("the batch must retry once after the 429, got %d calls", got)
	}
}

func TestEncodeBodyCloseFailure(t *testing.T) {
	withSeamRestore := func() { newGzipWriter = gzipNewWriter }
	defer withSeamRestore()
	calls := 0
	newGzipWriter = func(w io.Writer) *gzip.Writer {
		return gzip.NewWriter(failOnCallN(3, func() { calls++ }))
	}
	cfg := DefaultConfig()
	cfg.CompressionThreshold = 16
	tr := newTransport(cfg, "install", nil, log.New(io.Discard, "", 0))
	raw := []byte(strings.Repeat("a", 2048))
	wire, encoding := tr.encodeBody(raw)
	if encoding != "" || !bytes.Equal(wire, raw) {
		t.Fatalf("a failing gzip close must fall back to plain bytes, got %q %d", encoding, len(wire))
	}
}

// failOnCallN returns a writer whose Write calls succeed until the n-th,
// which fails along with every later one: gzip buffers its header and data
// in early writes and flushes the footer on Close, so the failure lands on
// the close path.
func failOnCallN(n int, note func()) io.Writer {
	return &countingFailWriter{limit: n, note: note}
}

type countingFailWriter struct {
	limit int
	calls int
	note  func()
}

func (w *countingFailWriter) Write(p []byte) (int, error) {
	w.calls++
	w.note()
	if w.calls >= w.limit {
		return 0, errors.New("write exploded on call")
	}
	return len(p), nil
}

func TestNewFailsWhenRoundTripVerificationFails(t *testing.T) {
	withSeamRestore := func() { cryptoRandRead = randRead }
	defer withSeamRestore()
	cryptoRandRead = func(b []byte) (int, error) { return 0, errors.New("no entropy") }
	cfg := DefaultConfig()
	cfg.APIKey = "test-api-key-123"
	cfg.ProjectEncryptionKey = testEncryptionKey()
	cfg.InstallIDPath = filepath.Join(t.TempDir(), "install-id")
	_, err := New(cfg)
	var cfgErr *EncryptionConfigError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("a failed round-trip must fail construction, got %v", err)
	}
}

func TestNormalizeRejectsUnparseableRedisURL(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKey = "test-api-key-123"
	cfg.Redis = &RedisConfig{URL: "redis://127.0.0.1:6379/\x7f", Prefix: "p", TTL: time.Minute}
	_, _, err := normalize(cfg)
	if err == nil || !strings.Contains(err.Error(), "redis url must be") {
		t.Fatalf("an unparseable redis url must be rejected, got %v", err)
	}
}

func TestFetchDynamicRulesLimiterAndRequestBuild(t *testing.T) {
	m := newMockIngest(t)
	cfg := DefaultConfig()
	cfg.APIKey = "test-api-key-123"
	cfg.Endpoint = m.URL
	cfg.RetryAttempts = 1
	cfg.BackoffFactor = 0.001
	tr := newTransport(cfg, "install", nil, log.New(io.Discard, "", 0))
	ctx := context.Background()

	// A saturated local limiter burns attempts: with retries left the gate
	// defers and the fetch proceeds on the freed slot; without them it
	// errors out.
	tr.limiter = newRateLimiter(1, 20*time.Millisecond)
	saturate := func() {
		tr.limiter.mu.Lock()
		tr.limiter.calls = []time.Time{time.Now()}
		tr.limiter.mu.Unlock()
	}
	m.serveRules(http.StatusOK, sampleRulesJSON())
	saturate()
	if _, err := tr.fetchDynamicRules(ctx); err != nil {
		t.Fatalf("a deferred gate retries, got %v", err)
	}
	noRetries := newTransport(cfg, "install", nil, log.New(io.Discard, "", 0))
	noRetries.cfg.RetryAttempts = 0
	noRetries.limiter = newRateLimiter(1, 20*time.Millisecond)
	noRetries.limiter.mu.Lock()
	noRetries.limiter.calls = []time.Time{time.Now()}
	noRetries.limiter.mu.Unlock()
	if _, err := noRetries.fetchDynamicRules(ctx); err == nil || !strings.Contains(err.Error(), "local rate limit") {
		t.Fatalf("an exhausted attempt budget must error, got %v", err)
	}

	// An unparseable endpoint fails the request build.
	bad := newTransport(cfg, "install", nil, log.New(io.Discard, "", 0))
	bad.cfg.Endpoint = "://bad endpoint"
	if _, err := bad.fetchDynamicRules(ctx); err == nil {
		t.Fatal("an unparseable endpoint must fail the request build")
	}

	// An open circuit breaker rejects the fetch before any request.
	open := newTransport(cfg, "install", nil, log.New(io.Discard, "", 0))
	for i := 0; i < breakerFailureThreshold; i++ {
		open.breaker.Failure()
	}
	if _, err := open.fetchDynamicRules(ctx); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("an open circuit must reject the fetch, got %v", err)
	}
}

func TestSendMetricAfterStop(t *testing.T) {
	m := newMockIngest(t)
	agent := newTestAgent(t, m, nil)
	_ = agent.Stop(context.Background())
	err := agent.SendMetric(context.Background(), testMetric(1))
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("SendMetric after Stop must return ErrClosed, got %v", err)
	}
}

func TestOverflowBlockPollsWhileWaiting(t *testing.T) {
	for _, kind := range []string{kindEvent, kindMetric} {
		t.Run(kind, func(t *testing.T) {
			m := newMockIngest(t)
			// The agent is deliberately not started: no flusher runs, so
			// the blocked sender stays parked until the poll fires.
			agent := newTestAgent(t, m, func(c *Config) {
				c.BufferSize = 1
				c.HighWatermarkRatio = 1.0
				c.Overflow = OverflowBlock
			})
			ctx := context.Background()
			if kind == kindEvent {
				if err := agent.SendEvent(ctx, testEvent(1, "")); err != nil {
					t.Fatalf("SendEvent: %v", err)
				}
			} else {
				if err := agent.SendMetric(ctx, testMetric(1)); err != nil {
					t.Fatalf("SendMetric: %v", err)
				}
			}
			canceled, cancel := context.WithCancel(ctx)
			done := make(chan error, 1)
			go func() {
				if kind == kindEvent {
					done <- agent.SendEvent(canceled, testEvent(2, ""))
				} else {
					done <- agent.SendMetric(canceled, testMetric(2))
				}
			}()
			// The blocked sender polls (500ms) before the context ends.
			time.Sleep(700 * time.Millisecond)
			cancel()
			if err := <-done; !errors.Is(err, context.Canceled) {
				t.Fatalf("block policy must honor the context after polling, got %v", err)
			}
			_ = agent.Stop(ctx)
		})
	}
}

func TestSettleMetricsNilErrorAfterFailedSplit(t *testing.T) {
	m := newMockIngest(t)
	agent := newTestAgent(t, m, func(c *Config) { c.RetryAttempts = 0 })
	// Four metrics: the full batch trips the size guard, both halves fit,
	// and the first half fails with 500s so the aggregate reports failure
	// with a nil error, which settleMetrics must replace before requeueing.
	pad := strings.Repeat("x", 40)
	for i := 0; i < 4; i++ {
		metric := testMetric(i)
		metric.Tags = map[string]string{"pad": pad}
		if err := agent.SendMetric(context.Background(), metric); err != nil {
			t.Fatalf("SendMetric: %v", err)
		}
	}
	m.setMaxBody(320)
	m.failNext(2)
	if err := agent.Flush(context.Background()); err == nil {
		t.Fatal("the failed split must surface a synthetic error")
	}
	if agent.Stats().MetricsPending != 4 {
		t.Fatalf("the failed split must requeue everything, got %+v", agent.Stats())
	}
	_ = agent.Stop(context.Background())
}

func TestReportStatusRecoversFromPanic(t *testing.T) {
	m := newMockIngest(t)
	agent := newTestAgent(t, m, nil, WithHTTPClient(&http.Client{Transport: panicRoundTripper{}}))
	agent.reportStatus(context.Background())
	if agent.Stats().StatusReportsFailed != 1 {
		t.Fatalf("a status panic must count as failed, got %+v", agent.Stats())
	}
	_ = agent.Stop(context.Background())
}

func TestReserveKeysMarshalFailureCountsAndRecords(t *testing.T) {
	logger := log.New(io.Discard, "", 0)
	agent := &Agent{
		logger:  logger,
		tr:      newTransport(DefaultConfig(), "install", nil, logger),
		persist: &persistence{logger: logger},
	}
	poisoned := SecurityEvent{EventType: "e", Metadata: map[string]any{"chan": make(chan int)}}
	agent.mu.Lock()
	key := agent.reserveEventKeyLocked(poisoned)
	agent.mu.Unlock()
	if key != "" {
		t.Fatal("an unserializable event must not reserve a key")
	}
	if agent.Stats().RedisPersistFailures != 1 {
		t.Fatalf("serialization failures must count, got %+v", agent.Stats())
	}
	// A serializable metric still fails the persistence write against a
	// dead Redis, which must also refuse the key and count the failure.
	deadPersist, err := newPersistence(&RedisConfig{URL: "redis://127.0.0.1:1", Prefix: "p", TTL: time.Minute}, logger)
	if err != nil {
		t.Fatalf("newPersistence: %v", err)
	}
	agent.persist = deadPersist
	agent.mu.Lock()
	metricKey := agent.reserveMetricKeyLocked(SecurityMetric{MetricType: MetricRequestCount})
	agent.mu.Unlock()
	if metricKey != "" {
		t.Fatal("a failing store must not reserve a metric key")
	}
	if agent.Stats().RedisPersistFailures != 2 {
		t.Fatalf("store failures must count, got %+v", agent.Stats())
	}
}

func TestFlushIfNeededWakesEmptyAndWatermark(t *testing.T) {
	m := newMockIngest(t)
	agent := newTestAgent(t, m, func(c *Config) {
		c.BufferSize = 2
		c.HighWatermarkRatio = 0.5
	})
	ctx := context.Background()
	if err := agent.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// A wake with an empty buffer must be a no-op (given time to consume).
	agent.triggerFlush()
	time.Sleep(50 * time.Millisecond)
	// A single item crosses the 0.5 watermark of a 2-slot buffer: the wake
	// flusher must drain it even though no interval elapsed.
	if err := agent.SendEvent(ctx, testEvent(1, "")); err != nil {
		t.Fatalf("SendEvent: %v", err)
	}
	waitUntil(t, 5*time.Second, "watermark wake must flush", func() bool {
		return agent.Stats().EventsPending == 0 && agent.Stats().EventsSent == 1
	})
	_ = agent.Stop(ctx)
}
