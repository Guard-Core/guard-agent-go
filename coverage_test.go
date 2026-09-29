package guardagent

// Coverage tests, unit tier: deterministic branches that need no Redis.
// Redis-backed durability branches live in coverage_integration_test.go.

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Seams are restored to these production values.
var (
	randRead      = crand.Read
	gzipNewWriter = gzip.NewWriter
)

func base64Pad(b []byte) string { return base64.URLEncoding.EncodeToString(b) }

func errWriter() io.Writer {
	return failingWriter{}
}

type failingWriter struct{}

func (failingWriter) Write(p []byte) (int, error) { return 0, errors.New("write exploded") }

// sealRawPlaintext seals arbitrary bytes with the project key exactly like
// PayloadEncryptor does, so tests can present well-formed ciphertexts with
// arbitrary plaintexts.
func sealRawPlaintext(projectKey, plaintext string) (string, error) {
	key, err := decodeUrlsafeBase64(projectKey)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, encryptionNonceSize)
	if _, err := randRead(nonce); err != nil {
		return "", err
	}
	return encodeUrlsafeBase64(aead.Seal(nonce, nonce, []byte(plaintext), nil)), nil
}

func testEncryptionKey() string {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return base64Pad(key)
}

// ------------------------------------------------------------ errors.go --

func TestTypedErrorMessages(t *testing.T) {
	bufferFull := &BufferFullError{Kind: "event", MaxLen: 5}
	if !strings.Contains(bufferFull.Error(), "event buffer full at maxlen=5") {
		t.Fatalf("BufferFullError message mismatch: %q", bufferFull.Error())
	}
	permanent := &PermanentError{StatusCode: 400, Detail: "bad"}
	if !strings.Contains(permanent.Error(), "permanent rejection with status 400: bad") {
		t.Fatalf("PermanentError message mismatch: %q", permanent.Error())
	}
	rateLimited := &RateLimitedError{RetryAfter: 7 * time.Second}
	if rateLimited.Error() != "guardagent: rate limited, retry after 7s" {
		t.Fatalf("RateLimitedError message mismatch: %q", rateLimited.Error())
	}
	if !errors.Is(bufferFull, ErrBufferFull) {
		t.Fatal("BufferFullError must match ErrBufferFull")
	}
}

// --------------------------------------------------------- encryption.go --

func TestEncryptionErrorMessages(t *testing.T) {
	enc := &EncryptionError{"boom"}
	if enc.Error() != "boom" {
		t.Fatalf("EncryptionError message mismatch: %q", enc.Error())
	}
	cfgErr := &EncryptionConfigError{"no fallback"}
	if cfgErr.Error() != "no fallback" {
		t.Fatalf("EncryptionConfigError message mismatch: %q", cfgErr.Error())
	}
}

func TestNewPayloadEncryptorRejectsBadKeys(t *testing.T) {
	if _, err := NewPayloadEncryptor(""); err == nil || !strings.Contains(err.Error(), "cannot be empty") {
		t.Fatalf("empty key must be rejected, got %v", err)
	}
	if _, err := NewPayloadEncryptor("!!!! not base64 !!!"); err == nil || !strings.Contains(err.Error(), "Invalid project key format") {
		t.Fatalf("invalid base64 must be rejected, got %v", err)
	}
	short := base64Pad(make([]byte, 16))
	if _, err := NewPayloadEncryptor(short); err == nil || !strings.Contains(err.Error(), "Invalid key size: 16") {
		t.Fatalf("short key must be rejected, got %v", err)
	}
}

func TestEncryptDecryptRoundTripWithAssociatedData(t *testing.T) {
	p, err := NewPayloadEncryptor(testEncryptionKey())
	if err != nil {
		t.Fatalf("encryptor: %v", err)
	}
	payload := map[string]any{"b": 2, "a": "x"}
	sealed, err := p.Encrypt(payload, "project-42")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	opened, err := p.Decrypt(sealed, "project-42")
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if opened["a"] != "x" {
		t.Fatalf("round trip mismatch: %v", opened)
	}
	// AAD mismatch must fail the GCM open.
	if _, err := p.Decrypt(sealed, "other-project"); err == nil {
		t.Fatal("decrypt with the wrong associated data must fail")
	}
}

func TestDecryptRejectsMalformedPayloads(t *testing.T) {
	p, err := NewPayloadEncryptor(testEncryptionKey())
	if err != nil {
		t.Fatalf("encryptor: %v", err)
	}
	if _, err := p.Decrypt("!!!", ""); err == nil {
		t.Fatal("invalid base64 must fail")
	}
	short := base64Pad(make([]byte, 8))
	if _, err := p.Decrypt(short, ""); err == nil {
		t.Fatal("truncated payload must fail")
	}
	sealed, err := p.Encrypt(map[string]any{"a": 1}, "")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	// Corrupt one ciphertext byte in the middle.
	raw, err := decodeUrlsafeBase64(sealed)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	raw[len(raw)/2] ^= 0xFF
	if _, err := p.Decrypt(encodeUrlsafeBase64(raw), ""); err == nil {
		t.Fatal("tampered payload must fail")
	}
	// A valid GCM payload whose plaintext is not a JSON object (null) and
	// one whose plaintext is not JSON at all, both sealed with the same key.
	for name, plaintext := range map[string]string{"null": "null", "junk": "not json"} {
		sealedPlaintext, err := sealRawPlaintext(testEncryptionKey(), plaintext)
		if err != nil {
			t.Fatalf("seal %s: %v", name, err)
		}
		if _, err := p.Decrypt(sealedPlaintext, ""); err == nil {
			t.Fatalf("a %s plaintext must fail to decode as an object", name)
		}
	}
}

func TestEncryptFailsWithoutEntropy(t *testing.T) {
	cryptoRandRead = func(b []byte) (int, error) { return 0, errors.New("no entropy") }
	defer func() { cryptoRandRead = randRead }()
	p, err := NewPayloadEncryptor(testEncryptionKey())
	if err != nil {
		t.Fatalf("encryptor: %v", err)
	}
	if _, err := p.Encrypt(map[string]any{"a": 1}, ""); err == nil {
		t.Fatal("Encrypt must surface the entropy failure")
	}
	// The startup round-trip verification must report the failure too.
	if p.VerifyKey() {
		t.Fatal("VerifyKey must fail when encryption fails")
	}
	// Identifier generators must fall back instead of failing.
	if id := newUUID4(); len(id) != 36 {
		t.Fatalf("uuid fallback must still produce a shaped id, got %q", id)
	}
	if h := randomHex(4); len(h) != 8 {
		t.Fatalf("randomHex fallback must still produce hex, got %q", h)
	}
}

func TestCanonicalJSONPythonShape(t *testing.T) {
	payload := map[string]any{
		"int8":    int8(-8),
		"int16":   int16(-16),
		"int32":   int32(-32),
		"int64":   int64(-64),
		"uint":    uint(1),
		"uint8":   uint8(8),
		"uint16":  uint16(16),
		"uint32":  uint32(32),
		"uint64":  uint64(64),
		"float32": float32(0.5),
		"float64": 2.0,
		"neg":     -3.0,
		"big":     1e20,
		"raw":     json.RawMessage(`{"raw":true}`),
		"number":  json.Number("42"),
		"slice":   []any{nil, true, "x"},
		"nested":  map[string]any{"z": 1, "a": map[string]any{"deep": 3.25}},
		"time":    time.Unix(0, 0).UTC(),
		"chan":    make(chan int),
	}
	got := canonicalJSON(payload)
	for _, want := range []string{
		`"int8":-8`, `"uint64":64`, `"float32":0.5`, `"float64":2.0`,
		`"neg":-3.0`, `"big":1e+20`, `"raw":{"raw":true}`, `"number":42`,
		`"slice":[null,true,"x"]`, `"nested":{"a":{"deep":3.25},"z":1}`,
		`"time":"1970-01-01T00:00:00Z"`, `"chan":null`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("canonical JSON missing %s in %s", want, got)
		}
	}
	// Keys must be sorted recursively: "nested" comes after "number" and
	// before "raw".
	if strings.Index(got, `"nested"`) > strings.Index(got, `"raw"`) {
		t.Fatalf("keys must be sorted: %s", got)
	}
}

func TestCanonicalStringEscaping(t *testing.T) {
	cases := map[string]string{
		"quote\":back\\":         `"quote\":back\\"`,
		"\b\f\n\r\t":             `"\b\f\n\r\t"`,
		"ascii ok":               `"ascii ok"`,
		"café":                   `"caf\u00e9"`,
		"emoji \U0001F600":       `"emoji \ud83d\ude00"`,
		"caf\u00e9 latin":        `"caf\u00e9 latin"`,
		string([]byte{0x01}):     `"\u0001"`,
		string([]rune{0x10FFFF}): `"\udbff\udfff"`,
	}
	for input, want := range cases {
		var b strings.Builder
		writeCanonicalString(input, &b)
		if b.String() != want {
			t.Fatalf("escape %q: got %s want %s", input, b.String(), want)
		}
	}
}

func TestCreateEncryptorNilWithoutKey(t *testing.T) {
	p, err := CreateEncryptor("")
	if p != nil || err != nil {
		t.Fatalf("empty key must yield a nil encryptor, got %v %v", p, err)
	}
}

// ---------------------------------------------------------- install_id.go --

func TestResolveInstallIDPaths(t *testing.T) {
	logger := log.New(io.Discard, "", 0)
	if id := resolveInstallID("explicit", "", logger); id != "explicit" {
		t.Fatalf("override must win, got %q", id)
	}
	dir := t.TempDir()
	statePath := filepath.Join(dir, "sub", "install-id")
	first := resolveInstallID("", statePath, logger)
	second := resolveInstallID("", statePath, logger)
	if first == "" || first != second {
		t.Fatalf("install id must persist across resolves, got %q then %q", first, second)
	}
	// A whitespace-only file falls through to a fresh id.
	emptyPath := filepath.Join(dir, "empty-id")
	if err := os.WriteFile(emptyPath, []byte("  \n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if id := resolveInstallID("", emptyPath, logger); id == "" {
		t.Fatal("whitespace file must produce a fresh id")
	}
	// A directory at the state path: read fails (logged, not ErrNotExist),
	// the write also fails, and the id still resolves in memory.
	if id := resolveInstallID("", dir, logger); id == "" {
		t.Fatal("unreadable state file must fall back to an in-memory id")
	}
	// A path under a regular file: MkdirAll fails and is logged.
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if id := resolveInstallID("", filepath.Join(blocker, "sub", "id"), logger); id == "" {
		t.Fatal("uncreatable state directory must fall back to an in-memory id")
	}
	// A file with a genuine read error (permission denied).
	denied := filepath.Join(dir, "denied")
	if err := os.WriteFile(denied, []byte("secret"), 0o000); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Chmod(denied, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	resolveInstallID("", denied, logger) // must log, not crash
	_ = os.Chmod(denied, 0o644)
}

func TestDefaultInstallIDPathWithoutHome(t *testing.T) {
	t.Setenv("HOME", "")
	if path := defaultInstallIDPath(); path != "" {
		t.Fatalf("no home must yield an empty default path, got %q", path)
	}
}

// ---------------------------------------------------------- redact.go --

func TestSanitizeHeadersDeepStructures(t *testing.T) {
	sensitive := []string{"Authorization"}
	deep := map[string]any{}
	cursor := deep
	for i := 0; i < 15; i++ {
		next := map[string]any{}
		cursor["deep"] = next
		cursor = next
	}
	got := SanitizeHeaders(map[string]any{
		"list":      []any{"a", 2, map[string]any{"authorization": "s"}},
		"strings":   []string{"x", "y"},
		"jsonScan":  `{"authorization":"s","keep":1}`,
		"jsonDeep":  "[1,2,3]",
		"badJSON":   "{not json",
		"whole":     strings.Repeat("{", maxJSONScanLen+1),
		"plain":     "hello",
		"empty":     "   ",
		"scalar":    3.14,
		"bytes":     []byte("bytes"),
		"duration":  time.Second,
		"jsonNum":   json.Number("9"),
		"deepLimit": deep,
		"func":      func() {},
	}, sensitive)
	m, ok := got.(map[string]any)
	if !ok {
		t.Fatalf("sanitize must return a map, got %T", got)
	}
	if m["func"] != redactedMarker {
		t.Fatalf("unrepresentable values must redact, got %v", m["func"])
	}
	if strings.Contains(fmt.Sprint(m["jsonScan"]), "s") {
		t.Fatalf("sensitive key inside a JSON string must redact: %v", m["jsonScan"])
	}
	if m["plain"] != "hello" || m["badJSON"] != "{not json" || m["empty"] != "   " {
		t.Fatalf("non-JSON and unparseable strings must pass through: %v", m)
	}
	if m["whole"] != redactedMarker {
		t.Fatalf("oversized JSON candidates must redact wholesale, got %v", m["whole"])
	}
	if strings.Contains(fmt.Sprint(m["deepLimit"]), `"secret"`) {
		t.Fatalf("over-depth subtree must redact wholesale: %v", m["deepLimit"])
	}
	list, ok := m["list"].([]any)
	if !ok {
		t.Fatalf("lists must survive: %T", m["list"])
	}
	listMap, ok := list[2].(map[string]any)
	if !ok || listMap["authorization"] != redactedMarker {
		t.Fatalf("sensitive keys inside list entries must redact: %v", list[2])
	}
	// map[string]string values sanitize through the same walker.
	strMap := SanitizeHeaders(map[string]string{
		"authorization": "secret",
		"json":          `{"authorization":"s"}`,
		"plain":         "ok",
	}, nil).(map[string]string)
	if strMap["authorization"] != redactedMarker {
		t.Fatalf("sensitive map values must redact: %v", strMap)
	}
	if strMap["json"] != `{"authorization":"[REDACTED]"}` {
		t.Fatalf("JSON-looking values must reserialize sanitized: %q", strMap["json"])
	}
	if strMap["plain"] != "ok" {
		t.Fatalf("plain values must pass: %q", strMap["plain"])
	}
	// Nil sensitive headers fall back to the defaults.
	fallback := SanitizeHeaders(map[string]any{"Cookie": "c"}, nil).(map[string]any)
	if fallback["Cookie"] != redactedMarker {
		t.Fatalf("default sensitive set must apply, got %v", fallback)
	}
}

func TestRedactEventAndMetricCopies(t *testing.T) {
	ev := SecurityEvent{EventType: "e", Metadata: map[string]any{"authorization": "s", "n": 1}}
	redacted := redactEventMetadata(ev, nil)
	if redacted.Metadata["authorization"] != redactedMarker {
		t.Fatalf("sensitive metadata must redact: %v", redacted.Metadata)
	}
	if ev.Metadata["authorization"] != "s" {
		t.Fatal("the input map must never be mutated")
	}
	if kept := redactEventMetadata(SecurityEvent{EventType: "e"}, nil); kept.Metadata != nil {
		t.Fatalf("nil metadata must pass through untouched: %v", kept.Metadata)
	}
	metric := SecurityMetric{MetricType: MetricRequestCount, Tags: map[string]string{"x-api-key": "s"}}
	tagged := redactMetricTags(metric, nil)
	if tagged.Tags["x-api-key"] != redactedMarker {
		t.Fatalf("sensitive tags must redact: %v", tagged.Tags)
	}
	if kept := redactMetricTags(SecurityMetric{MetricType: MetricRequestCount}, nil); kept.Tags != nil {
		t.Fatalf("nil tags must pass through untouched: %v", kept.Tags)
	}
	batch := &eventBatch{Events: []SecurityEvent{ev}, Metrics: []SecurityMetric{metric}}
	redactBatch(batch, nil)
	if batch.Events[0].Metadata["authorization"] != redactedMarker ||
		batch.Metrics[0].Tags["x-api-key"] != redactedMarker {
		t.Fatalf("batch redaction must cover both kinds: %+v", batch)
	}
}

// ------------------------------------------------------ rate_limiter.go --

func TestRateLimiterRetryAfter(t *testing.T) {
	l := newRateLimiter(2, 40*time.Millisecond)
	if l.RetryAfter() != 0 {
		t.Fatal("a fresh limiter must admit immediately")
	}
	if !l.Acquire() {
		t.Fatal("under the cap, the first acquire must succeed")
	}
	if !l.Acquire() {
		t.Fatal("under the cap, the second acquire must succeed")
	}
	if l.Acquire() {
		t.Fatal("a saturated limiter must deny")
	}
	if wait := l.RetryAfter(); wait <= 0 || wait > 40*time.Millisecond {
		t.Fatalf("retry window must bound the wait, got %s", wait)
	}
	// A fully aged window admits again and RetryAfter reports zero.
	l.mu.Lock()
	l.calls = []time.Time{time.Now().Add(-2 * l.window)}
	l.mu.Unlock()
	if wait := l.RetryAfter(); wait != 0 {
		t.Fatalf("an expired window must report zero wait, got %s", wait)
	}
	if !l.Acquire() {
		t.Fatal("aged calls must prune on acquire")
	}
}

// --------------------------------------------------------- transport.go --

func TestParseRetryAfterBounds(t *testing.T) {
	cases := []struct {
		header string
		want   time.Duration
	}{
		{"5", 5 * time.Second},
		{"  7  ", 7 * time.Second},
		{"0.25", 250 * time.Millisecond},
		{"bogus", 60 * time.Second},
		{"-3", 0},
		{"9999", 300 * time.Second},
		{"", 60 * time.Second},
	}
	for _, tc := range cases {
		if got := parseRetryAfter(tc.header); got != tc.want {
			t.Fatalf("parseRetryAfter(%q) = %s, want %s", tc.header, got, tc.want)
		}
	}
}

func TestRetryAndPartialBackoffBounds(t *testing.T) {
	if got := retryBackoff(31, 1.0); got != maxRetryBackoff {
		t.Fatalf("attempt beyond 30 must cap, got %s", got)
	}
	if got := retryBackoff(1, 0); got != time.Second {
		t.Fatalf("non-positive delay must floor at 1s, got %s", got)
	}
	if got := retryBackoff(10, 1000.0); got != maxRetryBackoff {
		t.Fatalf("huge delays must cap, got %s", got)
	}
	if got := retryBackoff(1, 1.0); got != 2*time.Second {
		t.Fatalf("exponential base must double, got %s", got)
	}
	if got := partialFailureBackoff(0, time.Second); got != time.Second {
		t.Fatalf("streaks below one must clamp to the interval, got %s", got)
	}
	if got := partialFailureBackoff(1, 0); got != maxPartialBackoff {
		t.Fatalf("a zero interval must floor at the cap, got %s", got)
	}
	if got := partialFailureBackoff(1, time.Second); got != time.Second {
		t.Fatalf("first streak uses the flush interval, got %s", got)
	}
	if got := partialFailureBackoff(20, time.Hour); got != maxPartialBackoff {
		t.Fatalf("huge backoffs must cap, got %s", got)
	}
}

func TestSleepCtx(t *testing.T) {
	if !sleepCtx(context.Background(), 0) {
		t.Fatal("zero sleep on a live context must succeed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if sleepCtx(ctx, 0) {
		t.Fatal("zero sleep on a canceled context must report the cancel")
	}
	if sleepCtx(ctx, time.Hour) {
		t.Fatal("a canceled context must interrupt the sleep")
	}
	if !sleepCtx(context.Background(), time.Millisecond) {
		t.Fatal("a short sleep on a live context must complete")
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("short", 10); got != "short" {
		t.Fatalf("short strings pass through, got %q", got)
	}
	if got := truncate("0123456789abcdef", 4); got != "0123" {
		t.Fatalf("long strings cut, got %q", got)
	}
}

func TestEvaluateBatchResponse(t *testing.T) {
	tr := newTransport(DefaultConfig(), "install", nil, log.New(io.Discard, "", 0))
	if outcome, err := tr.evaluateBatchResponse([]byte(`{"success":true}`)); outcome != outcomeAccepted || err != nil {
		t.Fatalf("clean 200 must accept, got %v %v", outcome, err)
	}
	if outcome, err := tr.evaluateBatchResponse([]byte(`{"success":false}`)); outcome != outcomePartial || err != nil {
		t.Fatalf("success:false must be partial, got %v %v", outcome, err)
	}
	if outcome, err := tr.evaluateBatchResponse([]byte(`{garbage`)); outcome != outcomePartial || err == nil {
		t.Fatalf("malformed bodies must be partial, got %v %v", outcome, err)
	}
}

func TestMarshalBatchCompressionFlag(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CompressionThreshold = 32
	tr := newTransport(cfg, "install", nil, log.New(io.Discard, "", 0))
	batch := &eventBatch{ProjectID: "p", Events: []SecurityEvent{testEvent(1, strings.Repeat("x", 64))}}
	raw, err := tr.marshalBatch(batch)
	if err != nil {
		t.Fatalf("marshalBatch: %v", err)
	}
	if !batch.Compressed {
		t.Fatal("bodies over the threshold must set the compressed flag")
	}
	var decoded eventBatch
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("re-marshaled batch must stay valid JSON: %v", err)
	}
	plainCfg := cfg
	plainCfg.CompressionThreshold = 4096
	smallTr := newTransport(plainCfg, "install", nil, log.New(io.Discard, "", 0))
	small := &eventBatch{ProjectID: "p", Events: []SecurityEvent{testEvent(1, "")}}
	if _, err := smallTr.marshalBatch(small); err != nil {
		t.Fatalf("marshalBatch: %v", err)
	}
	if small.Compressed {
		t.Fatal("bodies under the threshold must not claim compression")
	}
}

func TestEncodeBodyCompression(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CompressionThreshold = 16
	tr := newTransport(cfg, "install", nil, log.New(io.Discard, "", 0))
	raw := []byte(strings.Repeat("a", 2048))
	wire, encoding := tr.encodeBody(raw)
	if encoding != "gzip" || len(wire) >= len(raw) {
		t.Fatalf("compressible bodies must gzip, got encoding=%q len=%d", encoding, len(wire))
	}
	plain, encoding := tr.encodeBody([]byte("tiny"))
	if encoding != "" || string(plain) != "tiny" {
		t.Fatalf("small bodies must stay plain, got encoding=%q", encoding)
	}
	newGzipWriter = func(w io.Writer) *gzip.Writer { return gzip.NewWriter(errWriter()) }
	failed, failedEncoding := tr.encodeBody(raw)
	newGzipWriter = gzipNewWriter
	if failedEncoding != "" || !bytes.Equal(failed, raw) {
		t.Fatalf("a failing gzip writer must fall back to plain bytes, got %q %d", failedEncoding, len(failed))
	}
}

func TestProjectIDOrDefault(t *testing.T) {
	tr := newTransport(DefaultConfig(), "install", nil, log.New(io.Discard, "", 0))
	if got := tr.projectIDOrDefault(); got != "default" {
		t.Fatalf("missing project id must default, got %q", got)
	}
	tr.cfg.ProjectID = "acme"
	if got := tr.projectIDOrDefault(); got != "acme" {
		t.Fatalf("configured project id must win, got %q", got)
	}
}

func TestLimiterGateWaitsAndBurnsAttempts(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RetryAttempts = 1
	tr := newTransport(cfg, "install", nil, log.New(io.Discard, "", 0))
	tr.limiter = newRateLimiter(1, 20*time.Millisecond)
	saturate := func() {
		tr.limiter.mu.Lock()
		tr.limiter.calls = []time.Time{time.Now()}
		tr.limiter.mu.Unlock()
	}
	if allowed, err := tr.limiterGate(context.Background(), 0, "batch send"); !allowed || err != nil {
		t.Fatalf("a fresh limiter must admit, got %v %v", allowed, err)
	}
	// Saturated: the gate waits out the window and reports retry-eligible.
	saturate()
	if allowed, err := tr.limiterGate(context.Background(), 0, "batch send"); allowed || err != nil {
		t.Fatalf("a saturated gate must defer, got %v %v", allowed, err)
	}
	// At the attempt budget the gate errors instead of retrying.
	saturate()
	if allowed, err := tr.limiterGate(context.Background(), 1, "batch send"); allowed || err == nil {
		t.Fatalf("an exhausted attempt budget must error, got %v %v", allowed, err)
	}
	saturate()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if allowed, err := tr.limiterGate(ctx, 0, "batch send"); allowed || !errors.Is(err, context.Canceled) {
		t.Fatalf("a canceled context must surface immediately, got %v %v", allowed, err)
	}
}

func TestSendBatchStatusHandling(t *testing.T) {
	m := newMockIngest(t)
	cfg := DefaultConfig()
	cfg.APIKey = "test-api-key-123"
	cfg.Endpoint = m.URL
	cfg.RetryAttempts = 1
	cfg.BackoffFactor = 0.001
	tr := newTransport(cfg, "install", nil, log.New(io.Discard, "", 0))

	// 200 + evaluate clean body.
	if outcome, err := tr.sendBatch(context.Background(), eventsPath, []byte(`{"x":1}`), true); outcome != outcomeAccepted || err != nil {
		t.Fatalf("clean 200 must accept, got %v %v", outcome, err)
	}
	// 201 skips evaluation.
	if outcome, err := func() (sendOutcome, error) {
		m.mu.Lock()
		m.statusCodeOverride = http.StatusCreated
		m.mu.Unlock()
		defer func() { m.statusCodeOverride = 0 }()
		return tr.sendBatch(context.Background(), eventsPath, []byte(`{}`), true)
	}(); outcome != outcomeAccepted || err != nil {
		t.Fatalf("201 must accept without evaluation, got %v %v", outcome, err)
	}
	// Permanent rejections.
	for _, code := range []int{http.StatusBadRequest, http.StatusNotFound, http.StatusUnprocessableEntity} {
		m.mu.Lock()
		m.statusCodeOverride = code
		m.mu.Unlock()
		outcome, err := tr.sendBatch(context.Background(), eventsPath, []byte(`{}`), true)
		m.mu.Lock()
		m.statusCodeOverride = 0
		m.mu.Unlock()
		var permanent *PermanentError
		if outcome != outcomePermanent || !errors.As(err, &permanent) || permanent.StatusCode != code {
			t.Fatalf("status %d must be permanent, got %v %v", code, outcome, err)
		}
	}
	// An unexpected 4xx is partial (and exempt from the breaker).
	m.mu.Lock()
	m.statusCodeOverride = http.StatusConflict
	m.mu.Unlock()
	outcome, err := tr.sendBatch(context.Background(), eventsPath, []byte(`{}`), true)
	m.mu.Lock()
	m.statusCodeOverride = 0
	m.mu.Unlock()
	if outcome != outcomePartial || err == nil {
		t.Fatalf("unexpected 4xx must be partial, got %v %v", outcome, err)
	}
	// 403 retries with backoff and then fails.
	m.mu.Lock()
	m.statusCodeOverride = http.StatusForbidden
	m.mu.Unlock()
	outcome, err = tr.sendBatch(context.Background(), eventsPath, []byte(`{}`), true)
	m.mu.Lock()
	m.statusCodeOverride = 0
	m.mu.Unlock()
	if outcome != outcomeFailed || err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("403 must retry then fail, got %v %v", outcome, err)
	}
	// A canceled context during the send surfaces the context error.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if outcome, err := tr.sendBatch(ctx, eventsPath, []byte(`{}`), true); outcome != outcomeFailed || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled sends must report the context, got %v %v", outcome, err)
	}
	// Network errors retry with backoff and exhaust into outcomeFailed.
	down := newTransport(cfg, "install", nil, log.New(io.Discard, "", 0))
	down.cfg.Endpoint = "http://127.0.0.1:1"
	if outcome, err := down.sendBatch(context.Background(), eventsPath, []byte(`{}`), true); outcome != outcomeFailed || err == nil {
		t.Fatalf("unreachable endpoints must fail after retries, got %v %v", outcome, err)
	}
}

func TestSendEventsTransportPaths(t *testing.T) {
	m := newMockIngest(t)
	cfg := DefaultConfig()
	cfg.APIKey = "test-api-key-123"
	cfg.Endpoint = m.URL
	cfg.RetryAttempts = 1
	cfg.BackoffFactor = 0.001
	cfg.OnError = func(stage string, err error, ctx map[string]any) {}
	tr := newTransport(cfg, "install", nil, log.New(io.Discard, "", 0))

	// Empty batches short-circuit to accepted.
	if outcome, err := tr.sendEvents(context.Background(), nil); outcome != outcomeAccepted || err != nil {
		t.Fatalf("empty batches must accept, got %v %v", outcome, err)
	}
	if outcome, err := tr.sendMetrics(context.Background(), nil); outcome != outcomeAccepted || err != nil {
		t.Fatalf("empty batches must accept, got %v %v", outcome, err)
	}
	// Serialization failure retains the batch as partial and fires the hook.
	jsonMarshal = func(v any) ([]byte, error) { return nil, errors.New("marshal exploded") }
	var hookStage string
	tr.cfg.OnError = func(stage string, err error, ctx map[string]any) { hookStage = stage }
	if outcome, err := tr.sendEvents(context.Background(), []SecurityEvent{testEvent(1, "")}); outcome != outcomePartial || err == nil {
		t.Fatalf("marshal failure must be partial, got %v %v", outcome, err)
	}
	if hookStage != StageTransportSend {
		t.Fatalf("marshal failure must fire the transport hook, got %q", hookStage)
	}
	if outcome, err := tr.sendMetrics(context.Background(), []SecurityMetric{testMetric(1)}); outcome != outcomePartial || err == nil {
		t.Fatalf("marshal failure must be partial, got %v %v", outcome, err)
	}
	jsonMarshal = json.Marshal
	// A 413 on a multi-item batch splits recursively and confirms both halves.
	m.setMaxBody(10)
	big := make([]SecurityEvent, 4)
	for i := range big {
		big[i] = testEvent(i, "")
	}
	if outcome, err := tr.sendEvents(context.Background(), big); outcome != outcomeAccepted || err != nil {
		t.Fatalf("413 split must confirm when every part confirms, got %v %v", outcome, err)
	}
	bigMetrics := make([]SecurityMetric, 4)
	for i := range bigMetrics {
		bigMetrics[i] = testMetric(i)
	}
	if outcome, err := tr.sendMetrics(context.Background(), bigMetrics); outcome != outcomeAccepted || err != nil {
		t.Fatalf("413 metric split must confirm when every part confirms, got %v %v", outcome, err)
	}
	// A 413 on a singleton drops it durably.
	m.setMaxBody(10)
	if outcome, err := tr.sendEvents(context.Background(), []SecurityEvent{testEvent(9, strings.Repeat("y", 64))}); outcome != outcomePermanent || err != nil {
		t.Fatalf("singleton 413 must drop durably, got %v %v", outcome, err)
	}
	if outcome, err := tr.sendMetrics(context.Background(), []SecurityMetric{{MetricType: MetricRequestCount, Value: 1, Tags: map[string]string{"pad": strings.Repeat("y", 64)}}}); outcome != outcomePermanent || err != nil {
		t.Fatalf("singleton metric 413 must drop durably, got %v %v", outcome, err)
	}
	// A failed half makes the whole split report failure.
	m.setMaxBody(262144)
	m.failNext(2)
	if outcome, _ := tr.sendEvents(context.Background(), big); outcome != outcomeFailed {
		t.Fatalf("a failed batch must report failure, got %v", outcome)
	}
	m.clearKnobs()
}

func TestSendStatusPaths(t *testing.T) {
	m := newMockIngest(t)
	cfg := DefaultConfig()
	cfg.APIKey = "test-api-key-123"
	cfg.Endpoint = m.URL
	cfg.RetryAttempts = 1
	cfg.BackoffFactor = 0.001
	tr := newTransport(cfg, "install", nil, log.New(io.Discard, "", 0))
	payload := agentStatusPayload{Timestamp: time.Now().UTC(), Status: StatusHealthy}
	if outcome, err := tr.sendStatus(context.Background(), payload); outcome != outcomeAccepted || err != nil {
		t.Fatalf("clean status must accept, got %v %v", outcome, err)
	}
	// Serialization failure is partial.
	jsonMarshal = func(v any) ([]byte, error) { return nil, errors.New("marshal exploded") }
	if outcome, err := tr.sendStatus(context.Background(), payload); outcome != outcomePartial || err == nil {
		t.Fatalf("status marshal failure must be partial, got %v %v", outcome, err)
	}
	jsonMarshal = json.Marshal
	// A 413 on status drops it (fire and forget), never requeues.
	m.setMaxBody(1)
	if outcome, err := tr.sendStatus(context.Background(), payload); outcome != outcomePermanent || err != nil {
		t.Fatalf("oversized status must drop, got %v %v", outcome, err)
	}
	m.setMaxBody(262144)
}

func TestCanonicalItemsJSON(t *testing.T) {
	payload, err := canonicalItemsJSON([]SecurityEvent{testEvent(1, "")}, []SecurityMetric{testMetric(2)})
	if err != nil {
		t.Fatalf("canonicalItemsJSON: %v", err)
	}
	events, ok := payload["events"].([]any)
	if !ok || len(events) != 1 {
		t.Fatalf("events must round trip: %v", payload["events"])
	}
	metrics, ok := payload["metrics"].([]any)
	if !ok || len(metrics) != 1 {
		t.Fatalf("metrics must round trip: %v", payload["metrics"])
	}
	metadata, ok := events[0].(map[string]any)["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("event metadata must round trip: %v", events[0])
	}
	if _, ok := metadata["seq"].(json.Number); !ok {
		t.Fatalf("integers must stay numbers on the canonical plaintext, got %T", metadata["seq"])
	}
	empty, err := canonicalItemsJSON(nil, nil)
	if err != nil {
		t.Fatalf("canonicalItemsJSON: %v", err)
	}
	if e, ok := empty["events"].([]any); !ok || len(e) != 0 {
		t.Fatal("empty events must serialize as an empty list")
	}
	// Serialization failure surfaces.
	jsonMarshal = func(v any) ([]byte, error) { return nil, errors.New("marshal exploded") }
	if _, err := canonicalItemsJSON([]SecurityEvent{testEvent(1, "")}, nil); err == nil {
		t.Fatal("event marshal failure must surface")
	}
	if _, err := canonicalItemsJSON(nil, []SecurityMetric{testMetric(1)}); err == nil {
		t.Fatal("metric marshal failure must surface")
	}
	jsonMarshal = json.Marshal
}

func TestSendEncryptedBatchPaths(t *testing.T) {
	m := newMockIngest(t)
	cfg := DefaultConfig()
	cfg.APIKey = "test-api-key-123"
	cfg.Endpoint = m.URL
	cfg.RetryAttempts = 1
	cfg.BackoffFactor = 0.001
	cfg.ProjectEncryptionKey = testEncryptionKey()
	cfg.OnError = func(string, error, map[string]any) {}
	tr := newTransport(cfg, "install", nil, log.New(io.Discard, "", 0))
	encryptor, err := NewPayloadEncryptor(testEncryptionKey())
	if err != nil {
		t.Fatalf("encryptor: %v", err)
	}
	tr.encryptor = encryptor

	if outcome, err := tr.sendEncryptedBatch(context.Background(), []SecurityEvent{testEvent(1, "")}, nil); outcome != outcomeAccepted || err != nil {
		t.Fatalf("encrypted batch must confirm, got %v %v", outcome, err)
	}
	calls := m.callsTo(encryptedPath)
	if len(calls) != 1 {
		t.Fatalf("encrypted batches must hit %s, got %v", encryptedPath, calls)
	}
	// 413 on an encrypted batch drops it durably: it cannot be split.
	m.setMaxBody(1)
	if outcome, err := tr.sendEncryptedBatch(context.Background(), nil, []SecurityMetric{testMetric(1)}); outcome != outcomePermanent || err != nil {
		t.Fatalf("oversized encrypted batches must drop durably, got %v %v", outcome, err)
	}
	m.setMaxBody(262144)
	// Encryption failure retains the batch.
	cryptoRandRead = func(b []byte) (int, error) { return 0, errors.New("no entropy") }
	if outcome, err := tr.sendEncryptedBatch(context.Background(), []SecurityEvent{testEvent(2, "")}, nil); outcome != outcomePartial || err == nil {
		t.Fatalf("encryption failure must be partial, got %v %v", outcome, err)
	}
	cryptoRandRead = randRead
	// Serialization failure retains the batch.
	jsonMarshal = func(v any) ([]byte, error) { return nil, errors.New("marshal exploded") }
	if outcome, err := tr.sendEncryptedBatch(context.Background(), []SecurityEvent{testEvent(3, "")}, nil); outcome != outcomePartial || err == nil {
		t.Fatalf("serialization failure must be partial, got %v %v", outcome, err)
	}
	jsonMarshal = json.Marshal
}

// ------------------------------------------------------ dynamic_rules.go --

func sampleRulesJSON() string {
	limit := 10
	return fmt.Sprintf(`{"rule_id":"saas-rule","version":7,"ttl":120,"ip_ban_duration":60,
		"ip_blacklist":["10.0.0.1"],"ip_whitelist":["10.0.0.2"],
		"blocked_countries":["CN"],"whitelist_countries":["US"],
		"global_rate_limit":%d,"global_rate_window":60,
		"endpoint_rate_limits":{"/api":[5,60]},
		"blocked_cloud_providers":["AWS"],"blocked_user_agents":["bot"],
		"suspicious_patterns":["union select"],
		"enable_penetration_detection":true,"enable_ip_banning":false,
		"enable_rate_limiting":true,"auto_ban_threshold":3,"auto_ban_duration":600,
		"enable_rate_limit_auto_ban":true,"emergency_mode":true,
		"emergency_whitelist":["192.0.2.1"],"emergency_whitelist_only":true,
		"message":"locked","expires_at":"2030-01-01T00:00:00Z"}`, limit)
}

func TestDynamicRulesUnmarshalAppliesDefaultsAndOverrides(t *testing.T) {
	var sparse DynamicRules
	if err := json.Unmarshal([]byte(`{}`), &sparse); err != nil {
		t.Fatalf("sparse decode: %v", err)
	}
	def := DefaultDynamicRules()
	if sparse.RuleID != def.RuleID || sparse.TTL != def.TTL || sparse.IPBanDuration != def.IPBanDuration {
		t.Fatalf("sparse rules must carry the python defaults, got %+v", sparse)
	}
	if sparse.IPBlacklist == nil || sparse.EndpointRateLimits == nil || sparse.EmergencyWhitelist == nil {
		t.Fatal("absent lists must default to empty, never nil")
	}
	var full DynamicRules
	if err := json.Unmarshal([]byte(sampleRulesJSON()), &full); err != nil {
		t.Fatalf("full decode: %v", err)
	}
	if full.RuleID != "saas-rule" || full.Version != 7 || full.TTL != 120 || full.IPBanDuration != 60 {
		t.Fatalf("overrides must apply, got %+v", full)
	}
	if full.GlobalRateLimit == nil || *full.GlobalRateLimit != 10 || full.EndpointRateLimits["/api"][0] != 5 {
		t.Fatalf("pointer fields must decode, got %+v", full)
	}
	if full.EnableIPBanning == nil || *full.EnableIPBanning || !*full.EnableRateLimitAutoBan {
		t.Fatalf("bool pointers must decode, got %+v", full)
	}
	if full.Message == nil || *full.Message != "locked" || full.ExpiresAt == nil {
		t.Fatalf("optional fields must decode, got %+v", full)
	}
	if !full.EmergencyMode || !full.EmergencyWhitelistOnly || len(full.EmergencyWhitelist) != 1 {
		t.Fatalf("emergency fields must decode, got %+v", full)
	}
	if len(full.SuspiciousPatterns) != 1 || full.SuspiciousPatterns[0] != "union select" {
		t.Fatalf("pattern lists must decode, got %+v", full)
	}
	// Malformed payloads surface the decoder error.
	if err := json.Unmarshal([]byte(`{"version":"not-a-number"}`), &full); err == nil {
		t.Fatal("type mismatches must surface")
	}
}

func TestGetDynamicRulesCacheAndFallback(t *testing.T) {
	m := newMockIngest(t)
	m.serveRules(http.StatusOK, sampleRulesJSON())
	agent := newTestAgent(t, m, nil)
	ctx := context.Background()

	first := agent.GetDynamicRules(ctx)
	if first == nil || first.RuleID != "saas-rule" {
		t.Fatalf("first fetch must return the document, got %+v", first)
	}
	if agent.Stats().RulesFetched != 1 {
		t.Fatalf("successful fetches must count, got %+v", agent.Stats())
	}
	// Inside the TTL the cache answers without an HTTP call.
	if cached := agent.GetDynamicRules(ctx); cached != first {
		t.Fatal("cache must serve inside the TTL")
	}
	if len(m.callsTo(rulesPath)) != 1 {
		t.Fatalf("cached reads must not hit the API, got %d calls", len(m.callsTo(rulesPath)))
	}
	// Expired TTL refetches.
	agent.mu.Lock()
	agent.rulesLastUpdate = time.Now().Add(-10 * time.Minute)
	agent.mu.Unlock()
	if again := agent.GetDynamicRules(ctx); again == nil || again.RuleID != "saas-rule" {
		t.Fatalf("expired cache must refetch, got %+v", again)
	}
	// A failed refetch serves the last known rules.
	m.serveRules(http.StatusInternalServerError, "")
	agent.mu.Lock()
	agent.rulesLastUpdate = time.Now().Add(-10 * time.Minute)
	agent.mu.Unlock()
	if served := agent.GetDynamicRules(ctx); served == nil || served.RuleID != "saas-rule" {
		t.Fatalf("outage must serve the cached rules, got %+v", served)
	}
	// No cache plus an outage yields nil without erroring out.
	agent.mu.Lock()
	agent.cachedRules = nil
	agent.mu.Unlock()
	if served := agent.GetDynamicRules(ctx); served != nil {
		t.Fatalf("an outage without cache must return nil, got %+v", served)
	}
	if agent.Stats().RulesFetched != 2 {
		t.Fatalf("only successful fetches count, got %+v", agent.Stats())
	}
}

func TestFetchDynamicRulesStatusHandling(t *testing.T) {
	m := newMockIngest(t)
	cfg := DefaultConfig()
	cfg.APIKey = "test-api-key-123"
	cfg.Endpoint = m.URL
	cfg.RetryAttempts = 1
	cfg.BackoffFactor = 0.001
	tr := newTransport(cfg, "install", nil, log.New(io.Discard, "", 0))
	ctx := context.Background()

	// 200 with a malformed body surfaces a decode error.
	m.serveRules(http.StatusOK, "{not json")
	if _, err := tr.fetchDynamicRules(ctx); err == nil || !strings.Contains(err.Error(), "malformed dynamic rules") {
		t.Fatalf("malformed rules must surface, got %v", err)
	}
	// 429 exhausting the retry budget reports rate limiting.
	m.serveRules(http.StatusTooManyRequests, "")
	tr.limiter = newRateLimiter(defaultLimiterMaxCalls, defaultLimiterWindow)
	if _, err := tr.fetchDynamicRules(ctx); err == nil {
		t.Fatal("429 exhaustion must error")
	} else {
		var limited *RateLimitedError
		if !errors.As(err, &limited) {
			t.Fatalf("429 must surface as RateLimitedError, got %T %v", err, err)
		}
	}
	// Any other status exhausts into a generic error.
	m.serveRules(http.StatusBadGateway, "")
	if _, err := tr.fetchDynamicRules(ctx); err == nil || !strings.Contains(err.Error(), "status 502") {
		t.Fatalf("502 must exhaust into a generic error, got %v", err)
	}
	// A canceled context surfaces immediately.
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := tr.fetchDynamicRules(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled fetches must report the context, got %v", err)
	}
	// Network errors exhaust into the transport error.
	down := newTransport(cfg, "install", nil, log.New(io.Discard, "", 0))
	down.cfg.Endpoint = "http://127.0.0.1:1"
	if _, err := down.fetchDynamicRules(ctx); err == nil {
		t.Fatal("unreachable endpoints must error")
	}
	// A panic in the fetch path is recovered by the agent wrapper.
	panicTr := newTransport(cfg, "install", &http.Client{Transport: panicRoundTripper{}}, log.New(io.Discard, "", 0))
	agent := &Agent{logger: log.New(io.Discard, "", 0), tr: panicTr, cfg: cfg}
	if rules, err := agent.fetchRulesSafely(ctx); rules != nil || !errors.Is(err, ErrInternal) {
		t.Fatalf("panics must convert to ErrInternal, got %+v %v", rules, err)
	}
}

// -------------------------------------------------------------- agent.go --

func TestNewConstructionPaths(t *testing.T) {
	var warnBuf bytes.Buffer
	logger := log.New(&warnBuf, "", 0)
	cfg := DefaultConfig()
	cfg.APIKey = "test-api-key-123"
	cfg.Endpoint = "https://api.example.com/api/v1"
	cfg.InstallIDPath = filepath.Join(t.TempDir(), "install-id")
	agent, err := New(cfg, WithLogger(logger))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_ = agent.Stop(context.Background())
	if !strings.Contains(warnBuf.String(), apiVersionSuffixWarning) {
		t.Fatalf("endpoint normalization must warn, got %q", warnBuf.String())
	}

	// An invalid encryption key fails construction without plaintext fallback.
	cfg.ProjectEncryptionKey = base64Pad(make([]byte, 8))
	if _, err := New(cfg); err == nil {
		t.Fatal("invalid keys must fail construction")
	} else {
		var cfgErr *EncryptionConfigError
		if !errors.As(err, &cfgErr) {
			t.Fatalf("encryption failures must surface as EncryptionConfigError, got %T %v", err, err)
		}
		if !strings.Contains(cfgErr.Error(), "refusing plaintext fallback") {
			t.Fatalf("message mismatch: %q", cfgErr.Error())
		}
	}

	// A broken Redis URL fails construction.
	cfg.ProjectEncryptionKey = ""
	cfg.Redis = &RedisConfig{URL: "bad-scheme://x", Prefix: "p", TTL: time.Minute}
	if _, err := New(cfg); err == nil || !strings.Contains(err.Error(), "redis configuration invalid") {
		t.Fatalf("broken redis config must fail construction, got %v", err)
	}
}

func TestHealthyThresholds(t *testing.T) {
	m := newMockIngest(t)
	agent := newTestAgent(t, m, func(c *Config) {
		c.BufferSize = 100
		c.HighWatermarkRatio = 1.0
	})
	ctx := context.Background()

	// Before Start the agent is not healthy.
	if agent.Healthy() {
		t.Fatal("a stopped agent cannot be healthy")
	}
	if err := agent.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !agent.Healthy() {
		t.Fatal("a fresh started agent must be healthy")
	}
	// 95% occupancy fails the health check.
	for i := 0; i < 96; i++ {
		if err := agent.SendEvent(ctx, testEvent(i, "")); err != nil {
			t.Fatalf("SendEvent: %v", err)
		}
	}
	if agent.Healthy() {
		t.Fatal("95% occupancy must fail the health check")
	}
	// A wide-open circuit breaker fails the health check.
	agent.mu.Lock()
	agent.events = nil
	agent.metrics = nil
	agent.mu.Unlock()
	for i := 0; i < breakerFailureThreshold; i++ {
		agent.tr.breaker.Failure()
	}
	if agent.Healthy() {
		t.Fatal("an open circuit must fail the health check")
	}
	agent.tr.breaker.Success()
	// A >50% lifetime failure rate fails the health check.
	agent.mu.Lock()
	agent.eventsSent = 1
	agent.eventsFailed = 3
	agent.mu.Unlock()
	if agent.Healthy() {
		t.Fatal("a >50% failure rate must fail the health check")
	}
	// Status mirrors the same degradation with the softer thresholds.
	if s := agent.Status(); s.State != StatusDegraded {
		t.Fatalf("a >10%% failure rate must degrade the status, got %q", s.State)
	}
	// 90% occupancy degrades too.
	agent.mu.Lock()
	agent.eventsSent = 0
	agent.eventsFailed = 0
	agent.mu.Unlock()
	for i := 0; i < 90; i++ {
		if err := agent.SendEvent(ctx, testEvent(i, "")); err != nil {
			t.Fatalf("SendEvent: %v", err)
		}
	}
	if s := agent.Status(); s.State != StatusDegraded {
		t.Fatalf("90%% occupancy must degrade the status, got %q", s.State)
	}
	_ = agent.Stop(ctx)
	if agent.Healthy() {
		t.Fatal("a closed agent cannot be healthy")
	}
	if s := agent.Status(); s.State != StatusFailed {
		t.Fatalf("a closed agent must report failed, got %q", s.State)
	}
}

func TestStatusPayloadShape(t *testing.T) {
	m := newMockIngest(t)
	agent := newTestAgent(t, m, nil)
	ctx := context.Background()
	if err := agent.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := agent.SendEvent(ctx, testEvent(1, "")); err != nil {
		t.Fatalf("SendEvent: %v", err)
	}
	if err := agent.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	payload := agent.statusPayload()
	if payload.LastFlush == nil {
		t.Fatal("a completed flush must be reported in the payload")
	}
	if payload.Uptime <= 0 {
		t.Fatalf("a started agent must report uptime, got %f", payload.Uptime)
	}
	if payload.Status != StatusHealthy {
		t.Fatalf("payload status mismatch: %q", payload.Status)
	}
	_ = agent.Stop(ctx)
	payload = agent.statusPayload()
	if payload.Uptime != 0 {
		t.Fatalf("a closed agent must not report uptime, got %f", payload.Uptime)
	}
}

func TestRecordErrorRingBuffer(t *testing.T) {
	m := newMockIngest(t)
	agent := newTestAgent(t, m, nil)
	agent.mu.Lock()
	for i := 0; i < maxTrackedErrors+2; i++ {
		agent.recordErrorLocked(fmt.Sprintf("error-%d", i))
	}
	agent.mu.Unlock()
	errs := agent.Status().Errors
	if len(errs) != maxTrackedErrors {
		t.Fatalf("the error ring must cap at %d, got %d", maxTrackedErrors, len(errs))
	}
	if errs[0] != "error-2" || errs[len(errs)-1] != fmt.Sprintf("error-%d", maxTrackedErrors+1) {
		t.Fatalf("oldest errors must be evicted first, got %v", errs)
	}
}

func TestLoopCtxBeforeStart(t *testing.T) {
	m := newMockIngest(t)
	agent := newTestAgent(t, m, nil)
	if agent.loopCtx() == nil {
		t.Fatal("loopCtx must always return a context")
	}
}

func TestTriggerFlushWakeWithoutBuffer(t *testing.T) {
	m := newMockIngest(t)
	agent := newTestAgent(t, m, nil)
	ctx := context.Background()
	if err := agent.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// A wake with an empty buffer is a no-op (exercised directly so the
	// empty-buffer branch is deterministic).
	agent.flushIfNeeded()
	// A saturated wake channel drops the token instead of blocking.
	agent.flushWake <- struct{}{}
	agent.triggerFlush()
	// A wake for a non-watermark buffer defers to the elapsed-time gate,
	// which fires because the recorded last flush is two hours old.
	if err := agent.SendEvent(ctx, testEvent(1, "")); err != nil {
		t.Fatalf("SendEvent: %v", err)
	}
	agent.mu.Lock()
	agent.lastFlush = time.Now().Add(-2 * time.Hour)
	agent.mu.Unlock()
	agent.triggerFlush()
	waitUntil(t, 2*time.Second, "wake flusher must drain", func() bool {
		return agent.Stats().EventsPending == 0
	})
	_ = agent.Stop(ctx)
}

func TestEnqueueMetricPolicies(t *testing.T) {
	ctx := context.Background()

	// Drop evicts the oldest metric and counts the drop.
	m := newMockIngest(t)
	agent := newTestAgent(t, m, func(c *Config) { c.BufferSize = 2 })
	for i := 0; i < 3; i++ {
		if err := agent.SendMetric(ctx, testMetric(i)); err != nil {
			t.Fatalf("SendMetric: %v", err)
		}
	}
	if got := agent.Stats().MetricsDropped; got != 1 {
		t.Fatalf("drop policy must evict the oldest, got %d drops", got)
	}
	_ = agent.Stop(ctx)

	// Raise returns BufferFullError.
	m2 := newMockIngest(t)
	agent = newTestAgent(t, m2, func(c *Config) {
		c.BufferSize = 1
		c.HighWatermarkRatio = 1.0
		c.Overflow = OverflowRaise
	})
	if err := agent.SendMetric(ctx, testMetric(1)); err != nil {
		t.Fatalf("SendMetric: %v", err)
	}
	err := agent.SendMetric(ctx, testMetric(2))
	var full *BufferFullError
	if !errors.As(err, &full) || full.Kind != kindMetric {
		t.Fatalf("raise policy must return BufferFullError, got %v", err)
	}
	_ = agent.Stop(ctx)

	// Block waits for space freed by a flush.
	m3 := newMockIngest(t)
	agent = newTestAgent(t, m3, func(c *Config) {
		c.BufferSize = 1
		c.HighWatermarkRatio = 1.0
		c.Overflow = OverflowBlock
	})
	if err := agent.SendMetric(ctx, testMetric(1)); err != nil {
		t.Fatalf("SendMetric: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- agent.SendMetric(ctx, testMetric(2)) }()
	waitUntil(t, time.Second, "blocked sender must park", func() bool {
		agent.mu.Lock()
		defer agent.mu.Unlock()
		return len(agent.metrics) == 1
	})
	_ = agent.Flush(ctx)
	if err := <-done; err != nil {
		t.Fatalf("blocked sender must resume after a flush, got %v", err)
	}
	_ = agent.Stop(ctx)

	// Block with a canceled context returns the context error immediately.
	m4 := newMockIngest(t)
	agent = newTestAgent(t, m4, func(c *Config) {
		c.BufferSize = 1
		c.HighWatermarkRatio = 1.0
		c.Overflow = OverflowBlock
	})
	if err := agent.SendMetric(ctx, testMetric(1)); err != nil {
		t.Fatalf("SendMetric: %v", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := agent.SendMetric(canceled, testMetric(2)); !errors.Is(err, context.Canceled) {
		t.Fatalf("block policy must honor the context, got %v", err)
	}
	_ = agent.Stop(ctx)
}

func TestFlushMetricsGateAndSettlements(t *testing.T) {
	ctx := context.Background()
	m := newMockIngest(t)
	var hooks []string
	agent := newTestAgent(t, m, func(c *Config) {
		c.RetryAttempts = 0
		c.OnError = func(stage string, err error, _ map[string]any) { hooks = append(hooks, stage) }
	})
	if err := agent.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// First metric flush fails (500): requeue, arm the gate, fire the hook.
	m.failNext(1)
	if err := agent.SendMetric(ctx, testMetric(1)); err != nil {
		t.Fatalf("SendMetric: %v", err)
	}
	if err := agent.Flush(ctx); err == nil {
		t.Fatal("the failed flush must surface its error")
	}
	if agent.Stats().MetricsPending != 1 {
		t.Fatalf("failed batches must requeue, got %+v", agent.Stats())
	}
	// The gate suppresses the immediate retry.
	if err := agent.Flush(ctx); err != nil {
		t.Fatalf("the gated retry must be a no-op, got %v", err)
	}
	if got := len(m.callsTo(metricsPath)); got != 1 {
		t.Fatalf("the gate must suppress the immediate retry, got %d metric calls", got)
	}
	// A forced flush bypasses the gate and the recovered streak logs.
	if err := agent.Flush(ctx); err != nil {
		t.Fatalf("forced flush: %v", err)
	}
	_ = agent.Stop(ctx)
	found := false
	for _, stage := range hooks {
		if stage == StageFlushMetrics {
			found = true
		}
	}
	if !found {
		t.Fatalf("metric flush failures must fire the flush hook, got %v", hooks)
	}

	// Permanent rejection confirms the batch and counts it as sent.
	m2 := newMockIngest(t)
	agent = newTestAgent(t, m2, nil)
	if err := agent.SendMetric(ctx, testMetric(2)); err != nil {
		t.Fatalf("SendMetric: %v", err)
	}
	m2.reject400Next(1)
	if err := agent.Flush(ctx); err != nil {
		t.Fatalf("permanent rejections must not surface as errors, got %v", err)
	}
	stats := agent.Stats()
	if stats.MetricsSent != 1 || stats.MetricsPending != 0 {
		t.Fatalf("permanent rejections must confirm the batch, got %+v", stats)
	}
	_ = agent.Stop(ctx)

	// A transport panic during a metric flush still requeues the batch.
	m3 := newMockIngest(t)
	agent = newTestAgent(t, m3, nil, WithHTTPClient(&http.Client{Transport: panicRoundTripper{}}))
	if err := agent.SendMetric(ctx, testMetric(3)); err != nil {
		t.Fatalf("SendMetric: %v", err)
	}
	if err := agent.Flush(ctx); !errors.Is(err, ErrInternal) {
		t.Fatalf("panics must surface as ErrInternal, got %v", err)
	}
	if agent.Stats().MetricsPending != 1 {
		t.Fatalf("panics must not lose the batch, got %+v", agent.Stats())
	}
	_ = agent.Stop(ctx)
}

func TestRequeueTailEvictionDirect(t *testing.T) {
	m := newMockIngest(t)
	agent := newTestAgent(t, m, func(c *Config) { c.BufferSize = 2 })
	evicted := []bufferedEvent{
		{ev: testEvent(1, ""), key: "k1"},
		{ev: testEvent(2, ""), key: "k2"},
		{ev: testEvent(3, ""), key: "k3"},
	}
	agent.requeueEvents(evicted)
	if agent.Stats().EventsPending != 2 || agent.Stats().EventsDropped != 1 {
		t.Fatalf("requeue over capacity must evict the tail, got %+v", agent.Stats())
	}
	metricItems := []bufferedMetric{
		{m: testMetric(1), key: "m1"},
		{m: testMetric(2), key: "m2"},
		{m: testMetric(3), key: "m3"},
	}
	agent.requeueMetrics(metricItems)
	if agent.Stats().MetricsPending != 2 || agent.Stats().MetricsDropped != 1 {
		t.Fatalf("metric requeue over capacity must evict the tail, got %+v", agent.Stats())
	}
	_ = agent.Stop(context.Background())
}

func TestReportStatusOutcomes(t *testing.T) {
	ctx := context.Background()
	m := newMockIngest(t)
	agent := newTestAgent(t, m, nil)
	agent.reportStatus(ctx)
	if agent.Stats().StatusReportsSent != 1 {
		t.Fatalf("accepted status must count as sent, got %+v", agent.Stats())
	}
	// A failing endpoint counts and records the failure.
	down := newTestAgent(t, nil, nil)
	down.tr.cfg.Endpoint = "http://127.0.0.1:1"
	down.reportStatus(ctx)
	stats := down.Stats()
	if stats.StatusReportsFailed != 1 {
		t.Fatalf("failed status must count, got %+v", stats)
	}
	down.mu.Lock()
	lastErr := len(down.lastErrors)
	down.mu.Unlock()
	if lastErr == 0 {
		t.Fatal("failed status must record an error")
	}
	_ = agent.Stop(ctx)
	_ = down.Stop(ctx)
}

func TestRecoverPanicInExportedMethods(t *testing.T) {
	// A hand-built agent with a nil transport panics in Status(); the
	// recover must translate it into a log line, not a crash.
	logger := log.New(io.Discard, "", 0)
	agent := &Agent{logger: logger, tr: &transport{}}
	_ = agent.Status()
	// Start with a broken persistence handle panics inside the reload and
	// surfaces as ErrInternal.
	broken := &Agent{
		logger:  logger,
		tr:      newTransport(DefaultConfig(), "install", nil, logger),
		persist: &persistence{client: nil, logger: logger},
	}
	if err := broken.Start(context.Background()); !errors.Is(err, ErrInternal) {
		t.Fatalf("Start over a broken persistence must surface ErrInternal, got %v", err)
	}
}

func TestConfirmKeysWithoutPersistence(t *testing.T) {
	m := newMockIngest(t)
	agent := newTestAgent(t, m, nil)
	agent.confirmKeys([]string{"k"}) // no persistence: no-op, no panic
	agent.confirmKeys(nil)
	_ = agent.Stop(context.Background())
}

// ----------------------------------------------------------- background --

func TestBackgroundLoopsRecoverAndReport(t *testing.T) {
	m := newMockIngest(t)
	agent := newTestAgent(t, m, func(c *Config) {
		c.FlushInterval = 5 * time.Millisecond
		c.StatusInterval = time.Hour
	})
	// Shrink the status cadence after construction (validation floors it
	// at 60s for user configs; the loop only reads the field).
	agent.cfg.StatusInterval = 5 * time.Millisecond
	ctx := context.Background()
	if err := agent.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := agent.SendEvent(ctx, testEvent(1, "")); err != nil {
		t.Fatalf("SendEvent: %v", err)
	}
	waitUntil(t, 5*time.Second, "periodic flush must drain the buffer", func() bool {
		return agent.Stats().EventsPending == 0 && agent.Stats().EventsSent == 1
	})
	waitUntil(t, 5*time.Second, "status loop must report", func() bool {
		return agent.Stats().StatusReportsSent >= 1
	})
	_ = agent.Stop(ctx)
}

func TestAutoFlushLoopLogsRepeatedFailures(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	cfg := DefaultConfig()
	cfg.APIKey = "test-api-key-123"
	cfg.Endpoint = "http://127.0.0.1:1"
	cfg.StatusInterval = time.Hour
	cfg.BackoffFactor = 0.001
	cfg.InstallIDPath = filepath.Join(t.TempDir(), "install-id")
	agent, err := New(cfg, WithLogger(logger))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = agent.Stop(context.Background()) })
	ctx := context.Background()
	if err := agent.SendEvent(ctx, testEvent(1, "")); err != nil {
		t.Fatalf("SendEvent: %v", err)
	}
	expireGate := func() {
		agent.mu.Lock()
		agent.eventGate = time.Time{}
		agent.mu.Unlock()
	}
	// A first and second failure log the plain line; the gate is expired
	// between ticks so each tick attempts a real flush.
	if got := agent.flushTick(0); got != 1 {
		t.Fatalf("first failure must count one, got %d", got)
	}
	expireGate()
	agent.flushTick(1)
	expireGate()
	if !strings.Contains(buf.String(), "periodic flush failed: ") {
		t.Fatalf("single failures must log plainly, got %q", buf.String())
	}
	if strings.Contains(buf.String(), "repeatedly") {
		t.Fatalf("the escalation must wait for three, got %q", buf.String())
	}
	// ...the third consecutive one escalates.
	if got := agent.flushTick(2); got != 3 {
		t.Fatalf("third failure must count three, got %d", got)
	}
	if !strings.Contains(buf.String(), "periodic flush failing repeatedly (3 in a row)") {
		t.Fatalf("repeated failures must escalate the log, got %q", buf.String())
	}
	// A successful tick resets the streak silently.
	agent.tr.cfg.Endpoint = "http://127.0.0.1:1" // still down: drain nothing
	agent.mu.Lock()
	agent.events = nil
	agent.mu.Unlock()
	if got := agent.flushTick(3); got != 0 {
		t.Fatalf("a clean tick must reset the streak, got %d", got)
	}
}

func TestRulesLoopServesLastKnownRules(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	m := newMockIngest(t)
	cfg := DefaultConfig()
	cfg.APIKey = "test-api-key-123"
	cfg.Endpoint = m.URL
	cfg.FlushInterval = time.Hour
	cfg.StatusInterval = time.Hour
	cfg.BackoffFactor = 0.001
	cfg.InstallIDPath = filepath.Join(t.TempDir(), "install-id")
	agent, err := New(cfg, WithLogger(logger))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = agent.Stop(context.Background()) })
	agent.cfg.DynamicRuleInterval = 5 * time.Millisecond
	// Lift the local request limiter: the 5ms polling cadence would
	// otherwise saturate the 100-per-minute client window mid-test.
	agent.tr.limiter = newRateLimiter(1_000_000, time.Hour)
	m.serveRules(http.StatusInternalServerError, "")
	ctx := context.Background()
	if err := agent.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitUntil(t, 10*time.Second, "repeated rules failures must escalate the log", func() bool {
		return strings.Contains(buf.String(), "dynamic rules loop failing repeatedly")
	})
	// Recovery resets the streak silently; the breaker, opened by the
	// failure streak, is closed again by the first successful probe.
	m.serveRules(http.StatusOK, sampleRulesJSON())
	agent.tr.breaker.Success()
	waitUntil(t, 10*time.Second, "rules recovery must cache the document", func() bool {
		agent.mu.Lock()
		defer agent.mu.Unlock()
		return agent.cachedRules != nil
	})
	_ = agent.Stop(ctx)
}

// --------------------------------------------------------------- config --

func TestNormalizeValidationProblems(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKey = "short"
	cfg.BufferSize = -1
	cfg.FlushInterval = -1
	cfg.StatusInterval = time.Second
	cfg.DynamicRuleInterval = time.Second
	cfg.HighWatermarkRatio = 2
	cfg.MaxConcurrentFlushes = -1
	cfg.Overflow = "bogus"
	cfg.RetryAttempts = -1
	cfg.Timeout = -1
	cfg.BackoffFactor = -1
	cfg.CompressionThreshold = -1
	cfg.MaxPayloadSize = -1
	cfg.Endpoint = "not a url"
	_, _, err := normalize(cfg)
	var cfgErr *ConfigError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("invalid configs must surface a ConfigError, got %v", err)
	}
	for _, want := range []string{
		"api key", "valid URL", "buffer size", "flush interval", "status interval",
		"dynamic rule interval", "high watermark", "max concurrent flushes",
		"overflow policy", "retry attempts", "timeout", "backoff factor",
		"compression threshold", "max payload size",
	} {
		if !strings.Contains(cfgErr.Error(), want) {
			t.Fatalf("problems must include %q, got %q", want, cfgErr.Error())
		}
	}
	if err := cfgErr; err.Error() == "" {
		t.Fatal("message must render")
	}
	// Redis config defaults and problems.
	cfg = DefaultConfig()
	cfg.APIKey = "test-api-key-123"
	cfg.Redis = &RedisConfig{}
	if _, _, err := normalize(cfg); err == nil || !strings.Contains(err.Error(), "redis url is required") {
		t.Fatalf("redis without a url must be rejected, got %v", err)
	}
	cfg.Redis = &RedisConfig{URL: "redis://127.0.0.1:6379", TTL: -1}
	if _, _, err := normalize(cfg); err == nil || !strings.Contains(err.Error(), "redis ttl") {
		t.Fatalf("negative ttl must be rejected, got %v", err)
	}
	cfg.Redis = &RedisConfig{URL: "redis://127.0.0.1:6379"}
	normalized, _, err := normalize(cfg)
	if err != nil {
		t.Fatalf("valid redis config: %v", err)
	}
	if normalized.Redis.Prefix != defaultRedisPrefix || normalized.Redis.TTL != defaultPersistTTL {
		t.Fatalf("redis defaults must apply, got %+v", normalized.Redis)
	}
}

func TestShortOf(t *testing.T) {
	if got := shortOf("prefix:agent_events:event_short"); got != "event_short" {
		t.Fatalf("shortOf must take the last segment, got %q", got)
	}
	if got := shortOf("nocolon"); got != "nocolon" {
		t.Fatalf("a key without a colon passes through, got %q", got)
	}
}

func TestConfigErrorRendersProblems(t *testing.T) {
	err := &ConfigError{Problems: []string{"a", "b"}}
	if err.Error() != "guardagent: invalid configuration: a; b" {
		t.Fatalf("ConfigError render mismatch: %q", err.Error())
	}
}
