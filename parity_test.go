package guardagent

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------- rate limiter --

func TestRateLimiterAdmitsUpToCap(t *testing.T) {
	l := newRateLimiter(3, time.Second)
	for i := 0; i < 3; i++ {
		if !l.Acquire() {
			t.Fatalf("acquire %d must be admitted", i+1)
		}
	}
	if l.Acquire() {
		t.Fatal("4th acquire within the window must be denied")
	}
	wait := l.RetryAfter()
	if wait <= 0 || wait > time.Second {
		t.Fatalf("retry after got %s want within (0, 1s]", wait)
	}
}

func TestRateLimiterWindowPrunes(t *testing.T) {
	l := newRateLimiter(1, 10*time.Millisecond)
	if !l.Acquire() {
		t.Fatal("first acquire must be admitted")
	}
	if l.Acquire() {
		t.Fatal("second acquire must be denied")
	}
	time.Sleep(20 * time.Millisecond)
	if !l.Acquire() {
		t.Fatal("acquire after the window must be admitted")
	}
}

func TestRateLimiterRetryAfterZeroWhenEmpty(t *testing.T) {
	l := newRateLimiter(1, time.Second)
	if got := l.RetryAfter(); got != 0 {
		t.Fatalf("retry after got %s want 0", got)
	}
}

// TestSendRateLimitedByLocalLimiter drives the limiter through the public
// Flush path. The production limiter is 100/60s (newTransport default); the
// test swaps in the same limiter type with a tiny window so the denial path
// stays fast while the semantics (denied attempts wait, never hit the wire,
// and give up after the retry budget) stay identical.
func TestSendRateLimitedByLocalLimiter(t *testing.T) {
	m := newMockIngest(t)
	agent := newTestAgent(t, m, func(c *Config) { c.RetryAttempts = 0 })
	agent.tr.limiter = newRateLimiter(2, 100*time.Millisecond)
	ctx := context.Background()

	var sendErr error
	for i := 1; i <= 3; i++ {
		if err := agent.SendEvent(ctx, testEvent(i, "")); err != nil {
			t.Fatalf("SendEvent %d: %v", i, err)
		}
		if err := agent.Flush(ctx); err != nil {
			sendErr = err
		}
	}
	if sendErr == nil {
		t.Fatal("the third flush must fail under the local rate limiter")
	}
	if !strings.Contains(sendErr.Error(), "local rate limit") {
		t.Fatalf("unexpected flush error: %v", sendErr)
	}
	if got := agent.Stats().RequestsSent; got != 2 {
		t.Fatalf("requests sent got %d want 2", got)
	}
	if got := len(m.calls); got != 2 {
		t.Fatalf("HTTP calls got %d want 2 (denied attempts must not hit the wire)", got)
	}
}

// ---------------------------------------------------------- dynamic rules --

func rulesBody(t *testing.T, mutate func(map[string]any)) string {
	t.Helper()
	raw := map[string]any{
		"rule_id":                 "rule-42",
		"version":                 7,
		"ttl":                     300,
		"ip_blacklist":            []string{"10.0.0.1"},
		"ip_whitelist":            []string{"192.168.1.1"},
		"ip_ban_duration":         60,
		"blocked_countries":       []string{"XX"},
		"whitelist_countries":     []string{"YY"},
		"endpoint_rate_limits":    map[string]any{"/api/login": []any{5, 60}},
		"blocked_cloud_providers": []string{"AWS"},
		"blocked_user_agents":     []string{"badbot"},
		"suspicious_patterns":     []string{"union select"},
		"enable_ip_banning":       true,
		"auto_ban_threshold":      3,
		"emergency_mode":          true,
		"emergency_whitelist":     []string{"127.0.0.1"},
		"message":                 "lockdown",
	}
	if mutate != nil {
		mutate(raw)
	}
	out, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal rules: %v", err)
	}
	return string(out)
}

func TestGetDynamicRulesFetchesAndCaches(t *testing.T) {
	m := newMockIngest(t)
	m.serveRules(200, rulesBody(t, nil))
	agent := newTestAgent(t, m, func(c *Config) { c.RetryAttempts = 0 })
	ctx := context.Background()

	rules := agent.GetDynamicRules(ctx)
	if rules == nil {
		t.Fatal("rules must be returned")
	}
	if rules.RuleID != "rule-42" || rules.Version != 7 || !rules.EmergencyMode || rules.Message == nil || *rules.Message != "lockdown" {
		t.Fatalf("decoded rules: %+v", rules)
	}
	if rl, ok := rules.EndpointRateLimits["/api/login"]; !ok || rl[0] != 5 || rl[1] != 60 {
		t.Fatalf("endpoint rate limits: %+v", rules.EndpointRateLimits)
	}
	if got := agent.Stats().RulesFetched; got != 1 {
		t.Fatalf("rules fetched got %d want 1", got)
	}

	// Inside the TTL the cache serves without another request.
	if again := agent.GetDynamicRules(ctx); again != rules {
		t.Fatal("cached rules must be returned within the TTL")
	}
	if got := len(m.callsTo(rulesPath)); got != 1 {
		t.Fatalf("rules requests got %d want 1", got)
	}

	// Once the served TTL has elapsed the next call re-fetches (time is
	// advanced by rewinding the last-update stamp rather than waiting out
	// the 300s default).
	agent.mu.Lock()
	agent.rulesLastUpdate = agent.rulesLastUpdate.Add(-10 * time.Minute)
	agent.mu.Unlock()
	m.serveRules(200, rulesBody(t, nil))
	if agent.GetDynamicRules(ctx) == nil {
		t.Fatal("rules must be returned after ttl expiry")
	}
	if got := len(m.callsTo(rulesPath)); got != 2 {
		t.Fatalf("rules requests after ttl expiry got %d want 2", got)
	}
	if got := agent.Stats().RulesFetched; got != 2 {
		t.Fatalf("rules fetched got %d want 2", got)
	}

	// The GET carries the same auth headers as the POST paths.
	call := m.callsTo(rulesPath)[0]
	if call.Headers.Get("X-API-Key") != "test-api-key-123" {
		t.Fatalf("rules request must carry the API key: %v", call.Headers)
	}
}

func TestGetDynamicRulesSparsePayloadGetsPythonDefaults(t *testing.T) {
	m := newMockIngest(t)
	m.serveRules(200, "{}")
	agent := newTestAgent(t, m, nil)

	rules := agent.GetDynamicRules(context.Background())
	if rules == nil {
		t.Fatal("rules must be returned")
	}
	if rules.RuleID != defaultRuleID || rules.Version != defaultRuleVersion || rules.TTL != defaultRuleTTLSeconds || rules.IPBanDuration != defaultIPBanDuration {
		t.Fatalf("defaults not applied: %+v", rules)
	}
	if rules.Timestamp.IsZero() {
		t.Fatal("timestamp default must be applied")
	}
	if rules.IPBlacklist == nil || len(rules.IPBlacklist) != 0 {
		t.Fatalf("ip_blacklist must decode to an empty list, got %#v", rules.IPBlacklist)
	}
}

func TestGetDynamicRulesFailureServesCache(t *testing.T) {
	m := newMockIngest(t)
	m.serveRules(200, rulesBody(t, nil))
	agent := newTestAgent(t, m, func(c *Config) { c.RetryAttempts = 0 })
	ctx := context.Background()

	first := agent.GetDynamicRules(ctx)
	if first == nil {
		t.Fatal("first fetch must succeed")
	}

	m.serveRules(500, "{}")
	second := agent.GetDynamicRules(ctx)
	if second != first {
		t.Fatal("a failed fetch must serve the cached rules")
	}
	if got := agent.Stats().RulesFetched; got != 1 {
		t.Fatalf("rules fetched got %d want 1", got)
	}

	// No cache and a failing server: nil rules, no panic.
	fresh := newTestAgent(t, m, func(c *Config) { c.RetryAttempts = 0 })
	if got := fresh.GetDynamicRules(ctx); got != nil {
		t.Fatalf("no-cache failure must return nil, got %+v", got)
	}
}

func TestGetDynamicRulesStartsRulesLoop(t *testing.T) {
	m := newMockIngest(t)
	m.serveRules(200, rulesBody(t, nil))
	agent := newTestAgent(t, m, nil)
	if err := agent.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitUntil(t, 2*time.Second, "the rules loop must populate the cache", func() bool {
		return agent.GetDynamicRules(context.Background()) != nil
	})
}

func TestDynamicRulesWireRoundTrip(t *testing.T) {
	expires := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	payload := `{
		"rule_id": "r1", "version": 2,
		"timestamp": "2026-09-27T00:00:00Z",
		"expires_at": "2026-09-30T12:00:00Z",
		"ttl": 120,
		"ip_blacklist": ["1.1.1.1"], "ip_whitelist": [], "ip_ban_duration": 30,
		"blocked_countries": ["RU"], "whitelist_countries": ["US"],
		"global_rate_limit": 100, "global_rate_window": 60,
		"endpoint_rate_limits": {"/x": [10, 30]},
		"blocked_cloud_providers": ["GCP"],
		"blocked_user_agents": ["curl"],
		"suspicious_patterns": ["../"],
		"enable_penetration_detection": false,
		"emergency_whitelist_only": true
	}`
	var rules DynamicRules
	if err := json.Unmarshal([]byte(payload), &rules); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got, want := rules.ExpiresAt.UTC(), expires; !got.Equal(want) {
		t.Fatalf("expires_at got %v want %v", got, want)
	}
	if rules.GlobalRateLimit == nil || *rules.GlobalRateLimit != 100 {
		t.Fatalf("global_rate_limit: %+v", rules.GlobalRateLimit)
	}
	if rules.EnablePenetrationDetection == nil || *rules.EnablePenetrationDetection {
		t.Fatal("enable_penetration_detection must decode false, not the default nil")
	}
	if !rules.EmergencyWhitelistOnly || len(rules.EmergencyWhitelist) != 0 {
		t.Fatalf("emergency surface: %+v", rules)
	}

	// Re-serialization must emit lists, never null, mirroring pydantic's
	// default_factory=list fields.
	out, err := json.Marshal(&rules)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(out, &generic); err != nil {
		t.Fatalf("redecode: %v", err)
	}
	for _, key := range []string{"ip_whitelist", "blocked_countries", "suspicious_patterns", "emergency_whitelist"} {
		if _, ok := generic[key].([]any); !ok {
			t.Fatalf("%s must serialize as a list, got %v", key, generic[key])
		}
	}
}

// ------------------------------------------------------------ error hook --

func TestOnErrorFiresOnPermanentRejection(t *testing.T) {
	m := newMockIngest(t)
	type hookCall struct {
		stage   string
		err     error
		context map[string]any
	}
	calls := make(chan hookCall, 8)
	agent := newTestAgent(t, m, func(c *Config) {
		c.RetryAttempts = 0
		c.OnError = func(stage string, err error, ctx map[string]any) {
			calls <- hookCall{stage, err, ctx}
		}
	})
	ctx := context.Background()
	m.reject400Next(1)

	if err := agent.SendEvent(ctx, testEvent(1, "")); err != nil {
		t.Fatalf("SendEvent: %v", err)
	}
	if err := agent.Flush(ctx); err != nil {
		t.Fatalf("permanent rejection must settle without a flush error: %v", err)
	}
	select {
	case call := <-calls:
		if call.stage != StageTransportSend {
			t.Fatalf("stage got %q want %q", call.stage, StageTransportSend)
		}
		if call.context["data_type"] != "events" {
			t.Fatalf("context: %+v", call.context)
		}
	case <-time.After(time.Second):
		t.Fatal("on_error must fire with the transport_send stage on a permanent rejection")
	}
}

func TestOnErrorFiresOnFlushFailure(t *testing.T) {
	type hookCall struct {
		stage string
		err   error
	}
	calls := make(chan hookCall, 8)
	agent := newTestAgent(t, nil, func(c *Config) {
		c.RetryAttempts = 0
		c.Endpoint = "http://127.0.0.1:1" // dead port: the send fails on connection refused
		c.OnError = func(stage string, err error, _ map[string]any) {
			calls <- hookCall{stage, err}
		}
	})

	ctx := context.Background()
	if err := agent.SendEvent(ctx, testEvent(1, "")); err != nil {
		t.Fatalf("SendEvent: %v", err)
	}
	if err := agent.Flush(ctx); err == nil {
		t.Fatal("flush against a dead endpoint must fail")
	}
	// The baseline fires transport_send at the transport give-up AND
	// flush_events at the flush cycle; drain until the flush stage lands.
	deadline := time.After(2 * time.Second)
	for {
		select {
		case call := <-calls:
			if call.stage == StageFlushEvents {
				if call.err == nil {
					t.Fatal("hook must receive the flush error")
				}
				return
			}
		case <-deadline:
			t.Fatal("on_error must fire with the flush_events stage")
		}
	}
}

func TestOnErrorPanicsAreContained(t *testing.T) {
	m := newMockIngest(t)
	agent := newTestAgent(t, m, func(c *Config) {
		c.RetryAttempts = 0
		c.OnError = func(stage string, err error, ctx map[string]any) {
			panic("hook boom")
		}
	})
	ctx := context.Background()
	m.reject400Next(1)
	if err := agent.SendEvent(ctx, testEvent(1, "")); err != nil {
		t.Fatalf("SendEvent: %v", err)
	}
	if err := agent.Flush(ctx); err != nil {
		t.Fatalf("a panicking hook must not turn into a flush error: %v", err)
	}
}

func TestOnErrorFiresOn413Singleton(t *testing.T) {
	m := newMockIngest(t)
	m.setMaxBody(1)
	stages := make(chan string, 8)
	agent := newTestAgent(t, m, func(c *Config) {
		c.RetryAttempts = 0
		c.OnError = func(stage string, err error, _ map[string]any) {
			stages <- stage
		}
	})
	ctx := context.Background()
	if err := agent.SendEvent(ctx, testEvent(1, "")); err != nil {
		t.Fatalf("SendEvent: %v", err)
	}
	if err := agent.Flush(ctx); err != nil {
		t.Fatalf("413 singleton drop must settle: %v", err)
	}
	select {
	case stage := <-stages:
		if stage != StageTransportSend {
			t.Fatalf("stage got %q want %q", stage, StageTransportSend)
		}
	case <-time.After(time.Second):
		t.Fatal("on_error must fire when a singleton event still exceeds the payload limit")
	}
}

// The encryption stage exists alongside the others and is reachable from
// the encrypted send path; the encrypted-path happy case is covered by the
// wave 8 encryption tests, so here we only pin the stage wiring contract.
func TestEncryptionStageConstantMatchesBaseline(t *testing.T) {
	if StageEncryption != "encryption" || StageTransportSend != "transport_send" ||
		StageFlushEvents != "flush_events" || StageFlushMetrics != "flush_metrics" {
		t.Fatal("stage names must match the Python agent exactly")
	}
}

// ------------------------------------------------------- config surface --

func TestConfigParityDefaults(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.MaxPayloadSize != 1024 {
		t.Fatalf("max payload size got %d want 1024", cfg.MaxPayloadSize)
	}
	if cfg.DynamicRuleInterval != 300*time.Second {
		t.Fatalf("dynamic rule interval got %s want 300s", cfg.DynamicRuleInterval)
	}
	if cfg.OnError != nil {
		t.Fatal("on_error must default to nil")
	}
}

func TestConfigParityValidation(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKey = "test-api-key-123"
	cfg.DynamicRuleInterval = 30 * time.Second
	_, _, err := normalize(cfg)
	var cfgErr *ConfigError
	if !errors.As(err, &cfgErr) || !strings.Contains(err.Error(), "dynamic rule interval") {
		t.Fatalf("expected a dynamic rule interval problem, got %v", err)
	}

	cfg.DynamicRuleInterval = 300 * time.Second
	cfg.MaxPayloadSize = -1
	_, _, err = normalize(cfg)
	if !errors.As(err, &cfgErr) || !strings.Contains(err.Error(), "max payload size") {
		t.Fatalf("expected a max payload size problem, got %v", err)
	}

	cfg.MaxPayloadSize = 0
	normalized, _, err := normalize(cfg)
	if err != nil {
		t.Fatalf("zero max payload size must default-fill, got %v", err)
	}
	if normalized.MaxPayloadSize != 1024 {
		t.Fatalf("default-filled max payload size got %d want 1024", normalized.MaxPayloadSize)
	}
}

// ------------------------------------------------------------------ LOW --

func TestTruncatePayload(t *testing.T) {
	if got := TruncatePayload("short", 10); got != "short" {
		t.Fatalf("got %q", got)
	}
	got := TruncatePayload("0123456789abcdef", 10)
	if got != "0123456789...[TRUNCATED]" {
		t.Fatalf("got %q", got)
	}
	if len(got) != 10+len("...[TRUNCATED]") {
		t.Fatalf("truncated length got %d", len(got))
	}
}

func TestHashIPMatchesPythonVector(t *testing.T) {
	// hashlib.sha256(b"203.0.113.7salty").hexdigest()[:16] on the Python
	// baseline.
	if got := HashIP("203.0.113.7", "salty"); got != "baea654513019302" {
		t.Fatalf("got %q", got)
	}
	if got := HashIP("203.0.113.7", ""); len(got) != 16 {
		t.Fatalf("default salt hash length got %d", len(got))
	}
}

func TestKnownEventTypesTable(t *testing.T) {
	if len(KnownEventTypes) != 39 {
		t.Fatalf("got %d known event types want 39", len(KnownEventTypes))
	}
	for _, name := range []string{"user_agent_blocked", "decorator_violation", "security_headers_applied", "csp_violation", "dynamic_rule_violation"} {
		if !IsKnownEventType(name) {
			t.Fatalf("%s must be a known event type", name)
		}
	}
	if IsKnownEventType("not_a_real_event") {
		t.Fatal("unknown event types must not match")
	}
	// Documentation, not validation: SendEvent still accepts any type.
	m := newMockIngest(t)
	agent := newTestAgent(t, m, nil)
	ev := testEvent(1, "")
	ev.EventType = "brand_new_engine_event"
	if err := agent.SendEvent(context.Background(), ev); err != nil {
		t.Fatalf("event types must not be validated at the consumer: %v", err)
	}
}
