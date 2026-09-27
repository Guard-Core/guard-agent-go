package guardagent

import (
	"context"
	"encoding/json"
	"testing"
)

// ------------------------------------------------- SanitizeHeaders units --

func TestSanitizeHeadersDefaultSensitiveSet(t *testing.T) {
	sensitive := normalizeSensitiveHeaders(nil)
	want := []string{"authorization", "proxy-authorization", "cookie", "x-api-key"}
	if len(sensitive) != len(want) {
		t.Fatalf("default set = %v, want %v", sensitive, want)
	}
	for i, w := range want {
		if sensitive[i] != w {
			t.Fatalf("default set = %v, want %v", sensitive, want)
		}
	}
}

func TestSanitizeHeadersRedactsEachDefaultHeader(t *testing.T) {
	for _, header := range []string{"authorization", "proxy-authorization", "cookie", "x-api-key"} {
		metadata := map[string]any{header: "secret-value", "ok": "fine"}
		sanitized := SanitizeHeaders(metadata, DefaultSensitiveHeaders)
		got, ok := sanitized.(map[string]any)
		if !ok {
			t.Fatalf("%s: wrong result type %T", header, sanitized)
		}
		if got[header] != "[REDACTED]" {
			t.Fatalf("%s: value = %v, want [REDACTED]", header, got[header])
		}
		if got["ok"] != "fine" {
			t.Fatalf("%s: non-sensitive value disturbed: %v", header, got["ok"])
		}
	}
}

func TestSanitizeHeadersMatchesCaseInsensitiveAndTrimmed(t *testing.T) {
	metadata := map[string]any{
		"Authorization":  "bearer x",
		"  COOKIE  ":     "session=1",
		"X-API-KEY":      "k",
		"PROXY-AUTH":     "no",
		"Proxy-Authoriz": "no",
	}
	sanitized := SanitizeHeaders(metadata, nil)
	got := sanitized.(map[string]any)
	if got["Authorization"] != "[REDACTED]" || got["  COOKIE  "] != "[REDACTED]" || got["X-API-KEY"] != "[REDACTED]" {
		t.Fatalf("case-insensitive match failed: %v", got)
	}
	// "PROXY-AUTH" and "Proxy-Authoriz" are NOT in the default set; their
	// values must pass through untouched.
	if got["PROXY-AUTH"] != "no" || got["Proxy-Authoriz"] != "no" {
		t.Fatalf("non-sensitive keys redacted: %v", got)
	}
}

func TestSanitizeHeadersRecursesNestedStructures(t *testing.T) {
	metadata := map[string]any{
		"request": map[string]any{
			"headers": []any{
				map[string]any{"Cookie": "session=1"},
				map[string]any{"Accept": "text/html"},
			},
		},
	}
	sanitized := SanitizeHeaders(metadata, []string{"cookie"})
	outer := sanitized.(map[string]any)["request"].(map[string]any)
	headers := outer["headers"].([]any)
	first := headers[0].(map[string]any)
	second := headers[1].(map[string]any)
	if first["Cookie"] != "[REDACTED]" {
		t.Fatalf("nested cookie value = %v, want [REDACTED]", first["Cookie"])
	}
	if second["Accept"] != "text/html" {
		t.Fatalf("nested accept value = %v, want text/html", second["Accept"])
	}
}

func TestSanitizeHeadersJSONStringValues(t *testing.T) {
	metadata := map[string]any{
		"payload": `{"authorization":"secret","keep":1}`,
		"notjson": "{authorization: secret",
		"scalar":  "plain",
	}
	sanitized := SanitizeHeaders(metadata, nil)
	got := sanitized.(map[string]any)
	var parsed map[string]any
	if err := json.Unmarshal([]byte(got["payload"].(string)), &parsed); err != nil {
		t.Fatalf("payload not re-serialized as JSON: %v", err)
	}
	if parsed["authorization"] != "[REDACTED]" || parsed["keep"] != float64(1) {
		t.Fatalf("JSON string scan wrong: %v", parsed)
	}
	if got["notjson"] != "{authorization: secret" || got["scalar"] != "plain" {
		t.Fatalf("non-JSON strings disturbed: %v", got)
	}
}

func TestSanitizeHeadersOversizeJSONStringRedactedWholesale(t *testing.T) {
	// A JSON-looking string longer than the 8192-byte scan bound is
	// redacted rather than walked, mirroring the Python agent.
	big := `{"a":"` + string(make([]byte, 9000)) + `"}`
	sanitized := SanitizeHeaders(map[string]any{"payload": big}, nil)
	if sanitized.(map[string]any)["payload"] != "[REDACTED]" {
		t.Fatal("oversize JSON-looking string was not redacted wholesale")
	}
}

func TestSanitizeHeadersDepthLimitRedactsWholesale(t *testing.T) {
	// Build a chain deeper than maxSanitizeDepth (10).
	deep := any(map[string]any{"leaf": "value"})
	for i := 0; i < 15; i++ {
		deep = map[string]any{"nested": deep}
	}
	sanitized := SanitizeHeaders(map[string]any{"root": deep}, nil)
	got := sanitized.(map[string]any)["root"]
	for i := 0; i < 10; i++ {
		got = got.(map[string]any)["nested"]
	}
	if got != "[REDACTED]" {
		t.Fatalf("subtree deeper than the depth bound was not redacted wholesale: %#v", got)
	}
}

func TestSanitizeHeadersScalarsPassUnknownStructRedacted(t *testing.T) {
	type opaque struct{ Secret string }
	metadata := map[string]any{
		"count":  3,
		"ratio":  0.5,
		"on":     true,
		"absent": nil,
		"opaque": opaque{Secret: "x"},
	}
	got := SanitizeHeaders(metadata, nil).(map[string]any)
	if got["count"] != 3 || got["ratio"] != 0.5 || got["on"] != true || got["absent"] != nil {
		t.Fatalf("scalars disturbed: %v", got)
	}
	if got["opaque"] != "[REDACTED]" {
		t.Fatalf("unrepresentable struct value = %v, want [REDACTED]", got["opaque"])
	}
}

func TestSanitizeHeadersDoesNotMutateInput(t *testing.T) {
	metadata := map[string]any{"authorization": "secret"}
	_ = SanitizeHeaders(metadata, nil)
	if metadata["authorization"] != "secret" {
		t.Fatalf("input map mutated: %v", metadata)
	}
}

// --------------------------------------------------- config surface ------

func TestDefaultConfigSensitiveHeadersNilMeansDefaults(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.SensitiveHeaders != nil {
		t.Fatalf("DefaultConfig().SensitiveHeaders = %v, want nil (defaults)", cfg.SensitiveHeaders)
	}
	agent := newTestAgent(t, nil, nil)
	got := agent.cfg.SensitiveHeaders
	want := []string{"authorization", "proxy-authorization", "cookie", "x-api-key"}
	if len(got) != len(want) {
		t.Fatalf("normalized sensitive headers = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("normalized sensitive headers = %v, want %v", got, want)
		}
	}
}

func TestConfigSensitiveHeadersCaseNormalized(t *testing.T) {
	agent := newTestAgent(t, nil, func(c *Config) {
		c.SensitiveHeaders = []string{"  X-Custom-Secret ", "AUTHORIZATION"}
	})
	want := []string{"x-custom-secret", "authorization"}
	got := agent.cfg.SensitiveHeaders
	if len(got) != len(want) {
		t.Fatalf("normalized = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("normalized = %v, want %v", got, want)
		}
	}
}

// -------------------------------------------- public API end-to-end -----

func TestSendEventRedactsSensitiveMetadataAtCapture(t *testing.T) {
	m := newMockIngest(t)
	agent := newTestAgent(t, m, func(c *Config) {
		c.SensitiveHeaders = []string{"authorization", "x-custom-secret"}
	})
	ev := SecurityEvent{
		EventType: "penetration_attempt",
		Metadata: map[string]any{
			"authorization":   "Bearer sk-live",
			"X-Custom-Secret": "hunter2",
			"cookie":          "session=1",
			"safe":            "value",
		},
	}
	if err := agent.SendEvent(context.Background(), ev); err != nil {
		t.Fatalf("SendEvent: %v", err)
	}
	if err := agent.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	calls := m.callsTo(eventsPath)
	if len(calls) != 1 {
		t.Fatalf("expected 1 events call, got %d", len(calls))
	}
	if len(calls[0].Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(calls[0].Events))
	}
	md := calls[0].Events[0].Metadata
	for _, key := range []string{"authorization", "X-Custom-Secret"} {
		if md[key] != "[REDACTED]" {
			t.Fatalf("wire metadata[%q] = %v, want [REDACTED]", key, md[key])
		}
	}
	// A custom list replaces the defaults, so cookie is no longer sensitive.
	if md["cookie"] != "session=1" {
		t.Fatalf("cookie should pass through with a replaced list: %v", md["cookie"])
	}
	if md["safe"] != "value" {
		t.Fatalf("safe metadata value disturbed: %v", md["safe"])
	}
}

func TestSendMetricRedactsSensitiveTagsAtCapture(t *testing.T) {
	m := newMockIngest(t)
	agent := newTestAgent(t, m, func(c *Config) {
		c.SensitiveHeaders = []string{"x-api-key"}
	})
	metric := SecurityMetric{
		MetricType: MetricRequestCount,
		Value:      1,
		Tags:       map[string]string{"x-api-key": "k", "route": "/health"},
	}
	if err := agent.SendMetric(context.Background(), metric); err != nil {
		t.Fatalf("SendMetric: %v", err)
	}
	if err := agent.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	calls := m.callsTo(metricsPath)
	if len(calls) != 1 || len(calls[0].Metrics) != 1 {
		t.Fatalf("expected 1 metrics call with 1 metric, got %+v", calls)
	}
	tags := calls[0].Metrics[0].Tags
	if tags["x-api-key"] != "[REDACTED]" {
		t.Fatalf("wire tags[x-api-key] = %q, want [REDACTED]", tags["x-api-key"])
	}
	if tags["route"] != "/health" {
		t.Fatalf("safe tag disturbed: %v", tags)
	}
}

func TestDefaultSensitiveHeadersApplyWithoutConfig(t *testing.T) {
	m := newMockIngest(t)
	agent := newTestAgent(t, m, nil)
	ev := SecurityEvent{
		EventType: "ip_banned",
		Metadata:  map[string]any{"Cookie": "a=b", "referer": "https://x"},
	}
	if err := agent.SendEvent(context.Background(), ev); err != nil {
		t.Fatalf("SendEvent: %v", err)
	}
	if err := agent.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	md := m.callsTo(eventsPath)[0].Events[0].Metadata
	if md["Cookie"] != "[REDACTED]" {
		t.Fatalf("default set did not redact Cookie case-insensitively: %v", md)
	}
	if md["referer"] != "https://x" {
		t.Fatalf("referer disturbed: %v", md)
	}
}

func TestEmptyNonNilSensitiveHeadersDisablesRedaction(t *testing.T) {
	m := newMockIngest(t)
	agent := newTestAgent(t, m, func(c *Config) {
		c.SensitiveHeaders = []string{}
	})
	ev := SecurityEvent{
		EventType: "rate_limited",
		Metadata:  map[string]any{"authorization": "kept-by-request"},
	}
	if err := agent.SendEvent(context.Background(), ev); err != nil {
		t.Fatalf("SendEvent: %v", err)
	}
	if err := agent.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	md := m.callsTo(eventsPath)[0].Events[0].Metadata
	if md["authorization"] != "kept-by-request" {
		t.Fatalf("explicit empty list did not replace defaults: %v", md)
	}
}

func TestSerializationPassRedactsAgain(t *testing.T) {
	// The serialization-time pass must redact even when a caller bypassed
	// the capture-time pass, mirroring the Python transport's second pass.
	tr := newTransport(DefaultConfig(), "install", nil, nil)
	batch := &eventBatch{
		Events: []SecurityEvent{{
			EventType: "penetration_attempt",
			Metadata:  map[string]any{"authorization": "late-secret", "ok": 1},
		}},
	}
	raw, err := tr.marshalBatch(batch)
	if err != nil {
		t.Fatalf("marshalBatch: %v", err)
	}
	var wire struct {
		Events []SecurityEvent `json:"events"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatalf("unmarshal wire body: %v", err)
	}
	md := wire.Events[0].Metadata
	if md["authorization"] != "[REDACTED]" {
		t.Fatalf("wire body carried unredacted authorization: %v", md)
	}
	if md["ok"] != float64(1) {
		t.Fatalf("safe metadata disturbed on the wire: %v", md)
	}
}
