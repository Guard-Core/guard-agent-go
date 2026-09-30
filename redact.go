package guardagent

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// DefaultSensitiveHeaders is the default sensitive-header set, matching
// guard-agent (Python) AgentConfig.sensitive_headers.
var DefaultSensitiveHeaders = []string{
	"authorization",
	"proxy-authorization",
	"cookie",
	"x-api-key",
}

const (
	// maxSanitizeDepth bounds recursion; a subtree deeper than this is
	// redacted wholesale rather than walked, mirroring the Python agent.
	maxSanitizeDepth = 10
	// maxJSONScanLen bounds how long a string is JSON-scanned; longer
	// strings are redacted wholesale (fail-closed), matching Python.
	maxJSONScanLen = 8192
	// redactedMarker replaces every sensitive value, matching the Python
	// agent's [REDACTED] sentinel.
	redactedMarker = "[REDACTED]"
)

// normalizeSensitiveHeaders lowercases and trims the configured header
// names and returns the defaults for a nil list. An empty non-nil list is
// an intentional replacement: nothing beyond it is redacted.
func normalizeSensitiveHeaders(headers []string) []string {
	if headers == nil {
		headers = DefaultSensitiveHeaders
	}
	lowered := make([]string, 0, len(headers))
	for _, h := range headers {
		lowered = append(lowered, strings.ToLower(strings.TrimSpace(h)))
	}
	return lowered
}

// SanitizeHeaders removes sensitive values from telemetry data. It is the
// Go port of guard_agent.utils.sanitize_headers: it recurses into nested
// maps, slices, and JSON-looking string values up to a bounded depth; a
// subtree deeper than that is redacted wholesale rather than walked. Map
// keys are matched case-insensitively after stripping whitespace. Values
// of unrepresentable kinds (channels, funcs, structs other than the
// recognized scalars) are redacted fail-closed.
func SanitizeHeaders(value any, sensitiveHeaders []string) any {
	if sensitiveHeaders == nil {
		sensitiveHeaders = DefaultSensitiveHeaders
	}
	lowered := make(map[string]struct{}, len(sensitiveHeaders))
	for _, h := range sensitiveHeaders {
		lowered[strings.ToLower(strings.TrimSpace(h))] = struct{}{}
	}
	return sanitizeValue(value, lowered, 0)
}

func isSensitiveKey(key string, loweredSensitive map[string]struct{}) bool {
	_, ok := loweredSensitive[strings.ToLower(strings.TrimSpace(key))]
	return ok
}

func sanitizeValue(value any, loweredSensitive map[string]struct{}, depth int) any {
	if depth > maxSanitizeDepth {
		return redactedMarker
	}
	switch v := value.(type) {
	case nil, bool,
		int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64,
		float32, float64,
		[]byte:
		return value
	case string:
		return sanitizeStringValue(v, loweredSensitive, depth)
	case time.Time, time.Duration, json.Number:
		return value
	case map[string]any:
		return sanitizeStringAnyMap(v, loweredSensitive, depth)
	case map[string]string:
		return sanitizeStringStringMap(v, loweredSensitive, depth)
	case []any:
		sanitized := make([]any, len(v))
		for i, item := range v {
			sanitized[i] = sanitizeValue(item, loweredSensitive, depth+1)
		}
		return sanitized
	case []string:
		sanitized := make([]string, len(v))
		for i, item := range v {
			sanitized[i] = sanitizeValue(item, loweredSensitive, depth+1).(string)
		}
		return sanitized
	default:
		return redactedMarker
	}
}

func sanitizeStringAnyMap(
	value map[string]any, loweredSensitive map[string]struct{}, depth int,
) any {
	sanitized := make(map[string]any, len(value))
	for key, item := range value {
		if isSensitiveKey(key, loweredSensitive) {
			sanitized[key] = redactedMarker
			continue
		}
		sanitized[key] = sanitizeValue(item, loweredSensitive, depth+1)
	}
	return sanitized
}

func sanitizeStringStringMap(
	value map[string]string, loweredSensitive map[string]struct{}, depth int,
) any {
	sanitized := make(map[string]string, len(value))
	for key, item := range value {
		if isSensitiveKey(key, loweredSensitive) {
			sanitized[key] = redactedMarker
			continue
		}
		// sanitizeValue on a string input always yields a string (scalars
		// pass through, JSON candidates re-serialize, everything else is
		// the redaction marker), so the result formats back to itself.
		sanitized[key] = fmt.Sprintf("%v", sanitizeValue(item, loweredSensitive, depth+1))
	}
	return sanitized
}

// sanitizeStringValue JSON-scans strings that look like JSON (leading
// `{`, `[`, or `"`), redacts the scan when the candidate exceeds
// maxJSONScanLen, and re-serializes the sanitized structure; a value that
// does not parse as JSON passes through untouched, all mirroring the
// Python agent.
func sanitizeStringValue(
	value string, loweredSensitive map[string]struct{}, depth int,
) string {
	stripped := strings.TrimSpace(value)
	if stripped == "" || (stripped[0] != '{' && stripped[0] != '[' && stripped[0] != '"') {
		return value
	}
	if len(stripped) > maxJSONScanLen {
		return redactedMarker
	}
	var parsed any
	if err := json.Unmarshal([]byte(stripped), &parsed); err != nil {
		return value
	}
	sanitized := sanitizeValue(parsed, loweredSensitive, depth+1)
	// sanitized only contains JSON-representable values (it was decoded
	// from JSON and re-walked), so re-encoding cannot fail.
	encoded, _ := json.Marshal(sanitized)
	return string(encoded)
}

// redactEventMetadata returns a copy of the event with a redacted
// Metadata map, mirroring the Python agent's capture-time redaction. The
// input map is never mutated.
func redactEventMetadata(ev SecurityEvent, sensitiveHeaders []string) SecurityEvent {
	if ev.Metadata == nil {
		return ev
	}
	// A map input always sanitizes back to a map.
	ev.Metadata = SanitizeHeaders(ev.Metadata, sensitiveHeaders).(map[string]any)
	return ev
}

// redactMetricTags returns a copy of the metric with redacted Tags,
// mirroring the Python agent's capture-time redaction for metrics.
func redactMetricTags(m SecurityMetric, sensitiveHeaders []string) SecurityMetric {
	if m.Tags == nil {
		return m
	}
	// A string-map input always sanitizes back to a string map.
	m.Tags = SanitizeHeaders(m.Tags, sensitiveHeaders).(map[string]string)
	return m
}

// redactBatch performs the serialization-time redaction pass the Python
// transport runs over every outgoing batch body.
func redactBatch(batch *eventBatch, sensitiveHeaders []string) {
	for i := range batch.Events {
		batch.Events[i] = redactEventMetadata(batch.Events[i], sensitiveHeaders)
	}
	for i := range batch.Metrics {
		batch.Metrics[i] = redactMetricTags(batch.Metrics[i], sensitiveHeaders)
	}
}
