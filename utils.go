package guardagent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// TruncatePayload truncates payload to maxSize with a visible marker,
// mirroring guard_agent.utils.truncate_payload. maxSize counts bytes (the
// Python original counts characters; for ASCII telemetry the two agree).
func TruncatePayload(payload string, maxSize int) string {
	if len(payload) <= maxSize {
		return payload
	}
	return payload[:maxSize] + "...[TRUNCATED]"
}

// HashIP hashes an IP address for privacy-conscious telemetry: the first 16
// hex characters of SHA-256 over ip+salt, mirroring
// guard_agent.utils.hash_ip.
func HashIP(ip string, salt string) string {
	sum := sha256.Sum256([]byte(ip + salt))
	return hex.EncodeToString(sum[:])[:16]
}

// GenerateBatchID returns "{unix_millis}-{8 hex chars}", the reference
// generate_batch_id shape (timestamp plus a random hex suffix).
func GenerateBatchID() string {
	return newBatchID()
}

// SummarizeResponseBody collapses an HTTP response body into a bounded,
// single-line summary, mirroring guard_agent.utils.summarize_response_body:
// whitespace (including newlines) collapses so one response body can never
// span more than one log line, and the summary caps at maxLength characters
// with the original length noted when truncated.
func SummarizeResponseBody(text string, maxLength int) string {
	collapsed := strings.Join(strings.Fields(text), " ")
	if maxLength <= 0 || len(collapsed) <= maxLength {
		return collapsed
	}
	return fmt.Sprintf("%s... [truncated, %d chars total]", collapsed[:maxLength], len(text))
}

// SerializationError is raised when an object cannot be serialized to JSON
// for transport, mirroring the reference SerializationError.
type SerializationError struct {
	Message string
}

func (e *SerializationError) Error() string {
	return e.Message
}

// SafeJSONSerialize serializes v to compact JSON, raising SerializationError
// on failure, mirroring guard_agent.utils.safe_json_serialize.
func SafeJSONSerialize(v any) (string, error) {
	encoded, err := json.Marshal(v)
	if err != nil {
		wrapped := &SerializationError{Message: err.Error()}
		return "", wrapped
	}
	return string(encoded), nil
}

// SafeJSONDeserialize deserializes a JSON object with error handling,
// mirroring guard_agent.utils.safe_json_deserialize: a non-object payload
// or a parse failure returns nil.
func SafeJSONDeserialize(payload string) map[string]any {
	var result map[string]any
	if err := json.Unmarshal([]byte(payload), &result); err != nil {
		return nil
	}
	return result
}

// ValidateConfig audits an agent configuration and returns the list of
// problems, mirroring guard_agent.utils.validate_config: an advisory
// surface that never mutates or applies defaults (the construction-time
// normalize applies defaults and fails closed). An empty list means the
// configuration is sound.
func ValidateConfig(cfg Config) []string {
	_, warnings, err := normalize(cfg)
	problems := []string{}
	if err != nil {
		var configErr *ConfigError
		if errors.As(err, &configErr) {
			problems = append(problems, configErr.Problems...)
		} else {
			problems = append(problems, err.Error())
		}
	}
	problems = append(problems, warnings...)
	return problems
}
