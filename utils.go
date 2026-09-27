package guardagent

import (
	"crypto/sha256"
	"encoding/hex"
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
