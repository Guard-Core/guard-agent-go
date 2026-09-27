package guardagent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

type encVector struct {
	KeyB64                string `json:"key_b64"`
	PlaintextJSON         string `json:"plaintext_json"`
	CiphertextB64         string `json:"ciphertext_b64"`
	TamperedCiphertextB64 string `json:"tampered_ciphertext_b64"`
	AAD                   string `json:"aad"`
}

func loadVectors(t *testing.T) []encVector {
	t.Helper()
	raw, err := os.ReadFile("testdata/encryption_vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vectors []encVector
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(vectors) != 4 {
		t.Fatalf("expected 4 vectors, got %d", len(vectors))
	}
	return vectors
}

func TestPayloadEncryptorDecryptsPythonVectors(t *testing.T) {
	for i, v := range loadVectors(t) {
		encryptor, err := NewPayloadEncryptor(v.KeyB64)
		if err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		decrypted, err := encryptor.Decrypt(v.CiphertextB64, v.AAD)
		if err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		// UseNumber keeps Python's int-vs-float distinction on compare.
		decoder := json.NewDecoder(strings.NewReader(v.PlaintextJSON))
		decoder.UseNumber()
		var expected map[string]any
		if err := decoder.Decode(&expected); err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		want, _ := json.Marshal(expected)
		got, _ := json.Marshal(decrypted)
		if !bytes.Equal(got, want) {
			t.Fatalf("vector %d: decrypted %s, want %s", i, got, want)
		}
	}
}

func TestPayloadEncryptorCanonicalJSONBytePins(t *testing.T) {
	// The serializer must reproduce the Python plaintext bytes exactly.
	for i, v := range loadVectors(t) {
		decoder := json.NewDecoder(strings.NewReader(v.PlaintextJSON))
		decoder.UseNumber()
		var data map[string]any
		if err := decoder.Decode(&data); err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		if got := canonicalJSON(data); got != v.PlaintextJSON {
			t.Fatalf("vector %d: canonical %s, want %s", i, got, v.PlaintextJSON)
		}
	}
	// ensure_ascii escaping with surrogate pairs.
	got := canonicalJSON(map[string]any{"unicode": "h\u00e9llo w\u00f6rld \u4f60\u597d"})
	want := `{"unicode":"h\u00e9llo w\u00f6rld \u4f60\u597d"}`
	if got != want {
		t.Fatalf("canonical %s, want %s", got, want)
	}
	if got := canonicalJSON(map[string]any{"emoji": "\U0001F600"}); got != `{"emoji":"\ud83d\ude00"}` {
		t.Fatalf("surrogate pair escaping wrong: %s", got)
	}
}

func TestPayloadEncryptorKeyValidation(t *testing.T) {
	if _, err := NewPayloadEncryptor(""); err == nil {
		t.Fatal("empty key accepted")
	}
	if _, err := NewPayloadEncryptor("AAAA"); err == nil {
		t.Fatal("undersized key accepted")
	}
	var encErr *EncryptionError
	if _, err := NewPayloadEncryptor("AAAA"); !errors.As(err, &encErr) {
		t.Fatalf("wrong error type: %T", err)
	}
	if e, err := CreateEncryptor(""); e != nil || err != nil {
		t.Fatalf("CreateEncryptor with empty key = %v, %v", e, err)
	}
}

func TestPayloadEncryptorTamperAndAAD(t *testing.T) {
	v := loadVectors(t)[0]
	encryptor, err := NewPayloadEncryptor(v.KeyB64)
	if err != nil {
		t.Fatalf("NewPayloadEncryptor: %v", err)
	}
	if _, err := encryptor.Decrypt(v.TamperedCiphertextB64, ""); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
	aadVector := loadVectors(t)[3]
	if _, err := encryptor.Decrypt(aadVector.CiphertextB64, "wrong"); err == nil {
		t.Fatal("AAD mismatch accepted")
	}
}

func TestPayloadEncryptorRoundTripAndPadding(t *testing.T) {
	v := loadVectors(t)[0]
	encryptor, err := NewPayloadEncryptor(v.KeyB64)
	if err != nil {
		t.Fatalf("NewPayloadEncryptor: %v", err)
	}
	data := map[string]any{
		"events":  []any{map[string]any{"event_type": "rate_limit", "ip_address": "1.2.3.4"}},
		"metrics": []any{},
		"zeta":    1,
		"unicode": "hello",
	}
	encrypted, err := encryptor.Encrypt(data, "")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if len(encrypted)%4 != 0 || strings.ContainsAny(encrypted[:len(encrypted)-2], "+/") {
		t.Fatalf("output is not padded urlsafe base64: %s", encrypted)
	}
	decrypted, err := encryptor.Decrypt(encrypted, "")
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	want, _ := json.Marshal(data)
	got, _ := json.Marshal(decrypted)
	if !bytes.Equal(got, want) {
		t.Fatalf("round trip mismatch: %s vs %s", got, want)
	}
	if !encryptor.VerifyKey() {
		t.Fatal("VerifyKey failed for a valid key")
	}
}

func TestAgentRejectsInvalidEncryptionKey(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKey = "test-api-key-123"
	cfg.ProjectEncryptionKey = "not-a-valid-key"
	if _, err := New(cfg); err == nil {
		t.Fatal("invalid encryption key did not fail construction")
	}
	var cfgErr *EncryptionConfigError
	if _, err := New(cfg); !errors.As(err, &cfgErr) {
		t.Fatalf("wrong error type: %T", err)
	}
}

func TestAgentEncryptedIngestEndToEnd(t *testing.T) {
	v := loadVectors(t)[0]
	m := newMockIngest(t)
	agent := newTestAgent(t, m, func(c *Config) {
		c.ProjectEncryptionKey = v.KeyB64
	})
	err := agent.SendEvent(context.Background(), SecurityEvent{
		EventType: "penetration_attempt",
		IPAddress: "203.0.113.7",
	})
	if err != nil {
		t.Fatalf("SendEvent: %v", err)
	}
	if err := agent.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	calls := m.callsTo(encryptedPath)
	if len(calls) != 1 {
		t.Fatalf("expected 1 encrypted call, got %d", len(calls))
	}
	if len(m.callsTo(eventsPath)) != 0 {
		t.Fatal("plaintext events endpoint was used")
	}
	// The mock stores events only for the plaintext paths; fetch the raw
	// envelope body and open it under the configured key.
	encryptor, err := NewPayloadEncryptor(v.KeyB64)
	if err != nil {
		t.Fatalf("NewPayloadEncryptor: %v", err)
	}
	var envelope struct {
		EncryptedPayload string `json:"encrypted_payload"`
		BatchID          string `json:"batch_id"`
		AgentVersion     string `json:"agent_version"`
		GuardVersion     string `json:"guard_version"`
		GuardCoreVersion string `json:"guard_core_version"`
	}
	if err := json.Unmarshal(calls[0].Body, &envelope); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	if envelope.BatchID == "" || envelope.AgentVersion == "" {
		t.Fatalf("envelope missing clear fields: %+v", envelope)
	}
	inner, err := encryptor.Decrypt(envelope.EncryptedPayload, "")
	if err != nil {
		t.Fatalf("decrypt envelope: %v", err)
	}
	keys, ok := inner["events"].([]any)
	if !ok || len(keys) != 1 {
		t.Fatalf("inner payload events wrong: %#v", inner["events"])
	}
}

func TestAgentEncryptedStatusStaysPlaintext(t *testing.T) {
	v := loadVectors(t)[0]
	m := newMockIngest(t)
	agent := newTestAgent(t, m, func(c *Config) {
		c.ProjectEncryptionKey = v.KeyB64
	})
	outcome, err := agent.tr.sendStatus(context.Background(), agentStatusPayload{
		Timestamp: time.Now().UTC(),
		Status:    "healthy",
	})
	if err != nil {
		t.Fatalf("sendStatus: %v", err)
	}
	if outcome != outcomeAccepted {
		t.Fatalf("status outcome = %v, want accepted", outcome)
	}
	if len(m.callsTo(statusPath)) != 1 {
		t.Fatalf("expected 1 status call, got %d", len(m.callsTo(statusPath)))
	}
	if len(m.callsTo(encryptedPath)) != 0 {
		t.Fatal("status report was encrypted")
	}
}
