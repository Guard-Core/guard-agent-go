package guardagent

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// Encryption wire constants, mirroring guard_agent/encryption.py.
const (
	encryptionNonceSize = 12
	encryptionKeySize   = 32
)

// EncryptionError mirrors the Python EncryptionError: any encryption or
// key-decoding failure.
type EncryptionError struct{ msg string }

func (e *EncryptionError) Error() string { return e.msg }

// EncryptionConfigError mirrors the Python EncryptionConfigError: raised
// when encryption initialization fails; plaintext fallback is forbidden.
type EncryptionConfigError struct{ msg string }

func (e *EncryptionConfigError) Error() string { return e.msg }

// PayloadEncryptor encrypts telemetry payloads with AES-256-GCM, matching
// the Python agent byte-for-byte on the wire: canonical JSON plaintext
// (keys sorted recursively, compact separators, Python ensure_ascii
// escaping), a fresh 12-byte random nonce prefixing each ciphertext, the
// 16-byte GCM auth tag appended, and padded urlsafe base64 output.
type PayloadEncryptor struct {
	aead cipher.AEAD
}

// NewPayloadEncryptor decodes a padded (or unpadded) urlsafe-base64
// 256-bit project key.
func NewPayloadEncryptor(projectKey string) (*PayloadEncryptor, error) {
	if projectKey == "" {
		return nil, &EncryptionError{"Project key cannot be empty"}
	}
	decoded, err := decodeUrlsafeBase64(projectKey)
	if err != nil {
		return nil, &EncryptionError{fmt.Sprintf("Invalid project key format: %v", err)}
	}
	if len(decoded) != encryptionKeySize {
		return nil, &EncryptionError{fmt.Sprintf(
			"Invalid key size: %d bytes, expected %d", len(decoded), encryptionKeySize)}
	}
	// A validated 32-byte AES key and an AES block cipher cannot fail here;
	// the constructor errors of aes.NewCipher and cipher.NewGCM are only
	// reachable with rejected key sizes.
	block, _ := aes.NewCipher(decoded)
	aead, _ := cipher.NewGCM(block)
	return &PayloadEncryptor{aead: aead}, nil
}

// Encrypt returns the padded urlsafe-base64 nonce||ciphertext||tag string,
// byte-compatible with the Python agent's PayloadEncryptor.encrypt.
func (p *PayloadEncryptor) Encrypt(data map[string]any, associatedData string) (string, error) {
	plaintext := canonicalJSON(data)
	nonce := make([]byte, encryptionNonceSize)
	if _, err := cryptoRandRead(nonce); err != nil {
		return "", &EncryptionError{fmt.Sprintf("Failed to encrypt payload: %v", err)}
	}
	var aad []byte
	if associatedData != "" {
		aad = []byte(associatedData)
	}
	sealed := p.aead.Seal(nonce, nonce, []byte(plaintext), aad)
	return encodeUrlsafeBase64(sealed), nil
}

// Decrypt decrypts an encrypted payload (primarily for testing; in normal
// operation only the core backend decrypts).
func (p *PayloadEncryptor) Decrypt(encryptedData, associatedData string) (map[string]any, error) {
	combined, err := decodeUrlsafeBase64(encryptedData)
	if err != nil || len(combined) < encryptionNonceSize+16 {
		return nil, &EncryptionError{"Invalid or tampered payload"}
	}
	nonce := combined[:encryptionNonceSize]
	ciphertext := combined[encryptionNonceSize:]
	var aad []byte
	if associatedData != "" {
		aad = []byte(associatedData)
	}
	plaintext, err := p.aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, &EncryptionError{"Invalid or tampered payload"}
	}
	var parsed map[string]any
	if err := json.Unmarshal(plaintext, &parsed); err != nil || parsed == nil {
		return nil, &EncryptionError{"Invalid or tampered payload"}
	}
	return parsed, nil
}

// VerifyKey performs an encrypt/decrypt round trip, mirroring verify_key.
func (p *PayloadEncryptor) VerifyKey() bool {
	testData := map[string]any{"test": "verification"}
	encrypted, err := p.Encrypt(testData, "")
	if err != nil {
		return false
	}
	decrypted, err := p.Decrypt(encrypted, "")
	if err != nil {
		return false
	}
	raw, _ := json.Marshal(decrypted)
	want, _ := json.Marshal(testData)
	return bytes.Equal(raw, want)
}

// CreateEncryptor returns nil when no key is configured; an invalid key is
// an error, mirroring create_encryptor.
func CreateEncryptor(projectKey string) (*PayloadEncryptor, error) {
	if projectKey == "" {
		return nil, nil
	}
	return NewPayloadEncryptor(projectKey)
}

// canonicalJSON serializes data into the exact bytes Python
// json.dumps(data, separators=(",", ":"), sort_keys=True) emits: object
// keys sorted recursively, compact separators, and Python ensure_ascii
// escaping. encoding/json cannot produce those bytes (it does not escape
// non-ASCII and preserves map iteration order), so values are walked
// manually. Raw JSON messages are preserved as-is when present.
func canonicalJSON(data map[string]any) string {
	var b strings.Builder
	writeCanonicalJSON(data, &b)
	return b.String()
}

func writeCanonicalJSON(value any, b *strings.Builder) {
	switch v := value.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if v {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case int:
		b.WriteString(strconv.Itoa(v))
	case int8:
		b.WriteString(strconv.FormatInt(int64(v), 10))
	case int16:
		b.WriteString(strconv.FormatInt(int64(v), 10))
	case int32:
		b.WriteString(strconv.FormatInt(int64(v), 10))
	case int64:
		b.WriteString(strconv.FormatInt(v, 10))
	case uint:
		b.WriteString(strconv.FormatUint(uint64(v), 10))
	case uint8:
		b.WriteString(strconv.FormatUint(uint64(v), 10))
	case uint16:
		b.WriteString(strconv.FormatUint(uint64(v), 10))
	case uint32:
		b.WriteString(strconv.FormatUint(uint64(v), 10))
	case uint64:
		b.WriteString(strconv.FormatUint(v, 10))
	case float32:
		writeCanonicalFloat(float64(v), 32, b)
	case float64:
		writeCanonicalFloat(v, 64, b)
	case string:
		writeCanonicalString(v, b)
	case json.RawMessage:
		b.Write(v)
	case json.Number:
		b.WriteString(v.String())
	case []any:
		b.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				b.WriteByte(',')
			}
			writeCanonicalJSON(item, b)
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeCanonicalString(key, b)
			b.WriteByte(':')
			writeCanonicalJSON(v[key], b)
		}
		b.WriteByte('}')
	default:
		// Best-effort fallback through encoding/json for other types
		// (time.Time, structs); it matches Python's serialization for
		// the types the agent itself places in payloads.
		encoded, err := json.Marshal(v)
		if err != nil {
			b.WriteString("null")
			return
		}
		b.Write(encoded)
	}
}

// writeCanonicalFloat writes a float like Python repr: shortest round-trip
// form, with ".0" for whole values, matching Python json.dumps for floats.
func writeCanonicalFloat(v float64, bitSize int, b *strings.Builder) {
	if v == float64(int64(v)) && v >= -1e15 && v <= 1e15 {
		b.WriteString(strconv.FormatFloat(v, 'f', 1, bitSize))
		return
	}
	b.WriteString(strconv.FormatFloat(v, 'g', -1, bitSize))
}

// writeCanonicalString escapes exactly like Python json.dumps with
// ensure_ascii: short escapes for " \ b f n r t, \uXXXX for other control
// and non-ASCII characters, surrogate pairs for astral planes.
func writeCanonicalString(text string, b *strings.Builder) {
	b.WriteByte('"')
	for _, r := range text {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			code := uint32(r)
			if code < 0x20 || code > 0x7e {
				if code > 0xffff {
					for _, unit := range utf16.Encode([]rune{r}) {
						fmt.Fprintf(b, `\u%04x`, unit)
					}
				} else {
					fmt.Fprintf(b, `\u%04x`, code)
				}
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

// decodeUrlsafeBase64 accepts padded and unpadded urlsafe base64, matching
// the Python decoder's alphabet while tolerating both padding variants.
func decodeUrlsafeBase64(text string) ([]byte, error) {
	trimmed := strings.TrimRight(text, "=")
	return base64.RawURLEncoding.DecodeString(trimmed)
}

// encodeUrlsafeBase64 emits padded urlsafe base64, matching Python
// base64.urlsafe_b64encode.
func encodeUrlsafeBase64(data []byte) string {
	return base64.URLEncoding.EncodeToString(data)
}
