package guardagent

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestGenerateBatchIDShape(t *testing.T) {
	id := GenerateBatchID()
	if id == "" {
		t.Fatal("the batch id must not be empty")
	}
	dash := strings.Index(id, "-")
	if dash <= 0 || dash == len(id)-1 {
		t.Fatalf("the batch id must be {unix_millis}-{hex}, got %q", id)
	}
	hexPart := id[dash+1:]
	if len(hexPart) != 8 {
		t.Fatalf("the random suffix must be 8 hex chars, got %q", hexPart)
	}
	again := GenerateBatchID()
	if again == id {
		t.Fatalf("consecutive ids must differ, got %q twice", id)
	}
}

func TestSummarizeResponseBody(t *testing.T) {
	if got := SummarizeResponseBody("one  two\n\nthree\t\tfour", 100); got != "one two three four" {
		t.Fatalf("whitespace must collapse to single spaces, got %q", got)
	}
	long := strings.Repeat("a", 500)
	got := SummarizeResponseBody(long, 100)
	if !strings.HasPrefix(got, strings.Repeat("a", 100)+"... [truncated, 500 chars total]") {
		t.Fatalf("a long body must cap with the original length noted, got %q", got)
	}
	if got := SummarizeResponseBody("short", 0); got != "short" {
		t.Fatalf("a non-positive cap must return the collapsed body, got %q", got)
	}
}

func TestSafeJSONSerialize(t *testing.T) {
	encoded, err := SafeJSONSerialize(map[string]any{"a": 1})
	if err != nil || encoded != `{"a":1}` {
		t.Fatalf("objects must serialize compactly, got (%q, %v)", encoded, err)
	}
	_, err = SafeJSONSerialize(make(chan int))
	serErr, ok := err.(*SerializationError)
	if err == nil || !ok {
		t.Fatalf("an unserializable value must raise SerializationError, got %v (%T)", err, err)
	}
	if !strings.Contains(serErr.Error(), "unsupported type") {
		t.Fatalf("the error must carry the marshal problem, got %v", err)
	}
}

func TestSafeJSONDeserialize(t *testing.T) {
	obj := SafeJSONDeserialize(`{"a": 1}`)
	if obj == nil || obj["a"] != float64(1) {
		t.Fatalf("objects must deserialize, got %v", obj)
	}
	if got := SafeJSONDeserialize(`[1,2]`); got != nil {
		t.Fatalf("a non-object payload must return nil, got %v", got)
	}
	if got := SafeJSONDeserialize("{not json"); got != nil {
		t.Fatalf("a parse failure must return nil, got %v", got)
	}
}

func TestValidateConfigReportsProblems(t *testing.T) {
	problems := ValidateConfig(Config{
		APIKey:   "short",
		Endpoint: "ftp://not-http",
	})
	if len(problems) == 0 {
		t.Fatal("an invalid config must report problems")
	}
	joined := strings.Join(problems, "; ")
	if !strings.Contains(joined, "api key") || !strings.Contains(joined, "endpoint") {
		t.Fatalf("the problems must name the offending fields, got %q", joined)
	}

	sound := DefaultConfig()
	sound.APIKey = "a-sufficiently-long-api-key"
	sound.Endpoint = "https://ingest.example.com"
	if problems := ValidateConfig(sound); len(problems) != 0 {
		t.Fatalf("a sound config must report no problems, got %q", strings.Join(problems, "; "))
	}
}

func TestGenerateBatchIDTimestampAffinity(t *testing.T) {
	before := time.Now().UnixMilli()
	id := GenerateBatchID()
	after := time.Now().UnixMilli()
	prefix := id[:strings.Index(id, "-")]
	var millis int64
	if _, err := fmt.Sscanf(prefix, "%d", &millis); err != nil {
		t.Fatalf("the timestamp prefix must parse, got %q", id)
	}
	if millis < before-1000 || millis > after+1000 {
		t.Fatalf("the timestamp must be current, got %d in [%d, %d]", millis, before, after)
	}
}
