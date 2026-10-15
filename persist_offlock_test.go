package guardagent

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeRedis is a minimal RESP server. SET blocks until gate is closed, so
// tests control exactly when a write completes without sleeping.
type fakeRedis struct {
	ln       net.Listener
	gate     chan struct{}
	setSeen  chan string
	delSeen  chan string
	mu       sync.Mutex
	sets     []string
	order    []string
	dels     []string
	gateOnce sync.Once
}

func newFakeRedis(t *testing.T, gated bool) *fakeRedis {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f := &fakeRedis{ln: ln, gate: make(chan struct{}), setSeen: make(chan string, 64), delSeen: make(chan string, 64)}
	if !gated {
		f.release()
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	t.Cleanup(func() { f.release(); _ = ln.Close() })
	return f
}

func (f *fakeRedis) release() { f.gateOnce.Do(func() { close(f.gate) }) }

func (f *fakeRedis) serve(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	for {
		line, err := r.ReadString('\n')
		if err != nil || !strings.HasPrefix(line, "*") {
			return
		}
		n, _ := strconv.Atoi(strings.TrimSpace(line[1:]))
		args := make([]string, 0, n)
		for i := 0; i < n; i++ {
			hdr, err := r.ReadString('\n')
			if err != nil {
				return
			}
			size, _ := strconv.Atoi(strings.TrimSpace(hdr[1:]))
			buf := make([]byte, size+2)
			if _, err := io.ReadFull(r, buf); err != nil {
				return
			}
			args = append(args, string(buf[:size]))
		}
		switch strings.ToUpper(args[0]) {
		case "HELLO":
			_, _ = c.Write([]byte("-ERR unknown command\r\n"))
		case "SET":
			f.setSeen <- args[1]
			<-f.gate
			f.mu.Lock()
			f.sets = append(f.sets, args[1])
			f.order = append(f.order, "SET "+args[1])
			f.mu.Unlock()
			_, _ = c.Write([]byte("+OK\r\n"))
		case "DEL":
			f.mu.Lock()
			f.dels = append(f.dels, args[1:]...)
			f.order = append(f.order, "DEL "+args[1])
			f.mu.Unlock()
			for _, k := range args[1:] {
				f.delSeen <- k
			}
			_, _ = c.Write([]byte(":1\r\n"))
		default:
			_, _ = c.Write([]byte("+OK\r\n"))
		}
	}
}

func (f *fakeRedis) snapshot() (sets, dels []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.sets...), append([]string(nil), f.dels...)
}

func offLockAgent(t *testing.T, f *fakeRedis, m *mockIngest, mutate func(*Config)) *Agent {
	t.Helper()
	return newTestAgent(t, m, func(c *Config) {
		c.Redis = &RedisConfig{URL: "redis://" + f.ln.Addr().String(), Prefix: "t", TTL: time.Minute}
		if mutate != nil {
			mutate(c)
		}
	})
}

// within fails the test (never passes it) if fn does not finish in time;
// the time bound only turns a deadlock into a failure.
func within(t *testing.T, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { fn(); close(done) }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatalf("%s blocked behind a Redis write", what)
	}
}

func TestSendReturnsBeforeSlowRedisWrite(t *testing.T) {
	f := newFakeRedis(t, true)
	agent := offLockAgent(t, f, newMockIngest(t), nil)
	ctx := context.Background()
	within(t, "SendEvent", func() { _ = agent.SendEvent(ctx, testEvent(1, "")) })
	within(t, "SendMetric", func() { _ = agent.SendMetric(ctx, testMetric(1)) })
	<-f.setSeen
	<-f.setSeen
	if sets, _ := f.snapshot(); len(sets) != 0 {
		t.Fatalf("writes must still be blocked, saw %v", sets)
	}
	f.release()
	agent.persistWG.Wait()
	if sets, _ := f.snapshot(); len(sets) != 2 {
		t.Fatalf("both writes must land after release, got %v", sets)
	}
}

func TestConcurrentSendsNotSerializedBehindSlowWrite(t *testing.T) {
	f := newFakeRedis(t, true)
	agent := offLockAgent(t, f, newMockIngest(t), nil)
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) { defer wg.Done(); _ = agent.SendEvent(ctx, testEvent(i, "")) }(i)
	}
	within(t, "concurrent SendEvent", wg.Wait)
	if got := agent.Stats().EventsPending; got != 8 {
		t.Fatalf("pending got %d want 8", got)
	}
	// Status needs a.mu: it must also be reachable while writes are stuck.
	within(t, "Status", func() { _ = agent.Status() })
	f.release()
	agent.persistWG.Wait()
}

func TestStopDrainsPendingPersistsAndDeletesFlushedKey(t *testing.T) {
	f := newFakeRedis(t, true)
	m := newMockIngest(t)
	agent := offLockAgent(t, f, m, nil)
	if err := agent.SendEvent(context.Background(), testEvent(1, "")); err != nil {
		t.Fatalf("SendEvent: %v", err)
	}
	key := <-f.setSeen
	stopped := make(chan error, 1)
	go func() { stopped <- agent.Stop(context.Background()) }()
	// Stop has flushed the event (its key was released) but cannot return
	// while the write is stuck.
	waitUntil(t, 20*time.Second, "stop flushed the event", func() bool { return len(m.callsTo(eventsPath)) == 1 })
	select {
	case <-stopped:
		t.Fatal("Stop returned with a Redis write still pending")
	default:
	}
	f.release()
	if err := <-stopped; err != nil {
		t.Fatalf("Stop: %v", err)
	}
	sets, dels := f.snapshot()
	if len(sets) != 1 || sets[0] != key {
		t.Fatalf("the pending write must complete before Stop returns: %v", sets)
	}
	_ = dels
	f.mu.Lock()
	order := append([]string(nil), f.order...)
	f.mu.Unlock()
	if len(order) == 0 || order[len(order)-1] != "DEL "+key {
		t.Fatalf("the last operation on a record flushed during its write must be its delete: %v", order)
	}
}

func TestFlushDuringPersistDeletesKey(t *testing.T) {
	f := newFakeRedis(t, true)
	agent := offLockAgent(t, f, newMockIngest(t), nil)
	ctx := context.Background()
	if err := agent.SendEvent(ctx, testEvent(1, "")); err != nil {
		t.Fatalf("SendEvent: %v", err)
	}
	key := <-f.setSeen
	if err := agent.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	f.release()
	agent.persistWG.Wait()
	f.mu.Lock()
	order := append([]string(nil), f.order...)
	f.mu.Unlock()
	if len(order) == 0 || order[len(order)-1] != "DEL "+key {
		t.Fatalf("the key must be deleted after its write lands: %v", order)
	}
	agent.mu.Lock()
	defer agent.mu.Unlock()
	if len(agent.inflight) != 0 {
		t.Fatalf("inflight must be empty: %v", agent.inflight)
	}
}

func TestRequeueDuringPersistTracksKey(t *testing.T) {
	f := newFakeRedis(t, true)
	// The endpoint is unreachable, so the flush fails and requeues.
	agent := offLockAgent(t, f, nil, func(c *Config) {
		c.Endpoint = "http://127.0.0.1:1"
		c.RetryAttempts = 0
	})
	ctx := context.Background()
	if err := agent.SendEvent(ctx, testEvent(1, "")); err != nil {
		t.Fatalf("SendEvent: %v", err)
	}
	key := <-f.setSeen
	if err := agent.Flush(ctx); err == nil {
		t.Fatal("flush must fail against a dead endpoint")
	}
	f.release()
	agent.persistWG.Wait()
	_, dels := f.snapshot()
	if len(dels) != 0 {
		t.Fatalf("a requeued record must stay persisted, deleted %v", dels)
	}
	agent.mu.Lock()
	defer agent.mu.Unlock()
	if len(agent.events) != 1 || agent.events[0].key != key || len(agent.inflight) != 0 {
		t.Fatalf("requeued event must keep its key: %+v inflight=%v", agent.events, agent.inflight)
	}
}

func TestNoGoroutineWithoutPersistence(t *testing.T) {
	agent := newTestAgent(t, newMockIngest(t), nil)
	before := runtime.NumGoroutine()
	for i := 0; i < 50; i++ {
		_ = agent.SendEvent(context.Background(), testEvent(i, ""))
		_ = agent.SendMetric(context.Background(), testMetric(i))
	}
	if after := runtime.NumGoroutine(); after > before {
		t.Fatalf("goroutines grew %d -> %d without persistence", before, after)
	}
	if agent.inflight != nil {
		t.Fatal("no persistence bookkeeping expected")
	}
}

func TestStartupEncryptionErrorIncludesCause(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKey = "test-api-key-123"
	cfg.ProjectEncryptionKey = "!!not-base64!!"
	_, err := New(cfg)
	var cfgErr *EncryptionConfigError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("want EncryptionConfigError, got %T %v", err, err)
	}
	cause := errors.Unwrap(err)
	if cause == nil || !strings.Contains(err.Error(), cause.Error()) {
		t.Fatalf("message must include the wrapped cause: %v / %v", err, cause)
	}
}

func TestNoPersistAfterStop(t *testing.T) {
	f := newFakeRedis(t, false)
	agent := offLockAgent(t, f, newMockIngest(t), nil)
	if err := agent.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	agent.mu.Lock()
	key := agent.reserveMetricKeyLocked(testMetric(1))
	agent.mu.Unlock()
	if key != "" || len(agent.inflight) != 0 {
		t.Fatalf("a closed agent must not start persists: %q %v", key, agent.inflight)
	}
}

func TestStopReturnsWhenContextEndsDuringDrain(t *testing.T) {
	f := newFakeRedis(t, true)
	agent := offLockAgent(t, f, newMockIngest(t), nil)
	_ = agent.SendMetric(context.Background(), testMetric(1))
	<-f.setSeen
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	within(t, "Stop with a done context", func() { _ = agent.Stop(ctx) })
	f.release()
}

// inflightLen reads the in-flight persist count under the lock.
func inflightLen(a *Agent) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.inflight)
}

func TestInflightPersistsNeverExceedBufferSize(t *testing.T) {
	f := newFakeRedis(t, true)
	agent := offLockAgent(t, f, newMockIngest(t), func(c *Config) { c.BufferSize = 3 })
	ctx := context.Background()
	for i := 0; i < 20; i++ {
		_ = agent.SendEvent(ctx, testEvent(i, ""))
	}
	for i := 0; i < 3; i++ {
		_ = agent.SendMetric(ctx, testMetric(i))
	}
	if got := inflightLen(agent); got > 3 {
		t.Fatalf("in-flight persists %d exceed buffer size 3", got)
	}
	f.release()
	agent.persistWG.Wait()
}

func TestPersistBacklogCountsAndWarnsOncePerEpisode(t *testing.T) {
	f := newFakeRedis(t, true)
	var buf bytes.Buffer
	agent := newTestAgent(t, newMockIngest(t), func(c *Config) {
		c.Redis = &RedisConfig{URL: "redis://" + f.ln.Addr().String(), Prefix: "t", TTL: time.Minute}
		c.BufferSize = 3
	}, WithLogger(log.New(&buf, "", 0)))
	ctx := context.Background()
	warnings := func() int { return strings.Count(buf.String(), "persist backlog at buffer_size=3;") }
	for i := 0; i < 5; i++ {
		_ = agent.SendEvent(ctx, testEvent(i, ""))
	}
	agent.mu.Lock()
	failures, logged := agent.redisPersistFailures, agent.persistOverflowLogged
	agent.mu.Unlock()
	if failures != 2 || !logged || warnings() != 1 {
		t.Fatalf("want 2 failures and one warning, got %d, logged=%v, warnings=%d", failures, logged, warnings())
	}
	f.release()
	agent.persistWG.Wait()
	if inflightLen(agent) != 0 || agent.persistOverflowLogged {
		t.Fatal("draining must end the episode")
	}

	// A second episode saturates again and warns again.
	f2 := newFakeRedis(t, true)
	agent.persist, _ = newPersistence(&RedisConfig{URL: "redis://" + f2.ln.Addr().String(), Prefix: "t", TTL: time.Minute}, agent.logger)
	for i := 0; i < 5; i++ {
		_ = agent.SendMetric(ctx, testMetric(i))
	}
	if warnings() != 2 {
		t.Fatalf("the second episode must warn again, got %d", warnings())
	}
	f2.release()
	agent.persistWG.Wait()
}

func TestRecordGoneBeforeWriteStartsIsNeverWritten(t *testing.T) {
	f := newFakeRedis(t, false)
	agent := offLockAgent(t, f, newMockIngest(t), nil)
	// The writer blocks on a.mu until the lock is released, so the record
	// can be released before the write starts.
	agent.mu.Lock()
	key := agent.reserveEventKeyLocked(testEvent(1, ""))
	agent.inflight[key] = true
	agent.mu.Unlock()
	agent.persistWG.Wait()
	if sets, _ := f.snapshot(); len(sets) != 0 {
		t.Fatalf("a released record must not be written: %v", sets)
	}
	if inflightLen(agent) != 0 {
		t.Fatal("inflight must be empty")
	}
}
