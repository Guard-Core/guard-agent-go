//go:build integration

package guardagent

// Coverage tests, integration tier: Redis-backed durability branches,
// driven against the real Redis from CI with go-redis hooks for
// deterministic fault injection.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// redisHook rewrites or observes commands by name.
type redisHook struct {
	onProcess func(cmdName string, next func() error) error
}

func (h redisHook) DialHook(next redis.DialHook) redis.DialHook {
	return next
}

func (h redisHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if h.onProcess != nil {
			return h.onProcess(cmd.Name(), func() error { return next(ctx, cmd) })
		}
		return next(ctx, cmd)
	}
}

func (h redisHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

// uniqueSuffix namespaces keys per run so leftovers from an earlier run
// (inside the record TTL) cannot leak into reloads and scans.
func uniqueSuffix() string {
	return fmt.Sprintf("r%d", time.Now().UnixNano())
}

// scanAll runs a full SCAN iteration; a single SCAN page can legitimately
// come back empty when the keyspace is large.
func scanAll(ctx context.Context, client *redis.Client, pattern string) []string {
	var out []string
	var cursor uint64
	for {
		page, next, err := client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return out
		}
		out = append(out, page...)
		if next == 0 {
			return out
		}
		cursor = next
	}
}

func newHookedPersistence(t *testing.T, prefix string, mutate func(*redisHook)) *persistence {
	t.Helper()
	host := integrationRedisHost(t)
	hook := &redisHook{}
	if mutate != nil {
		mutate(hook)
	}
	p, err := newPersistence(&RedisConfig{
		URL:    "redis://" + host + ":6379",
		Prefix: prefix,
		TTL:    time.Minute,
	}, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("newPersistence: %v", err)
	}
	p.client.AddHook(*hook)
	t.Cleanup(func() { _ = p.close() })
	return p
}

func TestPersistenceStoreCooldownAndReset(t *testing.T) {
	p := newHookedPersistence(t, integrationRedisPrefix+":store:"+uniqueSuffix(), func(h *redisHook) {
		h.onProcess = func(name string, next func() error) error {
			if name == "set" {
				return errors.New("redis exploded")
			}
			return next()
		}
	})
	// The dead-write path is logged per failure...
	if p.store("k1", "v") {
		t.Fatal("writes against a failing redis must report not-durable")
	}
	if p.store("k2", "v") {
		t.Fatal("writes against a failing redis must report not-durable")
	}
	// ...and pause after three consecutive failures.
	if p.store("k3", "v") {
		t.Fatal("writes against a failing redis must report not-durable")
	}
	if p.storeAvailable() {
		t.Fatal("three consecutive failures must arm the write cooldown")
	}
	if p.store("k4", "v") {
		t.Fatal("writes during the cooldown must not even be attempted")
	}

	// A success between failures resets the consecutive counter.
	spy := newHookedPersistence(t, integrationRedisPrefix+":reset:"+uniqueSuffix(), func(h *redisHook) {
		fails := 0
		h.onProcess = func(name string, next func() error) error {
			if name == "set" {
				fails++
				if fails == 1 {
					return errors.New("redis exploded once")
				}
			}
			return next()
		}
	})
	if spy.store("k1", "v") {
		t.Fatal("the first write must fail")
	}
	if !spy.store("k2", "v") {
		t.Fatal("the retry write must succeed once redis recovers")
	}
	if !spy.store("k3", "v") {
		t.Fatal("writes must stay available after a recovery")
	}
}

func TestPersistenceDelEmptyAndFailure(t *testing.T) {
	p := newHookedPersistence(t, integrationRedisPrefix+":del:"+uniqueSuffix(), nil)
	p.del(nil) // empty deletes are no-ops

	failing := newHookedPersistence(t, integrationRedisPrefix+":del:"+uniqueSuffix(), func(h *redisHook) {
		h.onProcess = func(name string, next func() error) error {
			if name == "del" {
				return errors.New("del exploded")
			}
			return next()
		}
	})
	failing.del([]string{"k1", "k2"}) // logged, never surfaced
}

func TestLoadKindHandlesScanAndReadErrors(t *testing.T) {
	ctx := context.Background()
	p := newHookedPersistence(t, integrationRedisPrefix+":scan:"+uniqueSuffix(), func(h *redisHook) {
		h.onProcess = func(name string, next func() error) error {
			if name == "scan" {
				return errors.New("scan exploded")
			}
			return next()
		}
	})
	if _, err := p.loadKind(ctx, persistNamespaceEvents); err == nil {
		t.Fatal("a failing scan must surface")
	}

	// Seed one live record; the GET hook reports it vanished (redis.Nil) or
	// broken, per scenario.
	seed := func(hookErr error) *persistence {
		p := newHookedPersistence(t, integrationRedisPrefix+":get:"+uniqueSuffix(), func(h *redisHook) {
			h.onProcess = func(name string, next func() error) error {
				if name == "set" {
					return next()
				}
				if name == "get" && hookErr != nil {
					return hookErr
				}
				return next()
			}
		})
		if !p.store(p.fullKey(persistNamespaceEvents, "event_seed"), `{"event_type":"seed"}`) {
			t.Fatal("seed write must be durable")
		}
		return p
	}

	vanished := seed(redis.Nil)
	items, err := vanished.loadKind(ctx, persistNamespaceEvents)
	if err != nil {
		t.Fatalf("a vanished record must be skipped, got %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("a vanished record must not be reloaded, got %+v", items)
	}

	broken := seed(errors.New("get exploded"))
	if _, err := broken.loadKind(ctx, persistNamespaceEvents); err == nil {
		t.Fatal("a failing read must surface")
	}
}

func TestFetchDynamicRulesSendsProjectHeader(t *testing.T) {
	m := newMockIngest(t)
	m.serveRules(200, sampleRulesJSON())
	agent := newTestAgent(t, m, func(c *Config) { c.ProjectID = "acme" })
	rules := agent.GetDynamicRules(context.Background())
	if rules == nil || rules.RuleID != "saas-rule" {
		t.Fatalf("rules fetch must succeed, got %+v", rules)
	}
	calls := m.callsTo(rulesPath)
	if len(calls) != 1 || calls[0].Headers.Get("X-Project-Id") != "acme" {
		t.Fatalf("the rules fetch must carry the project header, got %+v", calls)
	}
}

func TestLoadKindPagesThroughLargeNamespaces(t *testing.T) {
	p := newHookedPersistence(t, integrationRedisPrefix+":pages:"+uniqueSuffix(), nil)
	ctx := context.Background()
	for i := 0; i < 250; i++ {
		key := p.fullKey(persistNamespaceEvents, fmt.Sprintf("event_%04d", i))
		if !p.store(key, fmt.Sprintf(`{"event_type":"e%d"}`, i)) {
			t.Fatalf("seed write %d must be durable", i)
		}
	}
	items, err := p.loadKind(ctx, persistNamespaceEvents)
	if err != nil {
		t.Fatalf("loadKind: %v", err)
	}
	if len(items) != 250 {
		t.Fatalf("every record must reload across scan pages, got %d", len(items))
	}
	if items[0].Short >= items[len(items)-1].Short {
		t.Fatal("records must reload oldest first")
	}
}

func TestOverflowDropConfirmsEvictedPersistedMetric(t *testing.T) {
	host := integrationRedisHost(t)
	prefix := integrationRedisPrefix + ":mdrop:" + uniqueSuffix()
	client := redis.NewClient(&redis.Options{Addr: host + ":6379"})
	t.Cleanup(func() {
		keys := scanAll(context.Background(), client, prefix+":*")
		if len(keys) > 0 {
			_ = client.Del(context.Background(), keys...).Err()
		}
		_ = client.Close()
	})
	m := newMockIngest(t)
	agent := newTestAgent(t, m, func(c *Config) {
		c.BufferSize = 1
		c.HighWatermarkRatio = 1.0
		c.Redis = &RedisConfig{URL: "redis://" + host + ":6379", Prefix: prefix, TTL: time.Minute}
	})
	ctx := context.Background()
	if err := agent.SendMetric(ctx, testMetric(1)); err != nil {
		t.Fatalf("SendMetric: %v", err)
	}
	// The buffer holds one metric; the second evicts the first, whose
	// persisted record must be confirmed (deleted).
	if err := agent.SendMetric(ctx, testMetric(2)); err != nil {
		t.Fatalf("SendMetric: %v", err)
	}
	waitUntil(t, 5*time.Second, "the evicted record must be deleted", func() bool {
		return len(scanAll(ctx, client, prefix+":agent_metrics:*")) == 1
	})
	_ = agent.Stop(ctx)
}

func TestReloadFromRedisRestoresDropsAndEvicts(t *testing.T) {
	host := integrationRedisHost(t)
	prefix := integrationRedisPrefix + ":reload:" + uniqueSuffix()
	client := redis.NewClient(&redis.Options{Addr: host + ":6379"})
	t.Cleanup(func() {
		_ = client.Del(context.Background(),
			prefix+":agent_events:*",
		).Err()
		keys, _, _ := client.Scan(context.Background(), 0, prefix+":agent_*", 100).Result()
		if len(keys) > 0 {
			_ = client.Del(context.Background(), keys...).Err()
		}
		_ = client.Close()
	})
	ctx := context.Background()

	validEvent := func(n int) string {
		data, _ := json.Marshal(testEvent(n, ""))
		return string(data)
	}
	corrupt := "{not json"

	// Controlled short keys keep the lexicographic (chronological) reload
	// order deterministic.
	eventShorts := []string{"event_0001", "event_0002", "event_0003", "event_0004"}
	// Four events over a two-slot buffer: the two oldest must be evicted
	// (and deleted) so they cannot resurrect, leaving the newest two.
	values := []string{validEvent(1), validEvent(2), validEvent(3), validEvent(4)}
	for i, short := range eventShorts {
		if err := client.Set(ctx, prefix+":agent_events:"+short, values[i], time.Minute).Err(); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	corruptShort := "event_ffff"
	if err := client.Set(ctx, prefix+":agent_events:"+corruptShort, corrupt, time.Minute).Err(); err != nil {
		t.Fatalf("seed: %v", err)
	}
	metricShorts := []string{"metric_0001", "metric_0002", "metric_0003"}
	for i, short := range metricShorts {
		data, _ := json.Marshal(testMetric(i))
		if err := client.Set(ctx, prefix+":agent_metrics:"+short, string(data), time.Minute).Err(); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	corruptMetricShort := "metric_ffff"
	if err := client.Set(ctx, prefix+":agent_metrics:"+corruptMetricShort, corrupt, time.Minute).Err(); err != nil {
		t.Fatalf("seed: %v", err)
	}

	agent := newTestAgent(t, nil, func(c *Config) {
		c.BufferSize = 2
		c.Redis = &RedisConfig{URL: "redis://" + host + ":6379", Prefix: prefix, TTL: time.Minute}
	})
	if err := agent.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	stats := agent.Stats()
	if stats.EventsPending != 2 || stats.MetricsPending != 2 {
		t.Fatalf("reload must cap at the buffer size, got %+v", stats)
	}
	// Every reloaded record counts as buffered, including the ones the
	// capacity guard evicts afterwards.
	if stats.EventsBuffered != 4 || stats.MetricsBuffered != 3 {
		t.Fatalf("reload must count buffered items, got %+v", stats)
	}
	// The corrupt records must be deleted so a later restart cannot
	// resurrect them, along with the evicted oldest records.
	for _, short := range append(eventShorts[:2], corruptShort, metricShorts[0], corruptMetricShort) {
		namespace := persistNamespaceEvents
		if strings.Contains(short, "metric") {
			namespace = persistNamespaceMetrics
		}
		full := prefix + ":" + namespace + ":" + short
		if n, _ := client.Exists(ctx, full).Result(); n != 0 {
			t.Fatalf("record %s must be deleted after eviction or corruption", full)
		}
	}
	// The surviving records must be the newest ones.
	agent.mu.Lock()
	first := agent.events[0].ev.EventType
	second := agent.events[1].ev.EventType
	agent.mu.Unlock()
	if first != "event_3" || second != "event_4" {
		t.Fatalf("reload must apply oldest first, got %s then %s", first, second)
	}
	_ = agent.Stop(ctx)
}

func TestReloadSurvivesRedisOutage(t *testing.T) {
	host := integrationRedisHost(t)
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	cfg := DefaultConfig()
	cfg.APIKey = "test-api-key-123"
	cfg.Endpoint = "http://127.0.0.1:1"
	cfg.InstallIDPath = filepath.Join(t.TempDir(), "install-id")
	cfg.Redis = &RedisConfig{URL: "redis://" + host + ":6379", Prefix: integrationRedisPrefix + ":outage:" + uniqueSuffix(), TTL: time.Minute}
	agent, err := New(cfg, WithLogger(logger))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = agent.Stop(context.Background()) })
	// Break the scan so the startup reload fails: the agent must start
	// memory-only and count the failure.
	agent.persist.client.AddHook(redisHook{onProcess: func(name string, next func() error) error {
		if name == "scan" {
			return errors.New("scan exploded")
		}
		return next()
	}})
	if err := agent.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !strings.Contains(buf.String(), "starting memory-only") {
		t.Fatalf("a failing reload must degrade to memory-only, got %q", buf.String())
	}
	if agent.Stats().RedisPersistFailures == 0 {
		t.Fatal("a failing reload must count a persistence failure")
	}
}

func TestAgentPersistEnqueueConfirmLifecycle(t *testing.T) {
	host := integrationRedisHost(t)
	prefix := integrationRedisPrefix + ":lifecycle:" + uniqueSuffix()
	client := redis.NewClient(&redis.Options{Addr: host + ":6379"})
	t.Cleanup(func() {
		keys := scanAll(context.Background(), client, prefix+":*")
		if len(keys) > 0 {
			_ = client.Del(context.Background(), keys...).Err()
		}
		_ = client.Close()
	})
	m := newMockIngest(t)
	agent := newTestAgent(t, m, func(c *Config) {
		c.Redis = &RedisConfig{URL: "redis://" + host + ":6379", Prefix: prefix, TTL: time.Minute}
	})
	ctx := context.Background()
	if err := agent.SendEvent(ctx, testEvent(1, "")); err != nil {
		t.Fatalf("SendEvent: %v", err)
	}
	if err := agent.SendMetric(ctx, testMetric(1)); err != nil {
		t.Fatalf("SendMetric: %v", err)
	}
	waitUntil(t, 5*time.Second, "enqueue must persist records", func() bool {
		return len(scanAll(ctx, client, prefix+":agent_*")) == 2
	})
	if err := agent.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	waitUntil(t, 5*time.Second, "confirmation must delete the records", func() bool {
		return len(scanAll(ctx, client, prefix+":agent_*")) == 0
	})
	_ = agent.Stop(ctx)
}

func TestConfirmKeysOverflowsToDirectDeleteAndSurvivesStop(t *testing.T) {
	host := integrationRedisHost(t)
	prefix := integrationRedisPrefix + ":confirm:" + uniqueSuffix()
	client := redis.NewClient(&redis.Options{Addr: host + ":6379"})
	t.Cleanup(func() {
		keys := scanAll(context.Background(), client, prefix+":*")
		if len(keys) > 0 {
			_ = client.Del(context.Background(), keys...).Err()
		}
		_ = client.Close()
	})
	agent := newTestAgent(t, nil, func(c *Config) {
		c.Redis = &RedisConfig{URL: "redis://" + host + ":6379", Prefix: prefix, TTL: time.Minute}
	})
	ctx := context.Background()
	// Saturate the confirm channel: the keys must fall through to a direct
	// delete instead of being lost.
	for i := 0; i < cap(agent.confirmCh); i++ {
		agent.confirmCh <- []string{fmt.Sprintf("%s:agent_events:filler_%d", prefix, i)}
	}
	agent.confirmKeys([]string{prefix + ":agent_events:spill"})
	waitUntil(t, 5*time.Second, "the spilled keys must delete directly", func() bool {
		return client.Exists(ctx, prefix+":agent_events:spill").Val() == 0
	})
	// Drain the channel so Stop's worker exits cleanly.
	for len(agent.confirmCh) > 0 {
		<-agent.confirmCh
	}
	_ = agent.Stop(ctx)
	// After Stop the confirm channel is closed: confirmKeys must recover
	// from the send panic and leave the records to TTL expiry.
	agent.confirmKeys([]string{prefix + ":agent_events:after-stop"})
}
