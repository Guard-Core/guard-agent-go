package guardagent

import (
	"context"
	"testing"
	"time"
)

// The reference get_stats dict view (guard_agent _client_status.py
// get_stats) the engine's middleware agent_stats merge consumes through
// guardcore's AgentStatsProvider seam.

func TestAgentStatsDictShape(t *testing.T) {
	agent := newTestAgent(t, nil, nil)
	stats := agent.AgentStats()

	// An unstarted agent: running=false, uptime=0, no cached rules, and
	// the zero rules_last_update renders as nil (the reference None).
	if stats["running"] != false || stats["uptime"] != 0.0 {
		t.Fatalf("an unstarted agent must report running=false uptime=0, got %v", stats)
	}
	if stats["cached_rules"] != false || stats["rules_last_update"] != nil {
		t.Fatalf("unstarted agent rule state must be empty, got %v", stats)
	}
	for _, key := range []string{"events_sent", "metrics_sent", "events_failed", "metrics_failed", "rules_fetched"} {
		if _, ok := stats[key]; !ok {
			t.Fatalf("the dict must carry %q", key)
		}
	}
	buffer := stats["buffer_stats"].(map[string]any)
	for _, key := range []string{
		"events_buffered", "metrics_buffered", "events_flushed", "metrics_flushed",
		"events_dropped", "metrics_dropped", "current_event_buffer_size",
		"current_metric_buffer_size", "redis_persist_failures", "durability_degraded",
	} {
		if _, ok := buffer[key]; !ok {
			t.Fatalf("buffer_stats must carry %q", key)
		}
	}
	transport := stats["transport_stats"].(map[string]any)
	for _, key := range []string{"requests_sent", "requests_failed", "circuit_breaker_state"} {
		if _, ok := transport[key]; !ok {
			t.Fatalf("transport_stats must carry %q", key)
		}
	}
}

func TestAgentStatsDictRunningArms(t *testing.T) {
	agent := newTestAgent(t, nil, nil)
	agent.mu.Lock()
	agent.started = true
	agent.startedAt = time.Now().Add(-2 * time.Second)
	agent.cachedRules = &DynamicRules{}
	agent.rulesLastUpdate = time.Now().UTC()
	agent.mu.Unlock()
	if err := agent.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	// After Stop the agent reports running=false again, but the uptime
	// and rule-state arms carried values while started: recompute against
	// a fresh started window to pin both arms of the uptime and
	// rules_last_update renders.
	agent.mu.Lock()
	agent.closed = false
	agent.started = true
	agent.mu.Unlock()
	stats := agent.AgentStats()
	if uptime := stats["uptime"].(float64); uptime < 2.0 {
		t.Fatalf("a started agent must report its uptime, got %v", uptime)
	}
	if stats["cached_rules"] != true {
		t.Fatal("a fetched rules snapshot must report cached_rules=true")
	}
	if last, ok := stats["rules_last_update"].(string); !ok || last == "" {
		t.Fatalf("a stamped rules update must render the timestamp, got %v", stats["rules_last_update"])
	}
}
