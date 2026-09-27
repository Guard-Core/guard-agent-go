package guardagent

import (
	"sync"
	"time"
)

// Local client-side rate limiter defaults, mirroring the Python agent's
// RateLimiter(100, 60) built in _transport_lifecycle.
const (
	defaultLimiterMaxCalls = 100
	defaultLimiterWindow   = 60 * time.Second
)

// RateLimiter is a simple sliding-window rate limiter for the agent's
// outgoing requests, mirroring guard_agent.utils.RateLimiter: every request
// attempt must Acquire a slot first; when the window is saturated the
// caller waits RetryBefore the next slot frees up. It is safe for
// concurrent use.
type RateLimiter struct {
	mu       sync.Mutex
	maxCalls int
	window   time.Duration
	calls    []time.Time
}

func newRateLimiter(maxCalls int, window time.Duration) *RateLimiter {
	return &RateLimiter{maxCalls: maxCalls, window: window}
}

// Acquire records one call when the limiter is under its cap and reports
// whether the call is allowed.
func (l *RateLimiter) Acquire() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.pruneLocked(now)
	if len(l.calls) < l.maxCalls {
		l.calls = append(l.calls, now)
		return true
	}
	return false
}

// RetryAfter returns how long until the next slot frees up; zero when the
// limiter currently admits calls. It mirrors RateLimiter.get_retry_after.
func (l *RateLimiter) RetryAfter() time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.calls) == 0 {
		return 0
	}
	oldest := l.calls[0]
	wait := l.window - time.Since(oldest)
	if wait < 0 {
		return 0
	}
	return wait
}

// pruneLocked drops call timestamps that left the window. Calls are
// appended in order, so the oldest is always first.
func (l *RateLimiter) pruneLocked(now time.Time) {
	keep := l.calls[:0]
	for _, ts := range l.calls {
		if now.Sub(ts) < l.window {
			keep = append(keep, ts)
		}
	}
	l.calls = keep
}
