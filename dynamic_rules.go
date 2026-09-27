package guardagent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// rulesPath is the GET endpoint for SaaS dynamic rules.
const rulesPath = "/api/v1/rules"

// DynamicRules defaults, mirroring guard_agent.models.DynamicRules field
// defaults. They are applied by UnmarshalJSON before overlaying the wire
// payload so a sparse server response decodes exactly like the pydantic
// model would.
const (
	defaultRuleID         = "default-rule"
	defaultRuleVersion    = 1
	defaultRuleTTLSeconds = 300
	defaultIPBanDuration  = 3600
)

// DynamicRules is the full SaaS rule surface the engine consumes, mirroring
// guard_agent.models.DynamicRules field for field with snake_case wire
// names. Decoding applies the Python defaults for absent fields.
type DynamicRules struct {
	RuleID    string     `json:"rule_id"`
	Version   int        `json:"version"`
	Timestamp time.Time  `json:"timestamp"`
	ExpiresAt *time.Time `json:"expires_at"`
	TTL       int        `json:"ttl"`

	IPBlacklist   []string `json:"ip_blacklist"`
	IPWhitelist   []string `json:"ip_whitelist"`
	IPBanDuration int      `json:"ip_ban_duration"`

	BlockedCountries   []string `json:"blocked_countries"`
	WhitelistCountries []string `json:"whitelist_countries"`

	GlobalRateLimit    *int              `json:"global_rate_limit"`
	GlobalRateWindow   *int              `json:"global_rate_window"`
	EndpointRateLimits map[string][2]int `json:"endpoint_rate_limits"`

	BlockedCloudProviders []string `json:"blocked_cloud_providers"`

	BlockedUserAgents []string `json:"blocked_user_agents"`

	SuspiciousPatterns []string `json:"suspicious_patterns"`

	EnablePenetrationDetection *bool `json:"enable_penetration_detection"`
	EnableIPBanning            *bool `json:"enable_ip_banning"`
	EnableRateLimiting         *bool `json:"enable_rate_limiting"`
	AutoBanThreshold           *int  `json:"auto_ban_threshold"`
	AutoBanDuration            *int  `json:"auto_ban_duration"`
	EnableRateLimitAutoBan     *bool `json:"enable_rate_limit_auto_ban"`

	EmergencyMode          bool     `json:"emergency_mode"`
	EmergencyWhitelist     []string `json:"emergency_whitelist"`
	EmergencyWhitelistOnly bool     `json:"emergency_whitelist_only"`
	Message                *string  `json:"message"`
}

// DefaultDynamicRules returns the pydantic-default DynamicRules value.
func DefaultDynamicRules() DynamicRules {
	now := time.Now().UTC()
	return DynamicRules{
		RuleID:                defaultRuleID,
		Version:               defaultRuleVersion,
		Timestamp:             now,
		TTL:                   defaultRuleTTLSeconds,
		IPBanDuration:         defaultIPBanDuration,
		IPBlacklist:           []string{},
		IPWhitelist:           []string{},
		BlockedCountries:      []string{},
		WhitelistCountries:    []string{},
		EndpointRateLimits:    map[string][2]int{},
		BlockedCloudProviders: []string{},
		BlockedUserAgents:     []string{},
		SuspiciousPatterns:    []string{},
		EmergencyWhitelist:    []string{},
	}
}

// dynamicRulesWire shadows DynamicRules with pointers on the fields that
// carry Python-side defaults, so "absent in JSON" stays distinguishable
// from "zero value".
type dynamicRulesWire struct {
	RuleID    *string    `json:"rule_id"`
	Version   *int       `json:"version"`
	Timestamp *time.Time `json:"timestamp"`
	ExpiresAt *time.Time `json:"expires_at"`
	TTL       *int       `json:"ttl"`

	IPBlacklist   []string `json:"ip_blacklist"`
	IPWhitelist   []string `json:"ip_whitelist"`
	IPBanDuration *int     `json:"ip_ban_duration"`

	BlockedCountries   []string `json:"blocked_countries"`
	WhitelistCountries []string `json:"whitelist_countries"`

	GlobalRateLimit    *int              `json:"global_rate_limit"`
	GlobalRateWindow   *int              `json:"global_rate_window"`
	EndpointRateLimits map[string][2]int `json:"endpoint_rate_limits"`

	BlockedCloudProviders []string `json:"blocked_cloud_providers"`

	BlockedUserAgents []string `json:"blocked_user_agents"`

	SuspiciousPatterns []string `json:"suspicious_patterns"`

	EnablePenetrationDetection *bool `json:"enable_penetration_detection"`
	EnableIPBanning            *bool `json:"enable_ip_banning"`
	EnableRateLimiting         *bool `json:"enable_rate_limiting"`
	AutoBanThreshold           *int  `json:"auto_ban_threshold"`
	AutoBanDuration            *int  `json:"auto_ban_duration"`
	EnableRateLimitAutoBan     *bool `json:"enable_rate_limit_auto_ban"`

	EmergencyMode          bool     `json:"emergency_mode"`
	EmergencyWhitelist     []string `json:"emergency_whitelist"`
	EmergencyWhitelistOnly bool     `json:"emergency_whitelist_only"`
	Message                *string  `json:"message"`
}

// UnmarshalJSON applies the Python defaults first and overlays the wire
// payload, so a sparse response decodes exactly like
// DynamicRules(**response_data) does in the Python agent.
func (r *DynamicRules) UnmarshalJSON(data []byte) error {
	*r = DefaultDynamicRules()
	var wire dynamicRulesWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	if wire.RuleID != nil {
		r.RuleID = *wire.RuleID
	}
	if wire.Version != nil {
		r.Version = *wire.Version
	}
	if wire.Timestamp != nil {
		r.Timestamp = *wire.Timestamp
	}
	r.ExpiresAt = wire.ExpiresAt
	if wire.TTL != nil {
		r.TTL = *wire.TTL
	}
	r.IPBlacklist = replaceOrEmpty(wire.IPBlacklist, r.IPBlacklist)
	r.IPWhitelist = replaceOrEmpty(wire.IPWhitelist, r.IPWhitelist)
	if wire.IPBanDuration != nil {
		r.IPBanDuration = *wire.IPBanDuration
	}
	r.BlockedCountries = replaceOrEmpty(wire.BlockedCountries, r.BlockedCountries)
	r.WhitelistCountries = replaceOrEmpty(wire.WhitelistCountries, r.WhitelistCountries)
	r.GlobalRateLimit = wire.GlobalRateLimit
	r.GlobalRateWindow = wire.GlobalRateWindow
	if wire.EndpointRateLimits != nil {
		r.EndpointRateLimits = wire.EndpointRateLimits
	}
	r.BlockedCloudProviders = replaceOrEmpty(wire.BlockedCloudProviders, r.BlockedCloudProviders)
	r.BlockedUserAgents = replaceOrEmpty(wire.BlockedUserAgents, r.BlockedUserAgents)
	r.SuspiciousPatterns = replaceOrEmpty(wire.SuspiciousPatterns, r.SuspiciousPatterns)
	r.EnablePenetrationDetection = wire.EnablePenetrationDetection
	r.EnableIPBanning = wire.EnableIPBanning
	r.EnableRateLimiting = wire.EnableRateLimiting
	r.AutoBanThreshold = wire.AutoBanThreshold
	r.AutoBanDuration = wire.AutoBanDuration
	r.EnableRateLimitAutoBan = wire.EnableRateLimitAutoBan
	r.EmergencyMode = wire.EmergencyMode
	r.EmergencyWhitelist = replaceOrEmpty(wire.EmergencyWhitelist, r.EmergencyWhitelist)
	r.EmergencyWhitelistOnly = wire.EmergencyWhitelistOnly
	r.Message = wire.Message
	return nil
}

// replaceOrEmpty prefers the decoded slice; nil keeps the default empty
// slice so a re-serialization never emits null where Python emits [].
func replaceOrEmpty(decoded, fallback []string) []string {
	if decoded != nil {
		return decoded
	}
	return fallback
}

// fetchDynamicRules GETs the rules document with the same retry machinery
// as batch sends: local rate limiter admission, circuit breaker, capped
// Retry-After on 429, exponential backoff on every other failure. A nil
// result with a nil error never happens; on give-up the error is
// returned and the caller falls back to its cache.
func (t *transport) fetchDynamicRules(ctx context.Context) (*DynamicRules, error) {
	for attempt := 0; ; attempt++ {
		if allowed, gateErr := t.limiterGate(ctx, attempt, "dynamic rules fetch"); !allowed {
			if gateErr != nil {
				return nil, gateErr
			}
			continue
		}
		if err := t.breaker.Admit(); err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.cfg.Endpoint+rulesPath, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", userAgent())
		req.Header.Set("X-API-Key", t.cfg.APIKey)
		req.Header.Set("X-Agent-Install-Id", t.installID)
		if t.cfg.ProjectID != "" {
			req.Header.Set("X-Project-Id", t.cfg.ProjectID)
		}
		resp, err := t.client.Do(req)
		if err != nil {
			t.breaker.Failure()
			t.requestsFailed.Add(1)
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if attempt < t.cfg.RetryAttempts && sleepCtx(ctx, retryBackoff(attempt, t.cfg.BackoffFactor)) {
				continue
			}
			return nil, err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, httpReadLimit))
		resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusOK:
			t.breaker.Success()
			t.requestsSent.Add(1)
			var rules DynamicRules
			if err := json.Unmarshal(body, &rules); err != nil {
				t.requestsFailed.Add(1)
				return nil, fmt.Errorf("guardagent: malformed dynamic rules response: %w", err)
			}
			return &rules, nil
		case resp.StatusCode == http.StatusTooManyRequests:
			t.breaker.Failure()
			t.requestsFailed.Add(1)
			delay := parseRetryAfter(resp.Header.Get("Retry-After"))
			if attempt < t.cfg.RetryAttempts && sleepCtx(ctx, delay) {
				continue
			}
			return nil, &RateLimitedError{RetryAfter: delay}
		default:
			t.breaker.Failure()
			t.requestsFailed.Add(1)
			if attempt < t.cfg.RetryAttempts && sleepCtx(ctx, retryBackoff(attempt, t.cfg.BackoffFactor)) {
				continue
			}
			return nil, fmt.Errorf("guardagent: dynamic rules request failed with status %d: %s", resp.StatusCode, truncate(string(body), 200))
		}
	}
}

// GetDynamicRules returns the SaaS dynamic rules, serving them from the
// in-memory cache while the rules document TTL has not expired. On a fetch
// failure the cached rules (possibly nil) are returned with a nil error,
// mirroring the Python RulesMixin.get_dynamic_rules: the engine must never
// see a rules outage as a hard failure. Every successful refresh bumps
// Stats.RulesFetched.
func (a *Agent) GetDynamicRules(ctx context.Context) (rules *DynamicRules) {
	defer recoverPanic(a.logger, "GetDynamicRules", nil)
	a.mu.Lock()
	cached := a.cachedRules
	if cached != nil && time.Since(a.rulesLastUpdate) < time.Duration(cached.TTL)*time.Second {
		a.mu.Unlock()
		return cached
	}
	a.mu.Unlock()

	fetched, err := a.fetchRulesSafely(ctx)
	if err != nil {
		a.logger.Printf("guardagent: failed to fetch dynamic rules: %v", err)
		a.mu.Lock()
		defer a.mu.Unlock()
		return a.cachedRules
	}
	if fetched != nil {
		a.mu.Lock()
		a.cachedRules = fetched
		a.rulesLastUpdate = time.Now()
		a.rulesFetched++
		a.mu.Unlock()
	}
	return fetched
}

// fetchRulesSafely converts a transport panic into an error so the rules
// path keeps the agent-wide failure isolation guarantee.
func (a *Agent) fetchRulesSafely(ctx context.Context) (rules *DynamicRules, err error) {
	defer func() {
		if r := recover(); r != nil {
			a.logger.Printf("guardagent: recovered from panic during dynamic rules fetch: %v", r)
			rules = nil
			err = fmt.Errorf("%w during dynamic rules fetch: %v", ErrInternal, r)
		}
	}()
	return a.tr.fetchDynamicRules(ctx)
}

// rulesLoop polls the SaaS for dynamic rules on the DynamicRuleInterval
// cadence. Consecutive failures escalate from warning to error at the
// same threshold as the other loops.
func (a *Agent) rulesLoop() {
	defer a.wg.Done()
	ticker := time.NewTicker(a.cfg.DynamicRuleInterval)
	defer ticker.Stop()
	consecutive := 0
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			rules := a.GetDynamicRules(a.loopCtx())
			if rules != nil {
				consecutive = 0
				continue
			}
			consecutive++
			if consecutive < 3 {
				a.logger.Printf("guardagent: dynamic rules loop failed %d time(s); serving last known rules", consecutive)
			} else {
				a.logger.Printf("guardagent: dynamic rules loop failing repeatedly (%d in a row); serving last known rules", consecutive)
			}
		}
	}
}
