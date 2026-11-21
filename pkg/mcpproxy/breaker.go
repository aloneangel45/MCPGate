package mcpproxy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// BreakerRuleID is the canonical security rule ID emitted when the circuit breaker trips.
const BreakerRuleID = "MCP08-RATE-BREAKER"

// BreakerConfig configures rate-limit, consecutive-error, and identical-loop circuit breaking.
type BreakerConfig struct {
	MaxCallsPerMinute    int
	MaxConsecutiveErrors int
	MaxIdenticalCalls    int
}

// BreakerTrip captures the state and reason when the circuit breaker trips.
type BreakerTrip struct {
	Tripped bool   `json:"tripped"`
	Reason  string `json:"reason,omitempty"`
	RuleID  string `json:"rule_id,omitempty"`
	Kind    string `json:"kind,omitempty"` // rate_limit | error_streak | identical_loop
}

// CircuitBreaker tracks tool-call velocity, repeated identical invocations, and consecutive
// server errors to halt runaway agent loops or DoS behavior.
type CircuitBreaker struct {
	mu                sync.Mutex
	cfg               BreakerConfig
	nowFn             func() time.Time
	callTimestamps    []time.Time
	consecutiveErrors int
	lastCallHash      string
	identicalCount    int
	tripped           bool
	tripReason        string
	tripKind          string
	tripCount         int64
}

// NewCircuitBreaker constructs a thread-safe CircuitBreaker from BreakerConfig.
func NewCircuitBreaker(cfg BreakerConfig) *CircuitBreaker {
	return &CircuitBreaker{
		cfg:   cfg,
		nowFn: time.Now,
	}
}

// SetClock overrides the time source (intended for deterministic unit testing).
func (cb *CircuitBreaker) SetClock(fn func() time.Time) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if fn == nil {
		cb.nowFn = time.Now
	} else {
		cb.nowFn = fn
	}
}

// AllowCall records an incoming tools/call request and checks whether the breaker is tripped.
func (cb *CircuitBreaker) AllowCall(tool string, args map[string]any) BreakerTrip {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.tripped {
		return BreakerTrip{
			Tripped: true,
			Reason:  cb.tripReason,
			RuleID:  BreakerRuleID,
			Kind:    cb.tripKind,
		}
	}

	now := cb.nowFn()

	// 1. Sliding 1-minute rate window check.
	if cb.cfg.MaxCallsPerMinute > 0 {
		cutoff := now.Add(-1 * time.Minute)
		keepIdx := 0
		for keepIdx < len(cb.callTimestamps) && !cb.callTimestamps[keepIdx].After(cutoff) {
			keepIdx++
		}
		if keepIdx > 0 {
			cb.callTimestamps = append([]time.Time(nil), cb.callTimestamps[keepIdx:]...)
		}
		cb.callTimestamps = append(cb.callTimestamps, now)
		if len(cb.callTimestamps) > cb.cfg.MaxCallsPerMinute {
			return cb.tripLocked("rate_limit", fmt.Sprintf("rate limit exceeded: %d tool calls in 1m (limit %d)", len(cb.callTimestamps), cb.cfg.MaxCallsPerMinute))
		}
	}

	// 2. Identical (tool + canonical args) loop detection.
	if cb.cfg.MaxIdenticalCalls > 0 {
		callHash := hashToolCall(tool, args)
		if callHash == cb.lastCallHash {
			cb.identicalCount++
		} else {
			cb.lastCallHash = callHash
			cb.identicalCount = 1
		}
		if cb.identicalCount > cb.cfg.MaxIdenticalCalls {
			return cb.tripLocked("identical_loop", fmt.Sprintf("identical tool call loop detected: %q repeated %d consecutive times (limit %d)", tool, cb.identicalCount, cb.cfg.MaxIdenticalCalls))
		}
	}

	return BreakerTrip{}
}

// RecordResult records whether a tools/call response resulted in an error.
func (cb *CircuitBreaker) RecordResult(isError bool) BreakerTrip {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if !isError {
		cb.consecutiveErrors = 0
		return BreakerTrip{}
	}

	cb.consecutiveErrors++
	if cb.cfg.MaxConsecutiveErrors > 0 && cb.consecutiveErrors >= cb.cfg.MaxConsecutiveErrors && !cb.tripped {
		return cb.tripLocked("error_streak", fmt.Sprintf("consecutive error threshold reached: %d consecutive failures (limit %d)", cb.consecutiveErrors, cb.cfg.MaxConsecutiveErrors))
	}
	return BreakerTrip{}
}

// IsTripped returns true if the circuit breaker is currently open (tripped).
func (cb *CircuitBreaker) IsTripped() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.tripped
}

// TripCount returns the total number of times this breaker has tripped.
func (cb *CircuitBreaker) TripCount() int64 {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.tripCount
}

// Reset clears the tripped state and resets sliding counters.
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.tripped = false
	cb.tripReason = ""
	cb.tripKind = ""
	cb.callTimestamps = nil
	cb.consecutiveErrors = 0
	cb.lastCallHash = ""
	cb.identicalCount = 0
}

func (cb *CircuitBreaker) tripLocked(kind, reason string) BreakerTrip {
	cb.tripped = true
	cb.tripKind = kind
	cb.tripReason = reason
	cb.tripCount++
	return BreakerTrip{
		Tripped: true,
		Reason:  reason,
		RuleID:  BreakerRuleID,
		Kind:    kind,
	}
}

func hashToolCall(tool string, args map[string]any) string {
	type callKey struct {
		Tool string         `json:"tool"`
		Args map[string]any `json:"args"`
	}
	b, _ := json.Marshal(callKey{Tool: tool, Args: args})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
