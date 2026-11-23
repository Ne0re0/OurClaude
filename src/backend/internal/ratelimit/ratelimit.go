package ratelimit

import (
	"sync"
	"time"
)

// Limiter is the interface for per-user rate limiting.
// The limit is passed on every call so changes to the runtime setting apply immediately; rpm <= 0 means unlimited.
type Limiter interface {
	Allow(userID uint, rpm int) bool
}

// New returns an in-memory limiter or a Redis-backed one if redisURL is provided.
func New(redisURL string) Limiter {
	if redisURL != "" {
		return newRedisLimiter(redisURL)
	}
	return newMemLimiter()
}

// --- in-memory token bucket ---

type bucket struct {
	tokens    float64
	lastRefil time.Time
}

type memLimiter struct {
	mu      sync.Mutex
	buckets map[uint]*bucket
}

func newMemLimiter() *memLimiter {
	return &memLimiter{buckets: make(map[uint]*bucket)}
}

func (l *memLimiter) Allow(userID uint, rpm int) bool {
	if rpm <= 0 {
		return true
	}
	limit := float64(rpm)

	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	b, ok := l.buckets[userID]
	if !ok {
		b = &bucket{tokens: limit, lastRefil: now}
		l.buckets[userID] = b
	}

	elapsed := now.Sub(b.lastRefil).Minutes()
	b.tokens += elapsed * limit
	if b.tokens > limit {
		b.tokens = limit
	}
	b.lastRefil = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
