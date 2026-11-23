package handlers

import (
	"sync"
	"time"
)

const (
	loginWindow             = 15 * time.Minute
	maxLoginAttemptsPerIP   = 10
	maxLoginAttemptsPerUser = 20
)

// loginLimiter caps admin login attempts per key (client IP or username) in a
// fixed window. Attempts are counted before the password is checked, so a burst
// of parallel requests cannot slip past the limit; a successful login resets them.
type loginLimiter struct {
	mu      sync.Mutex
	entries map[string]*loginAttempts
}

type loginAttempts struct {
	count int
	start time.Time
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{entries: make(map[string]*loginAttempts)}
}

// attempt records an attempt for key and returns how long to wait if key is over max, or 0.
func (l *loginLimiter) attempt(key string, max int, now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()

	if len(l.entries) > 10000 {
		for k, e := range l.entries {
			if now.Sub(e.start) >= loginWindow {
				delete(l.entries, k)
			}
		}
	}

	e, ok := l.entries[key]
	if !ok || now.Sub(e.start) >= loginWindow {
		e = &loginAttempts{start: now}
		l.entries[key] = e
	}
	if e.count >= max {
		return e.start.Add(loginWindow).Sub(now)
	}
	e.count++
	return 0
}

func (l *loginLimiter) reset(keys ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, k := range keys {
		delete(l.entries, k)
	}
}
