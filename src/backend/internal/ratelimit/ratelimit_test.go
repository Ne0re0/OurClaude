package ratelimit

import "testing"

func TestMemLimiterUsesLimitPassedPerCall(t *testing.T) {
	l := newMemLimiter()
	for i := 0; i < 5; i++ {
		if !l.Allow(1, 0) {
			t.Fatal("rpm 0 means unlimited")
		}
	}
	if !l.Allow(2, 2) || !l.Allow(2, 2) {
		t.Fatal("first two requests at rpm 2 should pass")
	}
	if l.Allow(2, 2) {
		t.Error("third request within the minute at rpm 2 should be limited")
	}
}
