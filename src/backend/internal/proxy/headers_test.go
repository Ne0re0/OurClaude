package proxy

import "testing"

func TestStripRequestHeader(t *testing.T) {
	stripped := []string{"Authorization", "X-Api-Key", "Anthropic-Auth-Token", "Cookie", "Host",
		"X-Forwarded-For", "X-Forwarded-Proto", "X-Real-Ip", "Cf-Connecting-Ip", "Forwarded"}
	kept := []string{"Anthropic-Version", "Anthropic-Beta", "Content-Type", "User-Agent", "X-App"}
	for _, h := range stripped {
		if !stripRequestHeader(h) {
			t.Errorf("%s should not reach Anthropic", h)
		}
	}
	for _, h := range kept {
		if stripRequestHeader(h) {
			t.Errorf("%s should be forwarded", h)
		}
	}
}

func TestForwardResponseHeader(t *testing.T) {
	hidden := []string{"Set-Cookie", "Anthropic-Organization-Id", "Cf-Ray", "Server", "Via"}
	shown := []string{"Content-Type", "Content-Encoding", "Request-Id", "Retry-After",
		"Anthropic-Ratelimit-Unified-Status", "Anthropic-Ratelimit-Requests-Remaining"}
	for _, h := range hidden {
		if forwardResponseHeader(h) {
			t.Errorf("%s would identify the pooled account", h)
		}
	}
	for _, h := range shown {
		if !forwardResponseHeader(h) {
			t.Errorf("%s should reach the client", h)
		}
	}
}
