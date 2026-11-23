package middleware

import (
	"net/http/httptest"
	"testing"
)

func TestClientIP(t *testing.T) {
	cases := []struct {
		name       string
		remoteAddr string
		realIP     string
		xff        string
		want       string
	}{
		{"docker gateway with X-Real-IP", "172.20.0.1:50802", "203.0.113.9", "", "203.0.113.9"},
		{"loopback with X-Real-IP", "127.0.0.1:4000", "2001:db8::7", "", "2001:db8::7"},
		{"private peer falls back to rightmost XFF", "172.20.0.1:50802", "", "198.51.100.1, 203.0.113.9", "203.0.113.9"},
		{"public peer ignores forged headers", "198.51.100.7:1234", "203.0.113.9", "203.0.113.9", "198.51.100.7"},
		{"invalid X-Real-IP falls back to XFF", "10.0.0.2:80", "not-an-ip", "203.0.113.9", "203.0.113.9"},
		{"no headers returns peer without port", "172.20.0.1:50802", "", "", "172.20.0.1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = c.remoteAddr
			if c.realIP != "" {
				r.Header.Set("X-Real-IP", c.realIP)
			}
			if c.xff != "" {
				r.Header.Set("X-Forwarded-For", c.xff)
			}
			if got := ClientIP(r); got != c.want {
				t.Errorf("ClientIP() = %q, want %q", got, c.want)
			}
		})
	}
}
