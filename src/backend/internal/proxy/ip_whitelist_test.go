package proxy

import (
	"net/http/httptest"
	"testing"
)

func TestIPAllowed(t *testing.T) {
	cases := []struct {
		name       string
		remoteAddr string
		realIP     string
		xff        string
		whitelist  string
		want       bool
	}{
		{"real IP in CIDR via nginx", "172.20.0.1:50802", "203.0.113.9", "203.0.113.9", "203.0.113.0/24", true},
		{"real IP exact match via nginx", "172.20.0.1:50802", "203.0.113.9", "203.0.113.9", "10.0.0.1, 203.0.113.9", true},
		{"forged X-Forwarded-For entry is ignored", "172.20.0.1:50802", "198.51.100.7", "203.0.113.9, 198.51.100.7", "203.0.113.9", false},
		{"real IP outside whitelist", "172.20.0.1:50802", "198.51.100.7", "198.51.100.7", "203.0.113.0/24", false},
		{"direct public peer cannot forge headers", "198.51.100.7:1234", "203.0.113.9", "203.0.113.9", "203.0.113.9", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/v1/messages", nil)
			r.RemoteAddr = c.remoteAddr
			r.Header.Set("X-Real-IP", c.realIP)
			r.Header.Set("X-Forwarded-For", c.xff)
			if got := ipAllowed(r, c.whitelist); got != c.want {
				t.Errorf("ipAllowed() = %v, want %v", got, c.want)
			}
		})
	}
}
