package middleware

import (
	"net/http/httptest"
	"testing"
)

func TestViewerMayAccess(t *testing.T) {
	cases := []struct {
		method, path string
		want         bool
	}{
		{"GET", "/api/admin/users", true},
		{"GET", "/api/admin/conversations", true},
		{"GET", "/api/admin/accounts/3/credentials", false},
		{"GET", "/api/admin/invites", false},
		{"GET", "/api/admin/download-links", false},
		{"POST", "/api/admin/users", false},
		{"PUT", "/api/admin/settings", false},
		{"DELETE", "/api/admin/sessions/4", false},
		{"POST", "/api/oauth/token", false},
		{"PUT", "/api/auth/password", true},
		{"POST", "/api/auth/totp/setup", true},
	}
	for _, c := range cases {
		if got := viewerMayAccess(c.method, c.path); got != c.want {
			t.Errorf("viewerMayAccess(%s %s) = %v, want %v", c.method, c.path, got, c.want)
		}
	}
}

func TestRequestIsHTTPS(t *testing.T) {
	cases := []struct {
		name, remoteAddr, proto string
		want                    bool
	}{
		{"nginx on the docker network says https", "172.20.0.1:50802", "https", true},
		{"no forwarded proto", "172.20.0.1:50802", "", false},
		{"public client cannot claim https", "198.51.100.7:1234", "https", false},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.remoteAddr
		if c.proto != "" {
			r.Header.Set("X-Forwarded-Proto", c.proto)
		}
		if got := RequestIsHTTPS(r); got != c.want {
			t.Errorf("%s: RequestIsHTTPS = %v, want %v", c.name, got, c.want)
		}
	}
}
