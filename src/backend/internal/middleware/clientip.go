package middleware

import (
	"net"
	"net/http"
	"strings"
)

// ClientIP returns the end user's IP address. Forwarding headers are only
// trusted when the direct peer is a loopback or private address (a local
// reverse proxy such as nginx reaching the Docker container); from any other
// peer they could be forged, so the peer address is used as is.
func ClientIP(r *http.Request) string {
	peer, trusted := peerAddr(r)
	if !trusted {
		return peer
	}

	if ip := net.ParseIP(strings.TrimSpace(r.Header.Get("X-Real-IP"))); ip != nil {
		return ip.String()
	}
	// The rightmost entry is the one our proxy appended; earlier ones are client-supplied.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if ip := net.ParseIP(strings.TrimSpace(parts[len(parts)-1])); ip != nil {
			return ip.String()
		}
	}
	return peer
}

// RequestIsHTTPS reports whether the client reached us over HTTPS, directly or
// through a trusted reverse proxy that terminated TLS (X-Forwarded-Proto).
func RequestIsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	_, trusted := peerAddr(r)
	return trusted && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// peerAddr returns the direct peer's IP and whether it may set forwarding headers.
func peerAddr(r *http.Request) (string, bool) {
	peer := r.RemoteAddr
	if host, _, err := net.SplitHostPort(peer); err == nil {
		peer = host
	}
	ip := net.ParseIP(peer)
	return peer, ip != nil && (ip.IsLoopback() || ip.IsPrivate())
}
